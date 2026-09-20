// ===========================================================================
//  Tests of the error vocabulary.
//
//  The interesting test here is the exhaustive one. An error enumeration is a
//  closed set by construction, and the three things that must agree about it
//  -- the enumerator, its numeric code and its name -- are maintained by hand
//  in error.hpp. Hand-maintained agreement is exactly the kind of claim that
//  silently stops being true, so reflection enumerates the enumerators and
//  checks the whole set instead of sampling it:
//
//    * every enumerator is known to `is_known`;
//    * every enumerator has a distinct, non-placeholder name;
//    * no two enumerators share a numeric code;
//    * `domain_of` agrees with the code ranges the enumeration declares.
//
//  Adding an enumerator without extending `to_string` therefore fails here,
//  not in production.
// ===========================================================================
#include "meta_auth/core/error.hpp"
#include "test_framework.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#if META_AUTH_HAS_REFLECTION
#include <meta>
#endif

// ---------------------------------------------------------------------------
// Compile-time facts about the vocabulary
// ---------------------------------------------------------------------------
static_assert(meta_auth::to_string(meta_auth::auth_error::policy_denied) == "policy_denied");
static_assert(meta_auth::domain_of(meta_auth::auth_error::mac_invalid)
              == meta_auth::error_domain::crypto);
static_assert(meta_auth::domain_of(meta_auth::auth_error::capability_revoked)
              == meta_auth::error_domain::capability);
static_assert(meta_auth::domain_of(meta_auth::auth_error::attestation_failed)
              == meta_auth::error_domain::identity);
static_assert(meta_auth::domain_of(meta_auth::auth_error::access_denied)
              == meta_auth::error_domain::sandbox);

// A forged capability is evidence of an attack; retrying it is wrong. A
// rejected credential is an ordinary user mistake. The classification is
// part of the API contract, not an implementation detail.
static_assert(!meta_auth::is_recoverable(meta_auth::auth_error::capability_forged));
static_assert(!meta_auth::is_recoverable(meta_auth::auth_error::attestation_failed));
static_assert(meta_auth::is_recoverable(meta_auth::auth_error::credential_rejected));
static_assert(meta_auth::is_recoverable(meta_auth::auth_error::unauthenticated));

static_assert(std::is_same_v<meta_auth::result<int>, std::expected<int, meta_auth::auth_error>>);
static_assert(std::is_same_v<meta_auth::status, std::expected<void, meta_auth::auth_error>>);

namespace {

#if META_AUTH_HAS_REFLECTION

inline constexpr auto error_count = std::meta::enumerators_of(^^meta_auth::auth_error).size();

/// Every enumerator of `auth_error`, in declaration order.
///
/// The count comes from reflection rather than from a literal. It used to be a
/// literal -- `std::array<auth_error, 28>` -- and adding an enumerator to the
/// library then made this function index past the end of the array: the
/// reflective walk was bounded by a number that no longer described the
/// enumeration, so the test that exists to catch an unhandled enumerator
/// failed for a different reason and said nothing about the actual defect.
consteval auto all_errors() -> std::array<meta_auth::auth_error, error_count> {
    auto enumerators = std::meta::enumerators_of(^^meta_auth::auth_error);
    std::array<meta_auth::auth_error, error_count> errors{};
    for (std::size_t index = 0; index < enumerators.size(); ++index) {
        errors[index] = std::meta::extract<meta_auth::auth_error>(enumerators[index]);
    }
    return errors;
}

#endif // META_AUTH_HAS_REFLECTION

/// Helper: a function that fails on odd input, and chains of it, so the
/// propagation macros can be exercised on both paths.
[[nodiscard]] auto halve(int value) -> meta_auth::result<int> {
    if (value % 2 != 0) {
        return meta_auth::failure(meta_auth::auth_error::value_out_of_range);
    }
    return value / 2;
}

[[nodiscard]] auto require_even(int value) -> meta_auth::status {
    META_AUTH_TRY_VOID(halve(value));
    return meta_auth::success();
}

/// Halves twice. The second call is what makes the failure originate inside
/// the chain rather than at its first step, which is the case the propagation
/// macro has to get right.
[[nodiscard]] auto quarter(int value) -> meta_auth::result<int> {
    META_AUTH_TRY_BIND(half, halve(value));
    META_AUTH_TRY_BIND(quarter_of_half, halve(half));
    return quarter_of_half;
}

} // namespace

// ---------------------------------------------------------------------------
// Exhaustive properties of the enumeration
// ---------------------------------------------------------------------------
META_AUTH_TEST("auth_error", "every_enumerator_is_known_and_named") {
#if META_AUTH_HAS_REFLECTION
    constexpr auto errors = all_errors();
    META_AUTH_CHECK_EQ(errors.size(), error_count);

    for (const auto error : errors) {
        META_AUTH_CHECK(meta_auth::is_known(error));
        const auto name = meta_auth::to_string(error);
        META_AUTH_CHECK(!name.empty());
        // The placeholder is only reachable if a new enumerator was added
        // without extending the switch.
        META_AUTH_CHECK_NE(name, std::string_view{"unknown"});
    }
#else
    META_AUTH_SKIP("reflection is disabled in this build");
#endif
}

META_AUTH_TEST("auth_error", "codes_and_names_are_unique") {
#if META_AUTH_HAS_REFLECTION
    constexpr auto errors = all_errors();
    for (std::size_t lhs = 0; lhs < errors.size(); ++lhs) {
        for (std::size_t rhs = lhs + 1; rhs < errors.size(); ++rhs) {
            // A duplicated code makes the audit trail ambiguous; a duplicated
            // name makes a log line ambiguous. Both are defects that only
            // appear months later, so both are checked here.
            META_AUTH_CHECK_NE(static_cast<std::uint16_t>(errors[lhs]),
                               static_cast<std::uint16_t>(errors[rhs]));
            META_AUTH_CHECK_NE(meta_auth::to_string(errors[lhs]),
                               meta_auth::to_string(errors[rhs]));
        }
    }
#else
    META_AUTH_SKIP("reflection is disabled in this build");
#endif
}

META_AUTH_TEST("auth_error", "codes_fall_inside_their_domain_range") {
#if META_AUTH_HAS_REFLECTION
    using meta_auth::error_domain;
    constexpr auto errors = all_errors();

    for (const auto error : errors) {
        const auto code = static_cast<std::uint16_t>(error);
        const auto domain = meta_auth::domain_of(error);

        // domain_of is defined by ranges, so this asserts the ranges are the
        // documented ones and that no code was placed in the wrong block.
        META_AUTH_CHECK(code >= 100 && code < 700);
        switch (domain) {
        case error_domain::core:
            META_AUTH_CHECK(code < 200);
            break;
        case error_domain::crypto:
            META_AUTH_CHECK(code >= 200 && code < 300);
            break;
        case error_domain::capability:
            META_AUTH_CHECK(code >= 300 && code < 400);
            break;
        case error_domain::identity:
            META_AUTH_CHECK(code >= 400 && code < 500);
            break;
        case error_domain::auth:
            META_AUTH_CHECK(code >= 500 && code < 600);
            break;
        case error_domain::sandbox:
            META_AUTH_CHECK(code >= 600 && code < 700);
            break;
        }
    }
#else
    META_AUTH_SKIP("reflection is disabled in this build");
#endif
}

// ---------------------------------------------------------------------------
// Result plumbing
// ---------------------------------------------------------------------------
META_AUTH_TEST("result", "failure_carries_the_error") {
    const auto outcome = halve(3);
    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::value_out_of_range);
}

META_AUTH_TEST("result", "success_carries_the_value") {
    const auto outcome = halve(8);
    META_AUTH_REQUIRE(outcome.has_value());
    META_AUTH_CHECK_EQ(*outcome, 4);
}

META_AUTH_TEST("result", "try_void_propagates_a_failure") {
    const auto outcome = require_even(5);
    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::value_out_of_range);
}

META_AUTH_TEST("result", "try_void_passes_a_success_through") {
    META_AUTH_CHECK(require_even(6).has_value());
}

META_AUTH_TEST("result", "try_bind_propagates_the_original_error") {
    // The propagation must preserve the *original* error: rewriting it to a
    // generic failure would hide which layer refused. 6 halves to 3, which is
    // odd, so the failure comes from the second step of the chain.
    const auto outcome = quarter(6);
    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::value_out_of_range);
}

META_AUTH_TEST("result", "try_bind_chains_values") {
    const auto outcome = quarter(8);
    META_AUTH_REQUIRE(outcome.has_value());
    META_AUTH_CHECK_EQ(*outcome, 2);
}

META_AUTH_TEST("result", "status_is_default_constructible_as_success") {
    const meta_auth::status outcome{};
    META_AUTH_CHECK(outcome.has_value());
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
META_AUTH_TEST("auth_error", "formatter_renders_name_and_code") {
    META_AUTH_CHECK_EQ(std::format("{}", meta_auth::auth_error::policy_denied),
                       std::string{"policy_denied(500)"});
    META_AUTH_CHECK_EQ(std::format("{}", meta_auth::error_domain::capability),
                       std::string{"capability"});
}

META_AUTH_TEST("auth_error", "a_result_renders_through_the_harness") {
    // The harness falls back to std::format for std::expected, which is what
    // makes an unexpected value in a failure report legible.
    const auto outcome = halve(3);
    const std::string rendered = meta_auth::test::stringify(outcome);
    META_AUTH_CHECK(rendered.find("error(") != std::string::npos);
    META_AUTH_CHECK(rendered.find("value_out_of_range") != std::string::npos);
}
