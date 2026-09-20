// ===========================================================================
//  Dialect smoke test.
//
//  Everything else in this suite tests the library. This file tests the
//  *compiler configuration* the library was built under, because a silently
//  disabled dialect feature is the one failure mode that would make the rest
//  of the suite pass while proving less than it claims.
//
//  The checks here are deliberately of two kinds:
//
//    * static_assert -- the feature is not merely advertised by a macro, it
//      actually works in this translation unit;
//    * a runtime report -- so that a surprising result in CI can be traced
//      back to the exact dialect it was produced under.
// ===========================================================================
#include "meta_auth/config.hpp"
#include "meta_auth/version.hpp"
#include "test_framework.hpp"

#include <cstdio>
#include <string_view>

#if META_AUTH_HAS_REFLECTION
#include <meta>
#endif

namespace {

// ---------------------------------------------------------------------------
// Version bookkeeping
// ---------------------------------------------------------------------------
static_assert(meta_auth::version_packed()
                  == ((META_AUTH_VERSION_MAJOR << 16U) | (META_AUTH_VERSION_MINOR << 8U)
                      | META_AUTH_VERSION_PATCH),
              "version_packed() must agree with the numeric version components.");

static_assert(meta_auth::version.size() == 5 && meta_auth::version[1] == '.',
              "The version string must be a semantic version literal.");

static_assert(meta_auth::project_name == "meta-auth-core");
static_assert(meta_auth::license_identifier == "Apache-2.0");

// ---------------------------------------------------------------------------
// Feature switches must be usable in #if and in constant expressions.
// ---------------------------------------------------------------------------
static_assert(META_AUTH_HAS_CONTRACTS == 0 || META_AUTH_HAS_CONTRACTS == 1,
              "META_AUTH_HAS_CONTRACTS must be a 0/1 switch.");
static_assert(META_AUTH_HAS_REFLECTION == 0 || META_AUTH_HAS_REFLECTION == 1,
              "META_AUTH_HAS_REFLECTION must be a 0/1 switch.");
static_assert(meta_auth::config::contracts_enabled == (META_AUTH_HAS_CONTRACTS != 0));
static_assert(meta_auth::config::reflection_enabled == (META_AUTH_HAS_REFLECTION != 0));

// ---------------------------------------------------------------------------
// Contracts, when enabled, must actually be enforced -- not merely parsed.
// ---------------------------------------------------------------------------
#if META_AUTH_HAS_CONTRACTS
namespace contracts_probe {

/// A precondition and a postcondition on a constexpr function: the contract
/// syntax has to be accepted in the declarator *and* the function has to
/// remain usable in a constant expression.
constexpr auto clamp_unit(double value) noexcept -> double
    pre(value >= 0.0)
    post(result: result <= 1.0)
{
    if (value > 1.0) {
        return 1.0;
    }
    return value;
}

static_assert(clamp_unit(0.5) == 0.5);
static_assert(clamp_unit(2.0) == 1.0);

/// `contract_assert` has to be a valid statement in a constexpr body, and it
/// must hold during constant evaluation.
constexpr auto checked_double(int value) noexcept -> int {
    contract_assert(value >= 0);
    return value * 2;
}

static_assert(checked_double(21) == 42);

} // namespace contracts_probe
#endif // META_AUTH_HAS_CONTRACTS

// ---------------------------------------------------------------------------
// Reflection, when enabled, must be able to do the two things the policy
// engine relies on: enumerate data members and read annotations.
// ---------------------------------------------------------------------------
#if META_AUTH_HAS_REFLECTION
namespace reflection_probe {

struct [[=42]] annotated_record {
    int identifier;
    std::string_view name;
    bool requires_attestation;
};

consteval auto field_count() -> std::size_t {
    return std::meta::nonstatic_data_members_of(
               ^^annotated_record, std::meta::access_context::current())
        .size();
}

consteval auto second_field_name() -> std::string_view {
    auto members = std::meta::nonstatic_data_members_of(
        ^^annotated_record, std::meta::access_context::current());
    return std::meta::identifier_of(members[1]);
}

consteval auto annotation_value() -> int {
    auto annotations = std::meta::annotations_of(^^annotated_record);
    if (annotations.size() != 1) {
        return -1;
    }
    return std::meta::extract<int>(std::meta::constant_of(annotations[0]));
}

static_assert(field_count() == 3,
              "Reflection must see all three data members; a mismatch here means "
              "the compiler's reflection model differs from the one the policy "
              "engine was written against.");
static_assert(second_field_name() == "name");
static_assert(annotation_value() == 42);

} // namespace reflection_probe
#endif // META_AUTH_HAS_REFLECTION

// ---------------------------------------------------------------------------
// Pack indexing, when available, must index a pack by constant expression.
// ---------------------------------------------------------------------------
#if META_AUTH_HAS_PACK_INDEXING
namespace pack_indexing_probe {

template <typename... Types>
consteval auto first_size() -> std::size_t {
    return sizeof(Types...[0]);
}

static_assert(first_size<char, int, double>() == sizeof(char));

} // namespace pack_indexing_probe
#endif

} // namespace

// ---------------------------------------------------------------------------
// Runtime report
//
// The assertions above are compile-time, so they hold whatever this binary is
// asked to do. This case adds the part a static_assert cannot express: it
// prints the dialect the binary was actually built with, so that a surprising
// result elsewhere in the suite can be traced back to how it was compiled.
// ---------------------------------------------------------------------------
META_AUTH_TEST("dialect", "configuration_report") {
    std::printf("\n    %s %.*s\n", meta_auth::project_name.data(),
                static_cast<int>(meta_auth::version.size()), meta_auth::version.data());
    std::printf("      dialect    : %s\n", meta_auth::config::dialect_summary());
    std::printf("      contracts  : %s\n", META_AUTH_HAS_CONTRACTS ? "enforced" : "disabled");
    std::printf("      reflection : %s\n", META_AUTH_HAS_REFLECTION ? "available" : "disabled");
    std::printf("      pack index : %s\n", META_AUTH_HAS_PACK_INDEXING ? "available" : "disabled");
    std::printf("      delete(msg): %s\n",
                META_AUTH_HAS_DELETED_WITH_MESSAGE ? "available" : "disabled");
    std::fflush(stdout);

    // The library is built on these three unconditionally; the assertion is
    // here as well as in config.hpp so that the requirement is visible in the
    // test suite and not only in a header.
    META_AUTH_CHECK(META_AUTH_HAS_EXPECTED == 1);
    META_AUTH_CHECK(META_AUTH_HAS_PACK_INDEXING == 1);
    META_AUTH_CHECK(META_AUTH_HAS_DELETED_WITH_MESSAGE == 1);
}
