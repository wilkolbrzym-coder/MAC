// ===========================================================================
//  meta-auth-core -- error vocabulary and result plumbing.
//
//  Two kinds of failure exist in this library and they are kept strictly
//  apart (see docs/DESIGN-PRINCIPLES.md, P7):
//
//    * a *domain error* is something the caller must handle: a wrong
//      credential, a device that failed attestation, a capability that was
//      revoked. It is a value, returned through `result<T>`, and it is part
//      of the function's type.
//    * a *broken invariant* is not the caller's business at all: an impossible
//      state, a span whose size contradicts its data. It is a contract
//      assertion (`core/contract.hpp`) and it terminates the process.
//
//  Mixing the two is how security code ends up swallowing a failure it cannot
//  handle. The vocabulary below is therefore closed: every domain error the
//  library can produce is an enumerator here, with a stable numeric code and a
//  name, and the test suite proves by reflection that the three are in
//  bijection (tests/core/test_error.cpp).
// ===========================================================================
#ifndef META_AUTH_CORE_ERROR_HPP
#define META_AUTH_CORE_ERROR_HPP

#include "meta_auth/config.hpp"

#include <cstdint>
#include <expected>
#include <format>
#include <string_view>
#include <utility>

namespace meta_auth {

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

/// Which layer produced a domain error.
///
/// The classification exists for the audit trail and for triage: a
/// `capability` failure and an `identity` failure with the same code mean
/// different things to whoever reads the log at three in the morning.
enum class error_domain : std::uint8_t {
    core = 0,       ///< plumbing: encoding, bounds, internal limits
    crypto = 1,     ///< digests, MACs, constant-time comparison
    capability = 2, ///< rights, delegation, revocation epochs
    identity = 3,   ///< principals, devices, attestation
    auth = 4,       ///< sessions, policy evaluation
    sandbox = 5,    ///< mediation gate, protected objects, audit trail
};

/// Every domain error the library can return.
///
/// The numeric values are stable and are what the audit trail records; names
/// are for humans and may be improved. Renumbering is a breaking change.
enum class auth_error : std::uint16_t {
    // -- core -------------------------------------------------------------
    value_out_of_range = 100, ///< an argument was outside its documented range
    buffer_too_small = 101,   ///< a fixed-capacity container had no room left
    encoding_invalid = 102,   ///< input was not a well-formed encoding
    capacity_exhausted = 103, ///< a bounded pool (capabilities, sessions) is full
    not_found = 104,          ///< the named entry does not exist

    // -- crypto -----------------------------------------------------------
    digest_mismatch = 200,     ///< a digest did not match the expected value
    mac_invalid = 201,         ///< a MAC did not verify
    key_material_invalid = 202,///< a key was the wrong length or all zeroes
    randomness_unavailable = 203, ///< the platform entropy source failed

    // -- capability -------------------------------------------------------
    insufficient_rights = 300,  ///< the capability lacks a right the call needs
    delegation_denied = 301,    ///< no `grant` right, so it cannot be handed on
    capability_revoked = 302,   ///< the capability's epoch is stale
    capability_forged = 303,    ///< the capability did not originate from an authority
    resource_unavailable = 304, ///< the mediated resource is not currently present
    capability_neutralised = 305,///< the capability was consumed and holds nothing

    // -- identity ---------------------------------------------------------
    unauthenticated = 400,       ///< no authenticated session
    credential_rejected = 401,   ///< the credential did not verify
    attestation_failed = 402,    ///< the device did not prove what it claims
    attestation_expired = 403,   ///< attestation was valid but is too old
    trust_anchor_unknown = 404,  ///< the device chains to no known anchor
    identity_revoked = 405,      ///< the principal is permanently revoked
    principal_unknown = 406,     ///< the principal was never enrolled

    // -- auth -------------------------------------------------------------
    policy_denied = 500,        ///< no rule grants the request (deny by default)
    session_state_invalid = 501,///< the transition is not legal from this state
    elevation_required = 502,   ///< the operation needs a second factor
    policy_incomplete = 503,    ///< a resource has no rule (a build-time defect)

    // -- sandbox ----------------------------------------------------------
    access_denied = 600,   ///< the gate refused: rights, epoch or policy
    audit_unavailable = 601,///< the audit trail could not record the decision
    object_sealed = 602,   ///< the object was sealed against further use
};

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/// Human-readable name. Exhaustive by construction: the test suite reflects
/// over the enumerators and fails if any of them reaches the default branch.
[[nodiscard]] constexpr auto to_string(auth_error error) noexcept -> std::string_view {
    switch (error) {
    case auth_error::value_out_of_range:
        return "value_out_of_range";
    case auth_error::buffer_too_small:
        return "buffer_too_small";
    case auth_error::encoding_invalid:
        return "encoding_invalid";
    case auth_error::capacity_exhausted:
        return "capacity_exhausted";
    case auth_error::not_found:
        return "not_found";

    case auth_error::digest_mismatch:
        return "digest_mismatch";
    case auth_error::mac_invalid:
        return "mac_invalid";
    case auth_error::key_material_invalid:
        return "key_material_invalid";
    case auth_error::randomness_unavailable:
        return "randomness_unavailable";

    case auth_error::insufficient_rights:
        return "insufficient_rights";
    case auth_error::delegation_denied:
        return "delegation_denied";
    case auth_error::capability_revoked:
        return "capability_revoked";
    case auth_error::capability_forged:
        return "capability_forged";
    case auth_error::resource_unavailable:
        return "resource_unavailable";
    case auth_error::capability_neutralised:
        return "capability_neutralised";

    case auth_error::unauthenticated:
        return "unauthenticated";
    case auth_error::credential_rejected:
        return "credential_rejected";
    case auth_error::attestation_failed:
        return "attestation_failed";
    case auth_error::attestation_expired:
        return "attestation_expired";
    case auth_error::trust_anchor_unknown:
        return "trust_anchor_unknown";
    case auth_error::identity_revoked:
        return "identity_revoked";
    case auth_error::principal_unknown:
        return "principal_unknown";

    case auth_error::policy_denied:
        return "policy_denied";
    case auth_error::session_state_invalid:
        return "session_state_invalid";
    case auth_error::elevation_required:
        return "elevation_required";
    case auth_error::policy_incomplete:
        return "policy_incomplete";

    case auth_error::access_denied:
        return "access_denied";
    case auth_error::audit_unavailable:
        return "audit_unavailable";
    case auth_error::object_sealed:
        return "object_sealed";
    }
    return "unknown";
}

/// The layer that produced the error. Derived from the numeric code rather
/// than from a second table, so the two cannot disagree.
[[nodiscard]] constexpr auto domain_of(auth_error error) noexcept -> error_domain {
    const auto code = static_cast<std::uint16_t>(error);
    if (code < 200) {
        return error_domain::core;
    }
    if (code < 300) {
        return error_domain::crypto;
    }
    if (code < 400) {
        return error_domain::capability;
    }
    if (code < 500) {
        return error_domain::identity;
    }
    if (code < 600) {
        return error_domain::auth;
    }
    return error_domain::sandbox;
}

/// True when the code is one this version defines.
///
/// Used when decoding an error from a log or a peer: an unknown code is a
/// `core::encoding_invalid`, never a silently accepted value.
[[nodiscard]] constexpr auto is_known(auth_error error) noexcept -> bool {
    switch (error) {
    case auth_error::value_out_of_range:
    case auth_error::buffer_too_small:
    case auth_error::encoding_invalid:
    case auth_error::capacity_exhausted:
    case auth_error::not_found:
    case auth_error::digest_mismatch:
    case auth_error::mac_invalid:
    case auth_error::key_material_invalid:
    case auth_error::randomness_unavailable:
    case auth_error::insufficient_rights:
    case auth_error::delegation_denied:
    case auth_error::capability_revoked:
    case auth_error::capability_forged:
    case auth_error::resource_unavailable:
    case auth_error::capability_neutralised:
    case auth_error::unauthenticated:
    case auth_error::credential_rejected:
    case auth_error::attestation_failed:
    case auth_error::attestation_expired:
    case auth_error::trust_anchor_unknown:
    case auth_error::identity_revoked:
    case auth_error::principal_unknown:
    case auth_error::policy_denied:
    case auth_error::session_state_invalid:
    case auth_error::elevation_required:
    case auth_error::policy_incomplete:
    case auth_error::access_denied:
    case auth_error::audit_unavailable:
    case auth_error::object_sealed:
        return true;
    }
    return false;
}

/// True when the caller can plausibly do something other than give up.
///
/// This is the only classification the API makes about recoverability, and it
/// is deliberately conservative: a failure that indicates an attack (a forged
/// capability, a failed attestation) is *not* recoverable, because the correct
/// response is to stop, not to retry.
[[nodiscard]] constexpr auto is_recoverable(auth_error error) noexcept -> bool {
    switch (error) {
    case auth_error::value_out_of_range:
    case auth_error::buffer_too_small:
    case auth_error::not_found:
    case auth_error::randomness_unavailable:
    case auth_error::resource_unavailable:
    case auth_error::unauthenticated:
    case auth_error::credential_rejected:
    case auth_error::attestation_expired:
    case auth_error::elevation_required:
        return true;

    case auth_error::encoding_invalid:
    case auth_error::capacity_exhausted:
    case auth_error::digest_mismatch:
    case auth_error::mac_invalid:
    case auth_error::key_material_invalid:
    case auth_error::insufficient_rights:
    case auth_error::delegation_denied:
    case auth_error::capability_revoked:
    case auth_error::capability_forged:
    case auth_error::capability_neutralised:
    case auth_error::attestation_failed:
    case auth_error::trust_anchor_unknown:
    case auth_error::identity_revoked:
    case auth_error::principal_unknown:
    case auth_error::policy_denied:
    case auth_error::session_state_invalid:
    case auth_error::policy_incomplete:
    case auth_error::access_denied:
    case auth_error::audit_unavailable:
    case auth_error::object_sealed:
        return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Result plumbing
// ---------------------------------------------------------------------------

/// The result of an operation that can fail with a domain error.
///
/// `std::expected` rather than exceptions, and rather than an out-parameter:
/// the failure is part of the signature, so a caller that ignores it does not
/// compile past `[[nodiscard]]`, and a `catch (...)` somewhere up the stack
/// cannot swallow a security decision.
template <typename T>
using result = std::expected<T, auth_error>;

/// The result of an operation with nothing to return.
using status = result<void>;

/// Build the failure half of a `result`. Spelled out rather than using
/// `std::unexpected` at every call site so that a grep for failures finds one
/// form.
[[nodiscard]] constexpr auto failure(auth_error error) noexcept
    -> std::unexpected<auth_error> {
    return std::unexpected<auth_error>{error};
}

/// Success with no value.
[[nodiscard]] constexpr auto success() noexcept -> status { return status{}; }

/// Propagate a failure out of a function that returns `status`.
///
/// The macros exist because the alternative in a language without exceptions is
/// a hand-written `if (!value) return failure(value.error());` at every step,
/// which is exactly the place where a security-relevant check gets lost. They
/// expand to ordinary declarations and `if` statements -- no statement
/// expressions, no GNU extensions -- so they are usable under -Wpedantic and
/// behave identically at compile time and at run time.
#define META_AUTH_TRY_VOID(expression)                                                       \
    do {                                                                                     \
        auto&& meta_auth_status = (expression);                                              \
        if (!meta_auth_status.has_value()) {                                                 \
            return ::meta_auth::failure(meta_auth_status.error());                           \
        }                                                                                    \
    } while (false)

/// Propagate a failure, or bind the value to `name`.
///
/// `name` and `name_result` are introduced into the enclosing scope, so the
/// macro is a declaration rather than an expression. Two uses of the same name
/// in one scope collide, which is deliberate: shadowing a checked value with a
/// second checked value is a defect, not a convenience.
#define META_AUTH_TRY_BIND(name, expression)                                                 \
    auto&& name##_result = (expression);                                                     \
    if (!name##_result.has_value()) {                                                        \
        return ::meta_auth::failure(name##_result.error());                                  \
    }                                                                                        \
    auto& name = *name##_result

} // namespace meta_auth

// ---------------------------------------------------------------------------
// Formatting, so that a failure report or a log line renders an error the same
// way everywhere (the test harness picks this up automatically).
// ---------------------------------------------------------------------------
template <>
struct std::formatter<meta_auth::auth_error, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(meta_auth::auth_error error, std::format_context& context) const {
        return std::format_to(context.out(), "{}({})", meta_auth::to_string(error),
                              static_cast<std::uint16_t>(error));
    }
};

template <>
struct std::formatter<meta_auth::error_domain, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(meta_auth::error_domain domain, std::format_context& context) const {
        using meta_auth::error_domain;
        std::string_view name = "unknown";
        switch (domain) {
        case error_domain::core:
            name = "core";
            break;
        case error_domain::crypto:
            name = "crypto";
            break;
        case error_domain::capability:
            name = "capability";
            break;
        case error_domain::identity:
            name = "identity";
            break;
        case error_domain::auth:
            name = "auth";
            break;
        case error_domain::sandbox:
            name = "sandbox";
            break;
        }
        return std::format_to(context.out(), "{}", name);
    }
};

#endif // META_AUTH_CORE_ERROR_HPP
