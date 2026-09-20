// ===========================================================================
//  meta-auth-core -- principals.
//
//  A principal is whoever an operation is performed for or by: a user, a
//  device, a service. It is a type rather than a string because the identity
//  of a principal is a compile-time fact in this library: the policy engine
//  matches on it, the audit trail records it, and a misspelled principal name
//  should be a build failure rather than a request that is denied for reasons
//  nobody can reconstruct afterwards.
//
//  The name is the identity, and the digest of the name is what appears in
//  records. Two principals with the same name and different kinds are
//  different principals -- a user named "sensor-7" and a device named
//  "sensor-7" are not interchangeable, and the type system keeps them apart.
// ===========================================================================
#ifndef META_AUTH_IDENTITY_PRINCIPAL_HPP
#define META_AUTH_IDENTITY_PRINCIPAL_HPP

#include "meta_auth/config.hpp"
#include "meta_auth/core/fixed_string.hpp"
#include "meta_auth/core/strong_id.hpp"
#include "meta_auth/crypto/sha256.hpp"

#include <cstdint>
#include <string_view>

namespace meta_auth {

/// What a principal is. Part of the type, so a device identifier cannot be
/// passed where a user identifier is expected.
enum class principal_kind : std::uint8_t {
    user = 1,    ///< a natural person, authenticated by a credential
    device = 2,  ///< a thing, authenticated by attestation
    service = 3, ///< a component, authenticated by its host's attestation
};

[[nodiscard]] constexpr auto to_string(principal_kind kind) noexcept -> std::string_view {
    switch (kind) {
    case principal_kind::user:
        return "user";
    case principal_kind::device:
        return "device";
    case principal_kind::service:
        return "service";
    }
    return "unknown";
}

/// Tag types, one per kind, so that `strong_id` distinguishes principals of
/// different kinds without the kind having to be part of the value.
struct user_tag;
struct device_tag;
struct service_tag;

using user_id = strong_id<user_tag>;
using device_id = strong_id<device_tag>;
using service_id = strong_id<service_tag>;

/// A principal, named at compile time.
///
/// The name is the whole identity: there is no registry to consult, no
/// database that can disagree with the policy, and no way to construct a
/// principal that the policy does not know about.
template <fixed_string Name, principal_kind Kind>
struct principal {
    /// The name, as a `fixed_string` so it is usable as a template argument
    /// and comparable without constructing a `std::string`.
    static constexpr fixed_string<Name.size() + 1> name = Name;

    static constexpr principal_kind kind = Kind;

    /// The stable identity of this principal, for records and for a wire
    /// format. A digest of the kind and the name, so that a user and a device
    /// with the same name do not collide -- which is the defect this whole
    /// header exists to prevent.
    [[nodiscard]] static constexpr auto digest() noexcept -> crypto::sha256_digest {
        constexpr std::string_view kind_text = to_string(Kind);
        crypto::sha256_hasher hasher;
        hasher.update(kind_text);
        hasher.update(std::string_view{":"});
        hasher.update(std::string_view{Name.view()});
        return hasher.finish();
    }

    /// A numeric identifier derived from the digest, for tables and records
    /// that need a fixed-width key.
    [[nodiscard]] static constexpr auto numeric_id() noexcept -> std::uint64_t {
        const auto bytes = digest().bytes;
        std::uint64_t value = 0;
        for (std::size_t index = 0; index < sizeof(std::uint64_t); ++index) {
            value = (value << 8U) | std::to_integer<std::uint64_t>(bytes[index]);
        }
        return value == 0 ? 1U : value;
    }
};

template <typename Candidate>
concept principal_type = requires {
    { Candidate::name } -> std::convertible_to<std::string_view>;
    { Candidate::kind } -> std::convertible_to<principal_kind>;
    { Candidate::digest() } -> std::same_as<crypto::sha256_digest>;
};

/// The name of a principal, for diagnostics and for the audit rendering.
template <principal_type Principal>
[[nodiscard]] constexpr auto principal_name() noexcept -> std::string_view {
    return std::string_view{Principal::name};
}

// ---------------------------------------------------------------------------
// The identifiers a program actually uses.
//
// A user is named by a user name, a device by a device identifier issued at
// enrolment, and so on. The `strong_id` tags keep them apart at the type
// level; these aliases keep the spelling at the call site short.
// ---------------------------------------------------------------------------
namespace detail {

/// Tag for a `strong_id` that identifies a specific named principal.
template <fixed_string Name, principal_kind Kind>
struct named_principal_tag {
    /// Overrides the reflection-based tag name, so that an identifier renders
    /// as `admin#7` rather than as the name of this template.
    static constexpr std::string_view tag_name = Name.view();
};

} // namespace detail

/// An identifier for a specific, named principal.
template <fixed_string Name, principal_kind Kind>
using named_principal_id = strong_id<detail::named_principal_tag<Name, Kind>>;

/// The standard principals a program tends to need, spelled out so that the
/// policy and the tests refer to the same names.
using admin_principal = principal<"admin", principal_kind::user>;
using operator_principal = principal<"operator", principal_kind::user>;
using auditor_principal = principal<"auditor", principal_kind::user>;
using service_principal = principal<"meta-auth-service", principal_kind::service>;

static_assert(principal_type<admin_principal>);
static_assert(principal_type<service_principal>);
static_assert(!principal_type<int>);

/// The kinds are part of the identity: a user and a device that share a name
/// are different principals, which is the collision the digest is built to
/// avoid.
static_assert(principal<"sensor-7", principal_kind::user>::digest()
              != principal<"sensor-7", principal_kind::device>::digest());
static_assert(principal<"sensor-7", principal_kind::device>::digest()
              == principal<"sensor-7", principal_kind::device>::digest());

} // namespace meta_auth

#endif // META_AUTH_IDENTITY_PRINCIPAL_HPP
