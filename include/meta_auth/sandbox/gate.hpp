// ===========================================================================
//  meta-auth-core -- the mediation gate and protected objects.
//
//  This is where the two halves of the model meet. The policy layer decides at
//  compile time *who may do what*, and produces a proof. The capability layer
//  carries *what this holder actually has*, as a value that must be presented.
//  Neither is sufficient alone:
//
//    * a policy proof without a capability would mean the request is authorised
//      in the abstract while nobody in particular holds the authority;
//    * a capability without a policy proof would mean possession is enough,
//      which is exactly the assumption that makes a stolen token usable.
//
//  `gate::admit` demands both, in that order of certainty: the proof is a
//  compile-time argument (a request the policy denies does not compile), and the
//  capability is checked at run time for the two things that cannot be known
//  when the program is built -- whether it holds the right, and whether it is
//  still current.
//
//  The gate is also the only place that records. A decision that is not
//  recorded is a decision nobody can review, and the record is written before
//  the caller is told the outcome, so a crash between the two leaves the
//  evidence rather than the act.
// ===========================================================================
#ifndef META_AUTH_SANDBOX_GATE_HPP
#define META_AUTH_SANDBOX_GATE_HPP

#include "meta_auth/auth/policy.hpp"
#include "meta_auth/capability/capability.hpp"
#include "meta_auth/config.hpp"
#include "meta_auth/core/contract.hpp"
#include "meta_auth/core/error.hpp"
#include "meta_auth/core/fixed_string.hpp"
#include "meta_auth/identity/principal.hpp"
#include "meta_auth/sandbox/audit.hpp"

#include <cstdint>
#include <format>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>

namespace meta_auth {

// ---------------------------------------------------------------------------
// Resources
//
// A resource is a type in the capability layer and an enumerator in the policy
// layer. This is the bridge between the two, and the correspondence is asserted
// rather than assumed: `to_string(kind)` and `resource_name<resource_for_t>`
// must agree, which the tests check for every kind.
// ---------------------------------------------------------------------------

template <resource_kind Kind>
struct resource_for;

template <>
struct resource_for<resource_kind::devices> {
    using type = named_resource<"devices">;
};

template <>
struct resource_for<resource_kind::sessions> {
    using type = named_resource<"sessions">;
};

template <>
struct resource_for<resource_kind::credentials> {
    using type = named_resource<"credentials">;
};

template <>
struct resource_for<resource_kind::audit_log> {
    using type = named_resource<"audit-log">;
};

template <>
struct resource_for<resource_kind::policy_store> {
    using type = named_resource<"policy-store">;
};

/// The capability-layer resource a policy-layer kind refers to.
template <resource_kind Kind>
using resource_for_t = typename resource_for<Kind>::type;

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// The mediation point for one resource.
///
/// Every operation on the resource goes through `admit`, and `admit` demands a
/// policy proof and a capability. There is no second path: the protected object
/// exposes no accessor that does not take both, which is what makes the gate a
/// gate rather than a suggestion.
///
/// The gate holds no authority of its own. It is the property that makes the
/// confused deputy impossible here: a component that holds nothing cannot be
/// tricked into using what it has, and a caller that lacks a capability cannot
/// supply one, because capabilities cannot be constructed.
template <resource_kind Resource>
class gate {
public:
    using resource_type = resource_for_t<Resource>;

    explicit gate(audit_trail& trail) noexcept : trail_(&trail) {}

    gate(const gate&) = delete;
    auto operator=(const gate&) -> gate& = delete;
    gate(gate&&) = delete;
    auto operator=(gate&&) -> gate& = delete;
    ~gate() = default;

    /// Admit an operation.
    ///
    /// The proof is taken by value: it is move-only, and consuming it means one
    /// proof authorises one operation rather than a session's worth of them.
    template <action Action, rights_set Rights, principal_type Principal>
    [[nodiscard]] auto admit(const capability<resource_type, Rights>& presented,
                             authorization<Resource, Action> proof,
                             std::string_view principal_label = {}) noexcept -> status {
        static_assert(Rights.is_subset_of(rights_set::all()),
                      "a capability's rights are always a subset of the defined rights");

        constexpr right required = required_right(Action);

        const audit_event base = make_event<Principal>(presented, principal_label);

        if (!presented.has(required)) {
            record(base, audit_outcome::denied_insufficient_rights);
            return failure(auth_error::insufficient_rights);
        }

        if (!presented.is_live()) {
            // Revoked after it was minted. The capability is a valid value and
            // it is simply no longer current; the distinction is what lets the
            // rejection be recorded rather than the capability vanishing.
            record(base, audit_outcome::denied_revoked);
            return failure(auth_error::capability_revoked);
        }

        record(base, audit_outcome::granted);
        static_cast<void>(proof); // consumed; the decision it proved was made above
        return success();
    }

    /// The trail this gate records into.
    [[nodiscard]] auto trail() noexcept -> audit_trail& { return *trail_; }
    [[nodiscard]] auto trail() const noexcept -> const audit_trail& { return *trail_; }

private:
    template <principal_type Principal, rights_set Rights>
    [[nodiscard]] constexpr auto make_event(
        const capability<resource_type, Rights>& presented,
        std::string_view principal_label) const noexcept -> audit_event {
        audit_event event{};
        event.timestamp_ns = audit_trail::now_ns();
        event.principal_hash =
            principal_label.empty() ? Principal::numeric_id()
                                    : hash_name_view(principal_label);
        event.resource_hash = resource_type::identifier();
        event.capability_serial = presented.serial();
        event.epoch = presented.epoch().value();
        event.rights_bits = presented.rights_value().bits();
        return event;
    }

    [[nodiscard]] static constexpr auto hash_name_view(std::string_view text) noexcept
        -> std::uint64_t {
        // A local re-derivation of FNV-1a over a run-time view: the compile-time
        // helper takes a fixed_string, and an audit record must be able to name
        // a principal whose label is only known at run time.
        std::uint64_t state = fnv1a_64::offset_basis;
        for (const char character : text) {
            state ^= static_cast<std::uint64_t>(static_cast<unsigned char>(character));
            state *= fnv1a_64::prime;
        }
        return state;
    }

    void record(const audit_event& base, audit_outcome outcome) noexcept {
        audit_event event = base;
        event.outcome = outcome;
        trail_->record(event);
    }

    audit_trail* trail_;
};

// ---------------------------------------------------------------------------
// Protected objects
// ---------------------------------------------------------------------------

/// A value that can only be reached through the gate.
///
/// The value is private and there is no accessor that skips the checks. Reading
/// it requires a capability holding `right::read` and a proof that the policy
/// allows `observe`; writing requires `right::write` and `modify`. Those are the
/// only two operations, and both go through the same gate, which is what makes
/// "the data is protected" a statement about the type rather than about the
/// discipline of the callers.
template <typename T, resource_kind Resource>
    requires std::copyable<T>
class protected_object {
public:
    using value_type = T;
    using resource_type = resource_for_t<Resource>;

    explicit protected_object(T initial) noexcept : value_(std::move(initial)) {}

    protected_object(const protected_object&) = delete;
    auto operator=(const protected_object&) -> protected_object& = delete;
    protected_object(protected_object&&) = delete;
    auto operator=(protected_object&&) -> protected_object& = delete;
    ~protected_object() = default;

    /// Read the value. Requires `observe` and the `read` right.
    template <rights_set Rights, principal_type Principal>
    [[nodiscard]] auto read(const capability<resource_type, Rights>& presented,
                            authorization<Resource, action::observe> proof,
                            gate<Resource>& mediator,
                            std::string_view principal_label = {}) const -> result<T> {
        // The admission is bound to a local before the propagation macro sees
        // it: the template argument list contains commas, and a macro argument
        // list does not know about angle brackets.
        const status admission = mediator.template admit<action::observe, Rights, Principal>(
            presented, std::move(proof), principal_label);
        META_AUTH_TRY_VOID(admission);
        return value_;
    }

    /// Replace the value. Requires `modify` and the `write` right.
    template <rights_set Rights, principal_type Principal>
    [[nodiscard]] auto write(const capability<resource_type, Rights>& presented,
                             authorization<Resource, action::modify> proof,
                             gate<Resource>& mediator, T replacement,
                             std::string_view principal_label = {}) -> status {
        const status admission = mediator.template admit<action::modify, Rights, Principal>(
            presented, std::move(proof), principal_label);
        META_AUTH_TRY_VOID(admission);
        value_ = std::move(replacement);
        return success();
    }

private:
    T value_;
};

} // namespace meta_auth

#endif // META_AUTH_SANDBOX_GATE_HPP
