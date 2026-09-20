// ===========================================================================
//  meta-auth-core -- resources, authorities and capabilities.
//
//  A capability is an unforgeable, uncopyable token that *is* the authority to
//  use a resource. Not a claim about authority, not a reference to a
//  permission record: the authority itself, in a value the holder must
//  physically possess to act.
//
//  Three properties make that more than a metaphor, and each is enforced by
//  the compiler rather than by convention:
//
//    1. Unforgeable. The constructor is private and an `authority` is the only
//       friend, so there is no expression that produces a capability without
//       going through one. A capability cannot be built from an integer, a
//       string, or a serialised form.
//    2. Uncopyable (affine). Copy construction and copy assignment are
//       deleted. Duplicating a capability requires `delegate`, which demands
//       the `grant` right, so "how many copies of this authority exist" is a
//       question with an answer that a reviewer can find in the source.
//    3. Monotone. `attenuate` and `delegate` take the requested rights as a
//       template argument and are constrained by `requires`, so a capability
//       that is stronger than the one held is not a run-time error -- it is an
//       overload that does not exist, reported by a `= delete("...")`
//       declaration that names the missing rights.
//
//  A trap worth knowing about
//  -------------------------
//  `authority::mint` is not constexpr, and that is a finding rather than a
//  preference. The natural implementation -- one constexpr function with an
//  `if consteval` branch that returns a compile-time placeholder instead of
//  allocating a serial -- is silently wrong on GCC 16.0.1:
//
//      constexpr std::uint64_t next() {
//          if consteval { return 0; }
//          else { return counter().fetch_add(1, std::memory_order_relaxed) + 1; }
//      }
//      auto         a = next();   // 1, the counter advanced
//      const auto   b = next();   // 0, and the counter did NOT advance
//
//  Initialising a `const` integral variable makes the compiler constant-fold
//  the call. During that fold `if consteval` is true, so the compile-time
//  branch is taken and the run-time side effect is discarded -- even though a
//  function containing an atomic operation is not a constant expression and
//  folding it should have failed. The result is a program that compiles
//  cleanly and numbers its capabilities from zero.
//
//  The library therefore keeps the two contexts in separate functions:
//  `mint` has no compile-time path, and `mint_consteval` is `consteval`, so a
//  run-time call to it is ill-formed. Neither can be folded into the other,
//  and misusing them is a diagnostic rather than a wrong value.
//
//  What this does not defend against is stated in docs/threat-model.md: an
//  author with write access to the source can declare an `authority` for any
//  resource. The model prevents the *defects* -- forgery, duplication,
//  amplification, use after revocation -- not a malicious maintainer.
// ===========================================================================
#ifndef META_AUTH_CAPABILITY_CAPABILITY_HPP
#define META_AUTH_CAPABILITY_CAPABILITY_HPP

#include "meta_auth/capability/revocation.hpp"
#include "meta_auth/capability/rights.hpp"
#include "meta_auth/config.hpp"
#include "meta_auth/core/contract.hpp"
#include "meta_auth/core/error.hpp"
#include "meta_auth/core/fixed_string.hpp"

#include <atomic>
#include <cstdint>
#include <format>
#include <optional>
#include <string_view>
#include <utility>

namespace meta_auth {

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// A resource is a type that names itself.
///
/// Naming a resource with a *type* rather than a value is what lets its
/// capabilities be typed: `capability<named_resource<"devices">, ...>` is a
/// different type from `capability<named_resource<"sessions">, ...>`, so a
/// capability for the wrong resource is a compile error rather than a check
/// that somebody might forget.
template <typename Candidate>
concept resource = requires {
    { Candidate::name } -> std::convertible_to<std::string_view>;
};

/// The standard resource: a compile-time name.
template <fixed_string Name>
struct named_resource {
    static constexpr fixed_string<Name.size() + 1> name = Name;

    /// A stable 64-bit identifier, for the audit trail and for a wire format.
    /// Not a security primitive: it names a resource, it does not authenticate
    /// one.
    [[nodiscard]] static constexpr auto identifier() noexcept -> std::uint64_t {
        return hash_name(Name);
    }
};

template <resource Resource>
[[nodiscard]] constexpr auto resource_name() noexcept -> std::string_view {
    return std::string_view{Resource::name};
}

namespace detail {

/// Serial numbers, per resource type.
///
/// Every capability gets one, so that an audit record can name the exact
/// capability that was used. A single atomic increment per mint is the whole
/// cost of that traceability.
template <typename Resource>
[[nodiscard]] auto serial_slot() noexcept -> std::atomic<std::uint64_t>& {
    static std::atomic<std::uint64_t> slot{0};
    return slot;
}

/// A serial number, unique within the process for this resource type.
///
/// Deliberately not constexpr, and deliberately not guarded by `if consteval`.
/// See the note in the header comment: a compile-time branch inside a function
/// that also has run-time effects is a trap on the reference compiler.
template <typename Resource>
[[nodiscard]] inline auto next_serial() noexcept -> std::uint64_t {
    return serial_slot<Resource>().fetch_add(1, std::memory_order_relaxed) + 1U;
}

} // namespace detail

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

template <typename Resource, rights_set Rights>
class capability;

/// The authority to create capabilities.
///
/// An authority is where power enters the program. It is deliberately a
/// *declared* object: a reviewer looking for every source of authority in a
/// codebase greps for `authority<`, and every hit is a place where the program
/// decided to be able to do something. An authority can be restricted but
/// never widened, and it cannot mint beyond its declared maximum.
template <typename Resource, rights_set MaxRights>
class authority {
public:
    static_assert(resource<Resource>, "authority requires a resource type");
    static_assert(!MaxRights.is_empty(),
                  "an authority with no rights is a contradiction: it could not mint anything. "
                  "Either declare the rights it needs or remove it.");

    using resource_type = Resource;
    static constexpr rights_set max_rights = MaxRights;

    /// An authority over the resource, holding the declared maximum.
    ///
    /// Not private: creating an authority is a *source-level* decision that a
    /// reviewer must be able to see, and C++ has no way to make it anything
    /// else. What is private is the capability constructor, so an authority is
    /// the only thing that can turn declared intent into a usable token.
    constexpr authority() noexcept = default;

    /// Mint a capability holding exactly `Requested`.
    ///
    /// The rights are a template argument, so what a capability holds is
    /// visible at the point it is created and cannot be computed.
    ///
    /// Not constexpr, on purpose. The obvious implementation branches on
    /// `if consteval` to provide a run-time serial and a compile-time
    /// placeholder from one function, and that implementation is silently
    /// wrong on GCC 16.0.1: initialising a `const` integral variable makes the
    /// compiler constant-fold the call, which takes the compile-time branch
    /// and discards the counter increment, so
    ///
    ///     const auto serial = authority.mint<rights>().serial();  // 0
    ///     auto serial = authority.mint<rights>().serial();        // 1
    ///
    /// disagree. Two entry points with disjoint call contexts cannot be
    /// folded into each other: this one has no compile-time path, and
    /// `mint_consteval` cannot be called at run time at all.
    template <rights_set Requested>
        requires(Requested.is_subset_of(MaxRights))
    [[nodiscard]] auto mint() const noexcept -> capability<Resource, Requested> {
        return capability<Resource, Requested>{detail::next_serial<Resource>(),
                                               current_epoch<Resource>(), std::nullopt};
    }

    /// Mint a capability during constant evaluation.
    ///
    /// The reserved serial zero marks it as having no run-time identity, and
    /// it belongs to the initial epoch. `consteval` rather than `constexpr`:
    /// calling this at run time is ill-formed, so the misuse is a compile
    /// error rather than a value that quietly differs from what the run-time
    /// path would have produced.
    template <rights_set Requested>
        requires(Requested.is_subset_of(MaxRights))
    [[nodiscard]] consteval auto mint_consteval() const noexcept
        -> capability<Resource, Requested> {
        return capability<Resource, Requested>{0, revocation_epoch{}, std::nullopt};
    }

    /// The same request with rights outside the authority's maximum.
    ///
    /// Deleted with a message rather than constrained away, because "no
    /// matching function" does not tell the reader which right was too much.
    template <rights_set Requested>
        requires(!Requested.is_subset_of(MaxRights))
    constexpr auto mint() const noexcept = delete(
        "authority::mint: the requested rights exceed this authority's maximum. "
        "An authority cannot create a capability stronger than itself.");

    /// A permanently weaker authority.
    template <rights_set Smaller>
        requires(Smaller.is_subset_of(MaxRights))
    [[nodiscard]] constexpr auto restrict() const noexcept -> authority<Resource, Smaller> {
        return authority<Resource, Smaller>{};
    }

    template <rights_set Smaller>
        requires(!Smaller.is_subset_of(MaxRights))
    constexpr auto restrict() const noexcept = delete(
        "authority::restrict: the requested rights exceed this authority's maximum. "
        "An authority can be narrowed but never widened.");

};

/// An unforgeable, affine token of authority over a resource.
///
/// Move-only. The four operations a holder can perform are: inspect what it
/// grants, weaken it and keep the result (`attenuate`), give a weaker one away
/// (`delegate`, which needs `grant`), and present it to a gate. There is no
/// fifth.
template <typename Resource, rights_set Rights>
class capability {
public:
    static_assert(resource<Resource>, "capability requires a resource type");

    using resource_type = Resource;

    /// The rights this capability grants. A constant, not a query: it is part
    /// of the type, which is what allows the check to happen at compile time.
    static constexpr rights_set rights = Rights;

    /// The same value as a call, so that generic code can ask a capability
    /// object what it grants without naming its type.
    [[nodiscard]] static constexpr auto rights_value() noexcept -> rights_set { return Rights; }

    /// A capability cannot be created out of nothing.
    ///
    /// There was no default constructor before, so the program was rejected
    /// correctly and the diagnostic said "no matching function for call to
    /// 'capability<...>::capability()'" next to a dozen candidate notes. The
    /// declaration exists so the rejection states the rule instead.
    capability() = delete(
        "A capability cannot be constructed. Only an authority can create one: call mint() on an "
        "authority, take one from a gate's caller, or obtain one by delegation.");

    /// Affine: no copy constructor, no copy assignment.
    ///
    /// This is the property that makes duplication explicit. A program that
    /// wants two capabilities must delegate, which requires `grant`, so a
    /// capability that has been handed out cannot be multiplied by accident.
    ///
    /// The diagnostic is spelled out because this is the rejection a developer
    /// meets while writing ordinary-looking code, and "use of deleted
    /// function" does not say what to write instead.
    capability(const capability&) = delete(
        "A capability cannot be copied. Authority is handed on with delegate(), which requires "
        "right::grant, or weakened with attenuate(), which consumes this one.");
    auto operator=(const capability&) -> capability& = delete(
        "A capability cannot be copied. Authority is handed on with delegate(), which requires "
        "right::grant, or weakened with attenuate(), which consumes this one.");

    constexpr capability(capability&& other) noexcept
        : serial_(other.serial_), epoch_(other.epoch_), parent_(other.parent_),
          valid_(other.valid_) {
        // The moved-from capability is neutralised rather than left holding a
        // valid serial: two capabilities claiming the same serial would make
        // an audit trail ambiguous exactly where it matters.
        other.neutralise();
    }

    constexpr auto operator=(capability&& other) noexcept -> capability& {
        if (this != &other) {
            serial_ = other.serial_;
            epoch_ = other.epoch_;
            parent_ = other.parent_;
            valid_ = other.valid_;
            other.neutralise();
        }
        return *this;
    }

    ~capability() = default;

    /// True when this capability still holds authority.
    ///
    /// False for a capability that has been moved from or consumed by
    /// `attenuate`. Such a value is still a well-formed object of this type --
    /// it has to be, or moving would not be possible -- but it no longer
    /// *is* a capability, and both `has` and `is_live` report that rather than
    /// answering from the fields the object still happens to carry.
    [[nodiscard]] constexpr auto is_valid() const noexcept -> bool { return valid_; }

    [[nodiscard]] constexpr auto has(right value) const noexcept -> bool {
        return valid_ && Rights.contains(value);
    }

    /// True when this capability grants everything `Required` names. Used by
    /// the sandbox gate, and by the tests that assert the monotonicity law.
    template <rights_set Required>
    [[nodiscard]] static constexpr auto grants() noexcept -> bool {
        return Required.is_subset_of(Rights);
    }

    /// The serial number assigned when this capability was minted, or when the
    /// capability it was derived from was minted. Zero means "created during
    /// constant evaluation".
    [[nodiscard]] constexpr auto serial() const noexcept -> std::uint64_t { return serial_; }

    /// The serial of the capability this one was derived from, when there is
    /// one. Attenuation and delegation preserve provenance, so a capability in
    /// an audit record can be traced back to the authority that started it.
    [[nodiscard]] constexpr auto parent_serial() const noexcept -> std::optional<std::uint64_t> {
        return parent_;
    }

    /// The epoch this capability was minted in.
    [[nodiscard]] constexpr auto epoch() const noexcept -> revocation_epoch { return epoch_; }

    /// True when the resource's current epoch still matches this capability's.
    [[nodiscard]] auto is_live() const noexcept -> bool {
        return valid_ && epoch_is_current(epoch_, current_epoch<Resource>());
    }

    /// Weaken, keeping the result. Consumes the capability.
    ///
    /// Consuming rather than copying is the point: after attenuation there is
    /// exactly one capability, and it is the weaker one. A holder that wants
    /// to keep the stronger capability *and* hand out a weaker one must
    /// delegate, which requires the `grant` right.
    ///
    /// The source is neutralised, and that is not decoration. It was not, and
    /// the consequence was that `std::move(strong).attenuate<weaker>()` left
    /// `strong` fully usable -- so any capability could be duplicated at will,
    /// without `grant`, while the documentation promised that duplication
    /// requires delegation. Attenuation and delegation are different
    /// operations precisely because one consumes and the other does not; this
    /// is where that difference is enforced.
    template <rights_set Smaller>
        requires(Smaller.is_subset_of(Rights))
    [[nodiscard]] constexpr auto attenuate() && noexcept -> capability<Resource, Smaller> {
        capability<Resource, Smaller> weakened{serial_, epoch_, serial_, valid_};
        neutralise();
        return weakened;
    }

    template <rights_set Smaller>
        requires(!Smaller.is_subset_of(Rights))
    constexpr auto attenuate() && noexcept = delete(
        "capability::attenuate: the requested rights are not a subset of the rights held. "
        "Authority can only be weakened, never amplified.");

    /// Hand a weaker capability to somebody else, keeping this one.
    ///
    /// Requires both that the requested rights are a subset of the held rights
    /// and that this capability holds `grant`. The second requirement is the
    /// rule that stops a deputy from becoming a source of authority: without
    /// it, any holder could manufacture authority for a third party.
    template <rights_set Smaller>
        requires(Smaller.is_subset_of(Rights) && Rights.contains(delegation_right))
    [[nodiscard]] constexpr auto delegate() const noexcept -> capability<Resource, Smaller> {
        return capability<Resource, Smaller>{serial_, epoch_, serial_, valid_};
    }

    /// Delegation without the `grant` right.
    template <rights_set Smaller>
        requires(Smaller.is_subset_of(Rights) && !Rights.contains(delegation_right))
    constexpr auto delegate() const noexcept = delete(
        "capability::delegate: this capability does not hold right::grant, so it cannot be "
        "handed on. Delegation requires the right to delegate.");

    /// Delegation of rights that are not held.
    template <rights_set Smaller>
        requires(!Smaller.is_subset_of(Rights))
    constexpr auto delegate() const noexcept = delete(
        "capability::delegate: the requested rights are not a subset of the rights held. "
        "A capability cannot delegate authority it does not have.");

private:
    /// Private, and `authority` is the only friend that can reach it. Every
    /// other capability instantiation is a friend as well, because attenuation
    /// and delegation produce a capability of a different type.
    template <typename OtherResource, rights_set OtherRights>
    friend class capability;

    template <typename OtherResource, rights_set OtherMaxRights>
    friend class authority;

    constexpr capability(std::uint64_t serial, revocation_epoch epoch,
                         std::optional<std::uint64_t> parent, bool valid = true) noexcept
        : serial_(serial), epoch_(epoch), parent_(parent), valid_(valid) {}

    /// Drop the authority without destroying the object.
    ///
    /// The serial is cleared as well as the validity flag: a serial is what an
    /// audit record uses to name the capability that was used, and a
    /// neutralised value that still reports one invites a record that points
    /// at a capability nobody presented.
    constexpr void neutralise() noexcept {
        serial_ = 0;
        parent_ = std::nullopt;
        valid_ = false;
    }

    std::uint64_t serial_ = 0;
    revocation_epoch epoch_{};
    std::optional<std::uint64_t> parent_{};
    bool valid_ = true;
};

/// A capability is never a reference to shared state, so it can be used across
/// threads without synchronisation as long as the resource it names is.
static_assert(std::is_nothrow_move_constructible_v<capability<named_resource<"x">, rights_set{}>>);
static_assert(!std::is_copy_constructible_v<capability<named_resource<"x">, rights_set{}>>);
static_assert(!std::is_copy_assignable_v<capability<named_resource<"x">, rights_set{}>>);

} // namespace meta_auth

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
template <meta_auth::resource Resource, meta_auth::rights_set Rights>
struct std::formatter<meta_auth::capability<Resource, Rights>, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(const meta_auth::capability<Resource, Rights>& value,
                std::format_context& context) const {
        const auto serial = value.serial();
        const auto epoch = value.epoch().value();
        return std::format_to(context.out(), "capability<{}>[{}]#{}@{}",
                              meta_auth::resource_name<Resource>(), Rights.to_string(), serial,
                              epoch);
    }
};

#endif // META_AUTH_CAPABILITY_CAPABILITY_HPP
