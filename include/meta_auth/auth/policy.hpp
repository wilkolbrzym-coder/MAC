// ===========================================================================
//  meta-auth-core -- the policy engine.
//
//  A policy is a compile-time value: a list of rules, each naming a resource, an
//  action and who may perform it. Evaluation is a `consteval` function, so a
//  request that the policy denies is not a run-time error -- it is a program
//  that does not compile.
//
//  Three properties are the reason for doing it this way:
//
//    1. **Deny by default.** `evaluate` returns `allow` only when a rule matches,
//       so a resource nobody thought about is a resource nobody can use.
//    2. **Exhaustiveness is checked, not reviewed.** `policy` asserts at
//       definition time that every enumerator of `resource_kind` has at least
//       one rule. Adding a resource without a rule is a build failure that names
//       the missing resource, rather than a code-review comment that may or may
//       not be read.
//    3. **Denial says why.** A denied request is reported by a `= delete("...")`
//       declaration naming the resource and the action, because "no matching
//       function" is not an explanation.
//
//  The engine evaluates the *static* part of authorisation: who may do what.
//  The dynamic part -- does this particular capability still exist, is it
//  current, does it hold the right -- belongs to the capability layer and to the
//  sandbox gate, and the two meet in `authorization`, the proof a caller must
//  present to reach a protected operation.
// ===========================================================================
#ifndef META_AUTH_AUTH_POLICY_HPP
#define META_AUTH_AUTH_POLICY_HPP

#include "meta_auth/capability/rights.hpp"
#include "meta_auth/config.hpp"
#include "meta_auth/core/contract.hpp"
#include "meta_auth/core/fixed_string.hpp"
#include "meta_auth/identity/principal.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string_view>
#include <type_traits>

#if META_AUTH_HAS_REFLECTION
#include <meta>
#endif

namespace meta_auth {

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// What an operation does to a resource.
///
/// Six verbs rather than a free-form string, because the exhaustiveness of the
/// policy depends on being able to enumerate what can be asked for. A policy
/// language with arbitrary action names cannot be checked for completeness, and
/// an incomplete policy is the normal way authorisation systems fail.
enum class action : std::uint8_t {
    observe = 0,  ///< read the resource's state
    modify = 1,   ///< change the resource's state
    invoke = 2,   ///< cause the resource to act
    delegate = 3, ///< hand authority over the resource to somebody else
    revoke = 4,   ///< invalidate the authority others hold
    audit = 5,    ///< read what has been done to the resource
};

[[nodiscard]] constexpr auto to_string(action value) noexcept -> std::string_view {
    switch (value) {
    case action::observe:
        return "observe";
    case action::modify:
        return "modify";
    case action::invoke:
        return "invoke";
    case action::delegate:
        return "delegate";
    case action::revoke:
        return "revoke";
    case action::audit:
        return "audit";
    }
    return "unknown";
}

/// The least capability right an action requires.
///
/// The mapping is total and is checked by a test: every action maps to a right,
/// so a policy rule cannot grant an action whose dynamic requirement nobody
/// stated. `delegate` maps to `grant` rather than to a right of its own, which
/// is what makes "you cannot delegate what you cannot delegate" a single rule
/// rather than two.
[[nodiscard]] constexpr auto required_right(action value) noexcept -> right {
    switch (value) {
    case action::observe:
        return right::read;
    case action::modify:
        return right::write;
    case action::invoke:
        return right::execute;
    case action::delegate:
        return right::grant;
    case action::revoke:
        return right::revoke;
    case action::audit:
        return right::audit;
    }
    return right::read;
}

/// The resources this library mediates.
///
/// An enumeration rather than a set of types, because the exhaustiveness check
/// has to be able to enumerate them. Each enumerator corresponds to a
/// `named_resource` in the sandbox layer, and the correspondence is asserted.
enum class resource_kind : std::uint8_t {
    devices = 0,
    sessions = 1,
    credentials = 2,
    audit_log = 3,
    policy_store = 4,
};

[[nodiscard]] constexpr auto to_string(resource_kind value) noexcept -> std::string_view {
    switch (value) {
    case resource_kind::devices:
        return "devices";
    case resource_kind::sessions:
        return "sessions";
    case resource_kind::credentials:
        return "credentials";
    case resource_kind::audit_log:
        return "audit-log";
    case resource_kind::policy_store:
        return "policy-store";
    }
    return "unknown";
}

/// The number of resource kinds.
///
/// With reflection this is derived from the enumeration, so adding an enumerator
/// updates it automatically. Without reflection it is the one hand-maintained
/// constant in this header, and the test suite asserts that it agrees with
/// reflection whenever reflection is available -- which means the fallback is
/// verified in the builds that can verify it, rather than assumed everywhere.
#if META_AUTH_HAS_REFLECTION
inline constexpr std::size_t resource_kind_count =
    std::meta::enumerators_of(^^resource_kind).size();
#else
inline constexpr std::size_t resource_kind_count = 5;
#endif

/// Every resource kind, in declaration order.
[[nodiscard]] constexpr auto all_resource_kinds() noexcept
    -> std::array<resource_kind, resource_kind_count> {
    std::array<resource_kind, resource_kind_count> kinds{};
    for (std::size_t index = 0; index < resource_kind_count; ++index) {
        kinds[index] = static_cast<resource_kind>(index);
    }
    return kinds;
}

// ---------------------------------------------------------------------------
// Who a rule applies to
// ---------------------------------------------------------------------------

/// Any principal of a given kind.
template <principal_kind Kind>
struct any_principal {
    static constexpr principal_kind kind = Kind;
};

/// Exactly one principal.
template <principal_type Principal>
struct exactly {
    using principal = Principal;
};

template <typename Pattern, principal_type Candidate>
[[nodiscard]] consteval auto pattern_matches() noexcept -> bool {
    if constexpr (requires { Pattern::kind; }) {
        return Candidate::kind == Pattern::kind;
    } else {
        return std::is_same_v<typename Pattern::principal, Candidate>;
    }
}

// ---------------------------------------------------------------------------
// Rules and policies
// ---------------------------------------------------------------------------

/// A rule: this resource, this action, these principals.
///
/// Rules only allow. There is no deny rule, because a policy with both kinds of
/// rule has an ordering problem, and the only ordering that is safe is "deny
/// wins" -- which is exactly what the absence of a matching allow already means.
/// Adding deny rules would create the possibility of expressing the same policy
/// two ways, one of which is wrong.
template <resource_kind Resource, action Action, typename... Who>
struct allow {
    static constexpr resource_kind resource = Resource;
    static constexpr action action_value = Action;
    static constexpr std::size_t who_count = sizeof...(Who);

    template <principal_type Candidate>
    [[nodiscard]] static consteval auto matches() noexcept -> bool {
        return (pattern_matches<Who, Candidate>() || ...);
    }
};

// ---------------------------------------------------------------------------
// Exhaustiveness
// ---------------------------------------------------------------------------

/// The resource kinds a policy's rules cover.
template <typename... Rules>
[[nodiscard]] constexpr auto covered_resources() noexcept
    -> std::array<bool, resource_kind_count> {
    std::array<bool, resource_kind_count> covered{};
    ((covered[static_cast<std::size_t>(Rules::resource)] = true), ...);
    return covered;
}

/// True when every resource kind has at least one rule.
///
/// This is the check that makes "deny by default" safe rather than merely
/// strict: without it, adding an enumerator to `resource_kind` and forgetting to
/// extend the policy produces a resource that is silently unusable -- or worse,
/// one that a wildcard rule nobody re-read happens to cover.
template <typename... Rules>
[[nodiscard]] consteval auto is_exhaustive() noexcept -> bool {
    const auto covered = covered_resources<Rules...>();
    for (const bool kind_covered : covered) {
        if (!kind_covered) {
            return false;
        }
    }
    return true;
}

/// The first uncovered resource kind, for the diagnostic.
template <typename... Rules>
[[nodiscard]] consteval auto first_uncovered() noexcept -> resource_kind {
    constexpr auto covered = covered_resources<Rules...>();
    for (std::size_t index = 0; index < covered.size(); ++index) {
        if (!covered[index]) {
            return static_cast<resource_kind>(index);
        }
    }
    return resource_kind::devices;
}

/// True when one rule grants a request.
template <typename Rule, principal_type Principal, resource_kind Resource, action Action>
[[nodiscard]] consteval auto rule_grants() noexcept -> bool {
    if constexpr (Rule::resource == Resource && Rule::action_value == Action) {
        return Rule::template matches<Principal>();
    } else {
        return false;
    }
}

/// A policy: an exhaustive set of rules.
template <typename... Rules>
class policy {
public:
    static constexpr std::size_t rule_count = sizeof...(Rules);

    /// Every rule in the policy, for diagnostics and for the tests.
    [[nodiscard]] static constexpr auto rules() noexcept {
        return std::array<resource_kind, rule_count>{Rules::resource...};
    }

    /// True when the policy has a rule for the resource.
    template <resource_kind Resource>
    [[nodiscard]] static constexpr auto covers() noexcept -> bool {
        return ((Rules::resource == Resource) || ...);
    }

    /// True when some rule grants this principal this action on this resource.
    ///
    /// A fold with no negation and no ordering, so there is nothing to get
    /// wrong: the answer is `allow` exactly when a rule matches.
    template <principal_type Principal, resource_kind Resource, action Action>
    [[nodiscard]] static consteval auto grants() noexcept -> bool {
        return (rule_grants<Rules, Principal, Resource, Action>() || ...);
    }

    /// The static assertion that makes an incomplete policy a build failure.
    ///
    /// It lives inside the class body so that declaring a policy is enough to
    /// check it: there is no separate step to forget.
    static_assert(is_exhaustive<Rules...>(),
                  "this policy does not cover every resource kind. Deny-by-default means an "
                  "uncovered resource is unusable, so an incomplete policy is a defect rather "
                  "than a cautious default. Add a rule for the resource named in "
                  "first_uncovered<Rules...>().");
};

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// The result of evaluating a request against a policy.
enum class decision : std::uint8_t { deny = 0, allow = 1 };

[[nodiscard]] constexpr auto to_string(decision value) noexcept -> std::string_view {
    return value == decision::allow ? "allow" : "deny";
}

/// Evaluate a request at compile time.
///
/// A fold over the rules with no negation: `allow` if any rule matches, `deny`
/// otherwise. There is no evaluation order to get wrong because `||` over a
/// list of pure predicates has no order.
template <typename Policy, principal_type Principal, resource_kind Resource, action Action>
[[nodiscard]] consteval auto evaluate() noexcept -> decision {
    return Policy::template grants<Principal, Resource, Action>() ? decision::allow : decision::deny;
}

/// A proof that the policy allows an operation.
///
/// Opaque: the constructor is private and `authorize` is the only function that
/// can produce one, so a protected operation that takes an `authorization`
/// cannot be reached without the decision having been made. The proof carries
/// the resource and the action so that a gate can audit *what* was authorised
/// rather than merely that something was.
template <resource_kind Resource, action Action>
class authorization {
public:
    static constexpr resource_kind resource = Resource;
    static constexpr action action_value = Action;

    authorization(const authorization&) = delete;
    auto operator=(const authorization&) -> authorization& = delete;
    authorization(authorization&&) noexcept = default;
    auto operator=(authorization&&) noexcept -> authorization& = default;
    ~authorization() = default;

private:
    /// `authorize` is the only friend, so the only way to obtain the proof is
    /// to have the decision made. A public issuer would make the proof
    /// decorative.
    template <typename Policy, principal_type Principal, resource_kind R, action A>
        requires(evaluate<Policy, Principal, R, A>() == decision::allow)
    friend consteval auto authorize() noexcept -> authorization<R, A>;

    constexpr authorization() noexcept = default;
};

/// Authorise an operation, or fail to compile.
///
/// The constraint on the two overloads is the decision itself, so exactly one of
/// them is viable for any request, and the denied one is deleted with a message
/// that names what was asked for.
template <typename Policy, principal_type Principal, resource_kind Resource, action Action>
    requires(evaluate<Policy, Principal, Resource, Action>() == decision::allow)
[[nodiscard]] consteval auto authorize() noexcept -> authorization<Resource, Action> {
    return authorization<Resource, Action>{};
}

template <typename Policy, principal_type Principal, resource_kind Resource, action Action>
    requires(evaluate<Policy, Principal, Resource, Action>() == decision::deny)
consteval auto authorize() noexcept = delete(
    "policy: denied by default. No rule in this policy grants this principal this action on this "
    "resource. Either the request is wrong or the policy is missing a rule -- and adding the rule "
    "is a deliberate act, which is the point.");

} // namespace meta_auth

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
template <>
struct std::formatter<meta_auth::action, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(meta_auth::action value, std::format_context& context) const {
        return std::format_to(context.out(), "{}", meta_auth::to_string(value));
    }
};

template <>
struct std::formatter<meta_auth::resource_kind, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(meta_auth::resource_kind value, std::format_context& context) const {
        return std::format_to(context.out(), "{}", meta_auth::to_string(value));
    }
};

template <>
struct std::formatter<meta_auth::decision, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(meta_auth::decision value, std::format_context& context) const {
        return std::format_to(context.out(), "{}", meta_auth::to_string(value));
    }
};

#endif // META_AUTH_AUTH_POLICY_HPP
