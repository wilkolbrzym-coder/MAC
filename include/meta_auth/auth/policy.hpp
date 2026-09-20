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
///
/// The fall-through returns `right::revoke` rather than `right::read`. Both are
/// unreachable for a valid enumerator -- the switch is exhaustive and
/// `-Wswitch-enum` keeps it so -- but if a future enumerator slips past the
/// switch, the failure must be in the direction that denies access, and `read`
/// is the weakest right in the lattice. `revoke` is the strongest, so an
/// unmapped action demands the most authority instead of the least.
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
    return right::revoke;
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

    /// The member `pattern_matches` discriminates on. Distinct from `kind`,
    /// which every principal type has as well -- see the note there.
    static constexpr principal_kind any_of_kind = Kind;
};

/// Exactly one principal.
template <principal_type Principal>
struct exactly {
    using principal = Principal;
};

/// The one sentence every rejection of a malformed principal pattern uses.
///
/// A macro rather than a constant because `static_assert` needs a string
/// literal, and because three copies of a sentence that must agree are three
/// chances for them to stop agreeing.
#define META_AUTH_PRINCIPAL_PATTERN_MESSAGE                                         \
    "a policy rule's principal pattern must be exactly<Principal> or "              \
    "any_principal<Kind>. A bare principal type is not a pattern: it reads like "   \
    "one principal and would mean every principal of its kind."

namespace detail {

/// A dependent `false`, for a diagnostic that must fire only when a template is
/// actually instantiated with the offending type.
template <typename>
inline constexpr bool dependent_false = false;

} // namespace detail

/// True when `Pattern` is one of the two spellings a rule may use.
///
/// The discriminator is not "does it have a `principal` member", because that
/// question has a surprising answer. `principal<Name, Kind>` carries an
/// *injected-class-name*, so `typename principal<...>::principal` is valid and
/// names the class itself -- which means a bare principal type looks exactly
/// like `exactly<something>` to a member-detection test. The check is therefore
/// whether the member resolves to the enclosing type: that is true only for the
/// injected name, and it is what distinguishes
///
///     exactly<admin_principal>   // a pattern: this one principal
///     admin_principal            // not a pattern at all
///
/// A bare `principal<...>` would otherwise have been read as `exactly<itself>`
/// -- which is the *safe* reading, and therefore the more dangerous one: it
/// would have looked correct in every test and quietly meant something the
/// author never wrote.
template <typename Pattern>
[[nodiscard]] consteval auto is_principal_pattern() noexcept -> bool {
    if constexpr (requires { typename Pattern::principal; }) {
        return !std::is_same_v<typename Pattern::principal, Pattern>;
    } else if constexpr (requires { Pattern::any_of_kind; }) {
        return true;
    } else {
        return false;
    }
}

/// True when a rule's principal pattern covers `Candidate`.
///
/// `any_principal<Kind>` and `exactly<Principal>` are the whole vocabulary. The
/// widening this replaces was real: the matcher used to ask
/// `requires { Pattern::kind; }`, and *every* `principal<Name, Kind>` has a
/// `static constexpr principal_kind kind`, so a rule written
///
///     allow<resource_kind::devices, action::revoke, admin_principal>
///
/// fell through to the kind branch and granted `revoke` to every principal of
/// kind user -- one principal written, all of them authorised.
template <typename Pattern, principal_type Candidate>
[[nodiscard]] consteval auto pattern_matches() noexcept -> bool {
    if constexpr (requires { typename Pattern::principal; }) {
        if constexpr (std::is_same_v<typename Pattern::principal, Pattern>) {
            // The injected-class-name: a bare principal type was written.
            static_assert(detail::dependent_false<Pattern>,
                          META_AUTH_PRINCIPAL_PATTERN_MESSAGE);
            return false;
        } else {
            return std::is_same_v<typename Pattern::principal, Candidate>;
        }
    } else if constexpr (requires { Pattern::any_of_kind; }) {
        return Candidate::kind == Pattern::any_of_kind;
    } else {
        static_assert(detail::dependent_false<Pattern>,
                      META_AUTH_PRINCIPAL_PATTERN_MESSAGE);
        return false;
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

    /// Checked where the rule is written, not where it is evaluated.
    ///
    /// The matcher below raises the same objection, but only once a request
    /// reaches this rule -- and a rule that is never exercised is exactly the
    /// rule an unexercised widening hides in. The check belongs at the
    /// declaration.
    static_assert((is_principal_pattern<Who>() && ...),
                  META_AUTH_PRINCIPAL_PATTERN_MESSAGE);

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
/// the resource, the action *and the principal* so that a gate can audit what
/// was authorised, on whose behalf, rather than merely that something was.
///
/// Carrying the principal is what stops a proof from being presented for
/// somebody else. The gate takes the principal as a template parameter in the
/// same position, so a proof obtained for one principal cannot be passed to an
/// admission that claims another: the types do not match and the program does
/// not compile. Before that, `admit<Action, Rights, SomeOtherPrincipal>` would
/// accept any proof for that resource and action -- and name
/// `SomeOtherPrincipal` in the audit record, which is a stolen token that also
/// writes somebody else's name in the log.
template <resource_kind Resource, action Action, principal_type Principal>
class authorization {
public:
    static constexpr resource_kind resource = Resource;
    static constexpr action action_value = Action;
    using subject_type = Principal;

    authorization(const authorization&) = delete;
    auto operator=(const authorization&) -> authorization& = delete;

    /// Move is written out rather than defaulted, and that is not style.
    ///
    /// A defaulted move constructor is trivial, and a trivial move is what
    /// makes this empty class *trivially copyable* -- which it was, and which
    /// meant `std::bit_cast<authorization<...>>(std::array<std::byte, 1>{})`
    /// produced a valid-looking proof without the policy ever being
    /// evaluated. One line, no friend access, no cast that looks unusual. A
    /// user-provided move makes the class non-trivially-copyable, so
    /// `bit_cast` is ill-formed, and the only remaining way to obtain a proof
    /// is to satisfy `authorize`'s constraint.
    constexpr authorization(authorization&&) noexcept {}

    constexpr auto operator=(authorization&&) noexcept -> authorization& { return *this; }

    ~authorization() = default;

private:
    /// `authorize` is the only friend, so the only way to obtain the proof is
    /// to have the decision made. A public issuer would make the proof
    /// decorative.
    template <typename Policy, principal_type P, resource_kind R, action A>
        requires(evaluate<Policy, P, R, A>() == decision::allow)
    friend consteval auto authorize() noexcept -> authorization<R, A, P>;

    constexpr authorization() noexcept = default;
};

/// Authorise an operation, or fail to compile.
///
/// The constraint on the two overloads is the decision itself, so exactly one of
/// them is viable for any request, and the denied one is deleted with a message
/// that names what was asked for.
template <typename Policy, principal_type Principal, resource_kind Resource, action Action>
    requires(evaluate<Policy, Principal, Resource, Action>() == decision::allow)
[[nodiscard]] consteval auto authorize() noexcept -> authorization<Resource, Action, Principal> {
    return authorization<Resource, Action, Principal>{};
}

template <typename Policy, principal_type Principal, resource_kind Resource, action Action>
    requires(evaluate<Policy, Principal, Resource, Action>() == decision::deny)
consteval auto authorize() noexcept = delete(
    "policy: denied by default. No rule in this policy grants this principal this action on this "
    "resource. Either the request is wrong or the policy is missing a rule -- and adding the rule "
    "is a deliberate act, which is the point.");

/// A proof that exists only as a type, for the assertions about it.
///
/// The static checks below are written against types rather than values so that
/// they hold in a build with contracts disabled, where constructing one would
/// have to go through the fallback path.
static_assert(!std::is_copy_constructible_v<authorization<resource_kind::devices,
                                                          action::observe, admin_principal>>,
              "a proof is move-only: one proof authorises one operation");
static_assert(!std::is_trivially_copyable_v<authorization<resource_kind::devices,
                                                          action::observe, admin_principal>>,
              "a proof must not be trivially copyable, or std::bit_cast forges one without the "
              "policy ever being evaluated");

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

// The message macro exists for the three `static_assert`s above and is not part
// of the vocabulary a consumer sees.
#undef META_AUTH_PRINCIPAL_PATTERN_MESSAGE
