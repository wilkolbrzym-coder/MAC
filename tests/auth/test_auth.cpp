// ===========================================================================
//  Tests of the session type-state and the policy engine.
//
//  Most of what these two components guarantee is checked by the compiler, and
//  the checks live where the guarantee does: the type-state assertions are in
//  session.hpp next to the class, and the policy's exhaustiveness assertion is
//  inside `policy` itself. What is tested here is the part a compiler cannot
//  express -- that a correct credential is accepted and every incorrect one is
//  not, that a transition preserves the session's identity, and that the
//  decision matrix is what the policy says it is, over every combination.
// ===========================================================================
#include "meta_auth/auth/policy.hpp"
#include "meta_auth/auth/session.hpp"
#include "test_framework.hpp"

#include <cstddef>
#include <cstdint>
#include <format>
#include <utility>
#include <string>
#include <string_view>
#include <vector>

using meta_auth::action;
using meta_auth::admin_principal;
using meta_auth::allow;
using meta_auth::any_principal;
using meta_auth::credential_record;
using meta_auth::decision;
using meta_auth::exactly;
using meta_auth::operator_principal;
using meta_auth::policy;
using meta_auth::principal_kind;
using meta_auth::resource_kind;
using meta_auth::auditor_principal;
using meta_auth::second_factor;
using meta_auth::session;
using meta_auth::session_state;
using meta_auth::service_principal;

namespace {

/// The application policy used by these tests, and by the demo.
using app_policy = policy<
    // Operators may observe and modify devices, and may hand out authority
    // over them; administrators may do everything an operator may.
    allow<resource_kind::devices, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::devices, action::modify, exactly<operator_principal>>,
    allow<resource_kind::devices, action::modify, exactly<admin_principal>>,
    allow<resource_kind::devices, action::delegate, exactly<operator_principal>>,
    allow<resource_kind::devices, action::revoke, exactly<admin_principal>>,

    // The service authenticates sessions and nothing else.
    allow<resource_kind::sessions, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::sessions, action::invoke, exactly<service_principal>>,

    // Credentials are an administrator's business.
    allow<resource_kind::credentials, action::modify, exactly<admin_principal>>,
    allow<resource_kind::credentials, action::revoke, exactly<admin_principal>>,
    allow<resource_kind::credentials, action::observe, exactly<admin_principal>>,

    // The audit log is readable by every authenticated principal and writable
    // by none of them: an audit trail a subject can edit is not evidence.
    allow<resource_kind::audit_log, action::audit, any_principal<principal_kind::user>>,
    allow<resource_kind::audit_log, action::audit, any_principal<principal_kind::service>>,

    // The policy store is administrator-only, and has no `observe` rule at
    // all: reading the policy is not a thing this application does.
    allow<resource_kind::policy_store, action::modify, exactly<admin_principal>>>;

/// A principal of each kind, so that a rule's `Who...` patterns can be turned
/// into concrete principals to evaluate.
using sensor_principal = meta_auth::principal<"sensor-7", principal_kind::device>;

template <typename Pattern>
struct representative;

template <principal_kind Kind>
struct representative<any_principal<Kind>> {
    using type = std::conditional_t<Kind == principal_kind::user, operator_principal,
                                    std::conditional_t<Kind == principal_kind::service,
                                                       service_principal, sensor_principal>>;
};

template <meta_auth::principal_type Principal>
struct representative<exactly<Principal>> {
    using type = Principal;
};

/// Verify that a rule is honoured by `evaluate`.
///
/// The cross-check that the evaluator does not ignore rules: each
/// `allow<...>` declaration is decomposed, its principal patterns are turned
/// into concrete principals, and the evaluator is asked for exactly those
/// combinations. Together with the denials asserted below, this pins the policy
/// from both sides without an explicit 3 x 5 x 6 matrix.
template <typename Rule>
struct rule_checker;

template <resource_kind Resource, action Action, typename... Who>
struct rule_checker<allow<Resource, Action, Who...>> {
    [[nodiscard]] static consteval auto honoured() noexcept -> bool {
        return ((meta_auth::evaluate<app_policy, typename representative<Who>::type, Resource,
                                      Action>()
                 == decision::allow)
                && ...);
    }
};

constexpr std::string_view operator_secret = "operator-passphrase";
constexpr std::string_view operator_second_factor = "operator-totp-000000";

/// The expected decision for every combination the tests exercise. Written as
/// a table so that the policy above and the expectation below can be compared
/// by reading them side by side.
[[nodiscard]] consteval auto expected_decision(principal_kind who, resource_kind resource,
                                               action what) noexcept -> decision {
    if (who == principal_kind::user) {
        // Deny by default: a user may read the device registry, but only an
        // operator may change it, and the distinction is the whole point.
        if (resource == resource_kind::devices) {
            return what == action::observe ? decision::allow : decision::deny;
        }
        if (resource == resource_kind::audit_log && what == action::audit) {
            return decision::allow;
        }
        if (resource == resource_kind::sessions && what == action::observe) {
            return decision::allow;
        }
        return decision::deny;
    }
    if (who == principal_kind::service) {
        if (resource == resource_kind::sessions && what == action::invoke) {
            return decision::allow;
        }
        if (resource == resource_kind::audit_log && what == action::audit) {
            return decision::allow;
        }
        return decision::deny;
    }
    return decision::deny;
}

/// The number of action enumerators, derived from reflection where it is
/// available so that adding one cannot leave the matrix quietly short.
#if META_AUTH_HAS_REFLECTION
inline constexpr std::size_t action_count =
    std::meta::enumerators_of(^^meta_auth::action).size();
#else
inline constexpr std::size_t action_count = 6;
#endif

/// A principal of each kind that *no rule names by name*.
///
/// `representative` above answers a different question -- "which principal
/// satisfies this pattern" -- and for `any_principal<user>` that answer is the
/// operator, who is also named by `exactly` rules. The matrix below asks what
/// an ordinary principal of the kind may do, so it needs a principal the policy
/// has no `exactly` rule for. Using the operator in both roles is how the table
/// came to disagree with the policy and then to be written and never called.
template <principal_kind Kind>
struct plain_principal;

template <>
struct plain_principal<principal_kind::user> {
    using type = auditor_principal;
};
template <>
struct plain_principal<principal_kind::service> {
    using type = service_principal;
};
template <>
struct plain_principal<principal_kind::device> {
    using type = sensor_principal;
};

/// One resource's column of the matrix.
template <principal_kind Kind, resource_kind Resource, std::size_t... Actions>
[[nodiscard]] consteval auto matrix_cell_row(std::index_sequence<Actions...>) noexcept -> bool {
    return ((meta_auth::evaluate<app_policy, typename plain_principal<Kind>::type, Resource,
                                 static_cast<meta_auth::action>(Actions)>()
             == expected_decision(Kind, Resource, static_cast<meta_auth::action>(Actions)))
            && ...);
}

/// One principal kind's row of the matrix: every resource, every action.
template <principal_kind Kind, std::size_t... Resources>
[[nodiscard]] consteval auto matrix_row(std::index_sequence<Resources...>) noexcept -> bool {
    return (matrix_cell_row<Kind, static_cast<resource_kind>(Resources)>(
                std::make_index_sequence<action_count>())
            && ...);
}

// The whole matrix, asserted rather than described.
//
// `expected_decision` was written as a table and then never called: the comment
// above the file claimed the decision matrix was checked "over every
// combination", and what actually ran was `rule_checker`, which verifies that
// the evaluator honours the rules it is given. That is a statement about the
// evaluator and says nothing about the policy -- a rule that allowed one
// principal too many satisfies it perfectly. These three assertions are the
// missing half: 3 x 5 x 6 = 90 decisions, each compared with what the policy is
// documented to say.
static_assert(matrix_row<principal_kind::user>(
    std::make_index_sequence<meta_auth::resource_kind_count>()));
static_assert(matrix_row<principal_kind::service>(
    std::make_index_sequence<meta_auth::resource_kind_count>()));
static_assert(matrix_row<principal_kind::device>(
    std::make_index_sequence<meta_auth::resource_kind_count>()));

/// The enrolled credentials. `enrol` is the enrolment step; it would run on the
/// device or in an administrative tool, and the record is what is kept.
inline const credential_record<operator_principal> operator_credential =
    credential_record<operator_principal>::enrol(operator_secret);

inline const second_factor<operator_principal> operator_mfa =
    second_factor<operator_principal>::enrol(operator_second_factor);

} // namespace

// ---------------------------------------------------------------------------
// Compile-time properties of the policy
// ---------------------------------------------------------------------------

/// The policy is exhaustive, which `policy` asserts internally; this records
/// what the assertion is worth checking against.
static_assert(app_policy::covers<resource_kind::devices>());
static_assert(app_policy::covers<resource_kind::policy_store>());
static_assert(meta_auth::is_exhaustive<
              allow<resource_kind::devices, action::observe, any_principal<principal_kind::user>>,
              allow<resource_kind::sessions, action::observe, any_principal<principal_kind::user>>,
              allow<resource_kind::credentials, action::observe, exactly<admin_principal>>,
              allow<resource_kind::audit_log, action::audit, exactly<admin_principal>>,
              allow<resource_kind::policy_store, action::modify, exactly<admin_principal>>>(),
              "a policy that covers every resource kind is exhaustive");

static_assert(app_policy::rule_count == 13);

/// Every rule is honoured: `evaluate` returns `allow` for the principals each
/// rule names. A policy whose rules the evaluator ignored would pass any test
/// that only checked denials, so both directions are asserted.
static_assert(rule_checker<allow<resource_kind::devices, action::observe,
                                 any_principal<principal_kind::user>>>::honoured());
static_assert(rule_checker<allow<resource_kind::devices, action::modify,
                                 exactly<operator_principal>>>::honoured());
static_assert(rule_checker<allow<resource_kind::devices, action::modify,
                                 exactly<admin_principal>>>::honoured());
static_assert(rule_checker<allow<resource_kind::devices, action::delegate,
                                 exactly<operator_principal>>>::honoured());
static_assert(rule_checker<allow<resource_kind::devices, action::revoke,
                                 exactly<admin_principal>>>::honoured());
static_assert(rule_checker<allow<resource_kind::sessions, action::observe,
                                 any_principal<principal_kind::user>>>::honoured());
static_assert(rule_checker<allow<resource_kind::sessions, action::invoke,
                                 exactly<service_principal>>>::honoured());
static_assert(rule_checker<allow<resource_kind::credentials, action::modify,
                                 exactly<admin_principal>>>::honoured());
static_assert(rule_checker<allow<resource_kind::credentials, action::revoke,
                                 exactly<admin_principal>>>::honoured());
static_assert(rule_checker<allow<resource_kind::credentials, action::observe,
                                 exactly<admin_principal>>>::honoured());
static_assert(rule_checker<allow<resource_kind::audit_log, action::audit,
                                 any_principal<principal_kind::user>>>::honoured());
static_assert(rule_checker<allow<resource_kind::audit_log, action::audit,
                                 any_principal<principal_kind::service>>>::honoured());
static_assert(rule_checker<allow<resource_kind::policy_store, action::modify,
                                 exactly<admin_principal>>>::honoured());

/// The other direction: a request the policy does not grant is denied, and the
/// resource is part of the request rather than decoration. An administrator who
/// may modify the policy store may still not read it, because this application
/// has no rule for reading it -- and "no rule" means "denied" rather than
/// "unclear".
static_assert(meta_auth::evaluate<app_policy, admin_principal, resource_kind::devices, action::observe>()
              == decision::allow);
static_assert(meta_auth::evaluate<app_policy, admin_principal, resource_kind::devices, action::revoke>()
              == decision::allow);
static_assert(meta_auth::evaluate<app_policy, admin_principal, resource_kind::policy_store, action::observe>()
              == decision::deny);
static_assert(meta_auth::evaluate<app_policy, admin_principal, resource_kind::policy_store, action::modify>()
              == decision::allow);
static_assert(meta_auth::evaluate<app_policy, admin_principal, resource_kind::audit_log, action::modify>()
              == decision::deny);
static_assert(meta_auth::evaluate<app_policy, operator_principal, resource_kind::devices, action::revoke>()
              == decision::deny);
static_assert(meta_auth::evaluate<app_policy, operator_principal, resource_kind::devices, action::invoke>()
              == decision::deny);
static_assert(meta_auth::evaluate<app_policy, operator_principal, resource_kind::credentials,
                       action::observe>()
              == decision::deny);
static_assert(meta_auth::evaluate<app_policy, operator_principal, resource_kind::credentials,
                       action::modify>()
              == decision::deny);
static_assert(meta_auth::evaluate<app_policy, operator_principal, resource_kind::sessions, action::observe>()
              == decision::allow);
static_assert(meta_auth::evaluate<app_policy, operator_principal, resource_kind::sessions, action::invoke>()
              == decision::deny);
static_assert(meta_auth::evaluate<app_policy, service_principal, resource_kind::devices, action::observe>()
              == decision::deny);
static_assert(meta_auth::evaluate<app_policy, service_principal, resource_kind::sessions, action::invoke>()
              == decision::allow);
static_assert(meta_auth::evaluate<app_policy, sensor_principal, resource_kind::devices, action::observe>()
              == decision::deny);

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------
META_AUTH_TEST("credential", "a_correct_secret_verifies_and_a_wrong_one_does_not") {
    META_AUTH_CHECK(meta_auth::verify_credential(operator_credential, operator_secret));
    META_AUTH_CHECK(!meta_auth::verify_credential(operator_credential, "wrong"));
    META_AUTH_CHECK(!meta_auth::verify_credential(operator_credential, ""));
    // A prefix of the secret must not verify: an implementation that compared a
    // prefix would accept this.
    META_AUTH_CHECK(!meta_auth::verify_credential(operator_credential, "operator-passphras"));
    // Nor must a longer string with the secret as a prefix.
    META_AUTH_CHECK(!meta_auth::verify_credential(operator_credential, "operator-passphrase "));
}

META_AUTH_TEST("credential", "a_record_is_bound_to_its_principal") {
    // The MAC is keyed by the principal's name, so two principals that choose
    // the same secret do not have interchangeable records. Without the binding,
    // a record leaked from one principal would authenticate another.
    const auto shared_secret = std::string_view{"the-same-secret"};
    const auto operator_record = credential_record<operator_principal>::enrol(shared_secret);
    const auto admin_record = credential_record<admin_principal>::enrol(shared_secret);

    META_AUTH_CHECK_NE(operator_record.mac(), admin_record.mac());
    META_AUTH_CHECK(meta_auth::verify_credential(operator_record, shared_secret));
    META_AUTH_CHECK(meta_auth::verify_credential(admin_record, shared_secret));
}

META_AUTH_TEST("credential", "an_unenrolled_principal_matches_no_secret") {
    const auto record = credential_record<service_principal>::unenrolled();
    META_AUTH_CHECK(!meta_auth::verify_credential(record, ""));
    META_AUTH_CHECK(!meta_auth::verify_credential(record, "anything"));
    META_AUTH_CHECK(!meta_auth::verify_credential(record, service_principal::name.view()));
}

META_AUTH_TEST("credential", "the_second_factor_is_checked_against_its_own_record") {
    META_AUTH_CHECK(meta_auth::verify_second_factor(operator_mfa, operator_second_factor));
    META_AUTH_CHECK(!meta_auth::verify_second_factor(operator_mfa, "000000"));

    // The primary credential must not satisfy the second factor, even though
    // both are MACs of a secret under the same principal key. If it did, the
    // "second" factor would be no factor at all.
    META_AUTH_CHECK(!meta_auth::verify_second_factor(operator_mfa, operator_secret));
}

// ---------------------------------------------------------------------------
// The session state machine
// ---------------------------------------------------------------------------
META_AUTH_TEST("session", "the_full_transition_chain") {
    auto anonymous = session<operator_principal, session_state::anonymous>::begin();
    const auto id = anonymous.identifier();
    META_AUTH_CHECK(id.is_valid());

    auto authenticated = std::move(anonymous).authenticate(operator_credential, operator_secret);
    META_AUTH_REQUIRE(authenticated.has_value());
    META_AUTH_CHECK_EQ(authenticated->identifier(), id);
    META_AUTH_CHECK_EQ(authenticated->principal_digest(), operator_principal::digest());
    META_AUTH_CHECK_EQ(authenticated->describe_subject(), std::string_view{"operator"});

    auto elevated =
        std::move(*authenticated).elevate(operator_mfa, operator_second_factor);
    META_AUTH_REQUIRE(elevated.has_value());
    META_AUTH_CHECK(elevated->require_second_factor());
    META_AUTH_CHECK_EQ(elevated->identifier(), id);

    auto revoked = std::move(*elevated).revoke();
    META_AUTH_CHECK_EQ(revoked.identifier(), id);
    // Nothing can be done with a revoked session -- not even reading who it was
    // for. The static assertions in session.hpp are the compile-time statement
    // of that; this is the run-time reminder.
    META_AUTH_CHECK_EQ(meta_auth::to_string(session_state::revoked), std::string_view{"revoked"});
}

META_AUTH_TEST("session", "a_wrong_credential_leaves_the_session_unauthenticated") {
    auto anonymous = session<operator_principal, session_state::anonymous>::begin();
    const auto outcome = std::move(anonymous).authenticate(operator_credential, "wrong");
    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::credential_rejected);
}

META_AUTH_TEST("session", "a_wrong_second_factor_does_not_elevate") {
    auto anonymous = session<operator_principal, session_state::anonymous>::begin();
    auto authenticated = std::move(anonymous).authenticate(operator_credential, operator_secret);
    META_AUTH_REQUIRE(authenticated.has_value());

    const auto outcome = std::move(*authenticated).elevate(operator_mfa, "000000");
    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::credential_rejected);
}

/// A credential record for one principal cannot be presented to another's
/// session at all: the parameter type rejects it, so the mistake is a compile
/// error rather than a rejection at run time. The diagnostic is asserted by
/// tests/compile_fail/session_credential_of_another_principal.cpp.
static_assert(!std::is_convertible_v<credential_record<admin_principal>,
                                     credential_record<operator_principal>>);
static_assert(!std::is_same_v<credential_record<admin_principal>,
                              credential_record<operator_principal>>);

META_AUTH_TEST("session", "sessions_get_distinct_identifiers") {
    std::vector<std::uint64_t> identifiers;
    for (int index = 0; index < 32; ++index) {
        auto anonymous = session<operator_principal, session_state::anonymous>::begin();
        identifiers.push_back(anonymous.identifier().value());
    }
    for (std::size_t lhs = 0; lhs < identifiers.size(); ++lhs) {
        for (std::size_t rhs = lhs + 1; rhs < identifiers.size(); ++rhs) {
            META_AUTH_CHECK_NE(identifiers[lhs], identifiers[rhs]);
        }
    }
}

META_AUTH_TEST("session", "a_session_carries_the_epoch_it_began_in") {
    auto anonymous = session<operator_principal, session_state::anonymous>::begin();
    META_AUTH_CHECK_EQ(anonymous.epoch(), meta_auth::current_epoch<operator_principal>());
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
META_AUTH_TEST("policy", "renders_actions_resources_and_decisions") {
    META_AUTH_CHECK_EQ(std::format("{}", action::observe), std::string{"observe"});
    META_AUTH_CHECK_EQ(std::format("{}", resource_kind::audit_log), std::string{"audit-log"});
    META_AUTH_CHECK_EQ(std::format("{}", decision::deny), std::string{"deny"});
    META_AUTH_CHECK_EQ(std::format("{}", session_state::elevated), std::string{"elevated"});
}

META_AUTH_TEST("session", "renders_principal_and_state") {
    auto anonymous = session<operator_principal, session_state::anonymous>::begin();
    const std::string rendered = std::format("{}", anonymous);
    META_AUTH_CHECK(rendered.find("operator") != std::string::npos);
    META_AUTH_CHECK(rendered.find("anonymous") != std::string::npos);
}

// ---------------------------------------------------------------------------
// The action-to-right mapping
// ---------------------------------------------------------------------------
META_AUTH_TEST("policy", "every_action_maps_to_exactly_one_right") {
    // The mapping is what connects the static policy to the dynamic capability
    // check. If an action mapped to no right, a gate would have nothing to
    // check; if two actions shared a right, a capability for one would satisfy
    // the other.
    std::vector<meta_auth::right> rights;
    for (std::uint8_t raw = 0; raw <= static_cast<std::uint8_t>(action::audit); ++raw) {
        const auto what = static_cast<action>(raw);
        const auto required = meta_auth::required_right(what);
        META_AUTH_CHECK(static_cast<std::uint32_t>(required) != 0U);
        for (const auto other : rights) {
            META_AUTH_CHECK_NE(required, other);
        }
        rights.push_back(required);
    }
    META_AUTH_CHECK_EQ(rights.size(), std::size_t{6});
}
