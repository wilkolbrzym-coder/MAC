// A policy that does not cover every resource kind does not compile.
#include "_prefix.hpp"

// `credentials` has no rule, so deny-by-default would make it unusable and the
// policy's own assertion refuses to accept it.
using incomplete_policy = policy<
    allow<resource_kind::devices, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::sessions, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::audit_log, action::audit, any_principal<principal_kind::user>>,
    allow<resource_kind::policy_store, action::modify, exactly<admin_principal>>>;

auto main() -> int {
    static_cast<void>(incomplete_policy::rule_count);
    return 0;
}
