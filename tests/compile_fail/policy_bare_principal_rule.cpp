// A rule names a *pattern*, not a principal type. Writing the bare principal
// where `exactly<...>` belongs used to mean "any principal of that kind" --
// a silent widening from one principal to every principal of its kind, in the
// direction that grants access.
#include "_prefix.hpp"

using widened_policy = policy<
    allow<resource_kind::devices, action::observe, admin_principal>,
    allow<resource_kind::sessions, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::credentials, action::observe, exactly<admin_principal>>,
    allow<resource_kind::audit_log, action::audit, any_principal<principal_kind::user>>,
    allow<resource_kind::policy_store, action::modify, exactly<admin_principal>>>;

auto main() -> int {
    static_cast<void>(widened_policy::rule_count);
    return 0;
}
