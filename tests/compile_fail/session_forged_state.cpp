// A session state cannot be fabricated. This is the program that compiled
// before: `session_core` was an aggregate with a public `create()` and the
// session's constructor took one, so an elevated session for the
// administrator was two lines away with no credential and no second factor.
#include "_prefix.hpp"

auto main() -> int {
    auto forged = session<admin_principal, session_state::elevated>{detail::session_core{}};
    static_cast<void>(forged.require_second_factor());
    return 0;
}
