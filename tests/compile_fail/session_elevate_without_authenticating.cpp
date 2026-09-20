// A second factor requires an authenticated session first.
#include "_prefix.hpp"

auto main() -> int {
    auto anonymous = session<operator_principal, session_state::anonymous>::begin();
    auto elevated =
        std::move(anonymous).elevate(negative_test::operator_second_factor, "totp");
    static_cast<void>(elevated);
    return 0;
}
