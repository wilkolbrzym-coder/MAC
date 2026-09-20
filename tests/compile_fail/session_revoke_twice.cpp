// A revoked session is terminal: it has no revoke either.
#include "_prefix.hpp"

auto main() -> int {
    auto anonymous = session<operator_principal, session_state::anonymous>::begin();
    auto revoked = std::move(anonymous).revoke();
    auto revoked_again = std::move(revoked).revoke();
    static_cast<void>(revoked_again);
    return 0;
}
