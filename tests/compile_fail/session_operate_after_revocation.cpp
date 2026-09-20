// A revoked session cannot act on its principal.
#include "_prefix.hpp"

auto main() -> int {
    auto anonymous = session<operator_principal, session_state::anonymous>::begin();
    auto revoked = std::move(anonymous).revoke();
    auto subject = revoked.describe_subject();
    static_cast<void>(subject);
    return 0;
}
