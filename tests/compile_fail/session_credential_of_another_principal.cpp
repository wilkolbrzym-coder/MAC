// A credential record is bound to its principal.
#include "_prefix.hpp"

auto main() -> int {
    const credential_record<admin_principal> admin_record =
        credential_record<admin_principal>::enrol("admin-secret");
    auto anonymous = session<operator_principal, session_state::anonymous>::begin();
    auto authenticated = std::move(anonymous).authenticate(admin_record, "admin-secret");
    static_cast<void>(authenticated);
    return 0;
}
