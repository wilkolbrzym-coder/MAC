// A request the policy does not grant does not compile.
#include "_prefix.hpp"

auto main() -> int {
    // The policy grants `modify` on devices to the operator, not to the
    // administrator... and this asks for the service principal.
    auto proof = authorize<negative_test::service_policy, service_principal,
                           resource_kind::devices, action::modify>();
    static_cast<void>(proof);
    return 0;
}
