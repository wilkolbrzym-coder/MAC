// Identifiers of different kinds are different types.
#include "_prefix.hpp"

auto main() -> int {
    const device_id as_device = device_id::from_value(7);
    const user_id as_user = as_device;
    static_cast<void>(as_user);
    return 0;
}
