// The value of a protected object has no accessor that skips the gate.
#include "_prefix.hpp"

auto main() -> int {
    protected_object<std::uint32_t, resource_kind::devices> registry{1U};
    auto value = registry.value_;
    static_cast<void>(value);
    return 0;
}
