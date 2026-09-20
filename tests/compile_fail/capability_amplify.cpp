// Attenuation may only remove rights. Asking for more is amplification.
#include "_prefix.hpp"

auto main() -> int {
    negative_test::device_authority root;
    auto read_only = root.mint<rights_set{right::read}>();
    auto amplified = std::move(read_only).attenuate<rights_set{right::read, right::write}>();
    static_cast<void>(amplified);
    return 0;
}
