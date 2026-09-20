// Capabilities are affine: duplicating one requires delegate().
#include "_prefix.hpp"

auto main() -> int {
    negative_test::device_authority root;
    auto original = root.mint<rights_set{right::read}>();
    auto duplicate = original;
    static_cast<void>(duplicate);
    return 0;
}
