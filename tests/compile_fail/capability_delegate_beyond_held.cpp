// A capability cannot delegate authority it does not have.
#include "_prefix.hpp"

auto main() -> int {
    negative_test::device_authority root;
    auto holder = root.mint<rights_set{right::read, right::grant}>();
    auto too_much = holder.delegate<rights_set{right::read, right::write, right::grant}>();
    static_cast<void>(too_much);
    return 0;
}
