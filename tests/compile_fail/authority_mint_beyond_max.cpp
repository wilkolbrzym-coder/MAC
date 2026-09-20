// An authority may not create a capability stronger than itself.
#include "_prefix.hpp"

auto main() -> int {
    const authority<negative_test::device_resource, rights_set{right::read}> limited;
    auto too_strong = limited.mint<rights_set{right::read, right::write}>();
    static_cast<void>(too_strong);
    return 0;
}
