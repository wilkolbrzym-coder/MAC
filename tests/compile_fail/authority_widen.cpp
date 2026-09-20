// An authority can be narrowed but never widened.
#include "_prefix.hpp"

auto main() -> int {
    const authority<negative_test::device_resource, rights_set{right::read}> limited;
    auto widened = limited.restrict<rights_set{right::read, right::write}>();
    static_cast<void>(widened);
    return 0;
}
