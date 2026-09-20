// A capability cannot be constructed from nothing: the constructor is private
// and an authority is the only way to obtain one.
#include "_prefix.hpp"

auto main() -> int {
    capability<negative_test::device_resource, rights_set{right::read}> forged;
    static_cast<void>(forged);
    return 0;
}
