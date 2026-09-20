// Delegation requires the grant right: without it a deputy could manufacture
// authority for a third party.
#include "_prefix.hpp"

auto main() -> int {
    negative_test::device_authority root;
    auto no_grant = root.mint<rights_set{right::read, right::write}>();
    auto handed_out = no_grant.delegate<rights_set{right::read}>();
    static_cast<void>(handed_out);
    return 0;
}
