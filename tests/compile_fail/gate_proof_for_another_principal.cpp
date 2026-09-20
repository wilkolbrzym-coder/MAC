// A proof is bound to the principal it was issued for. The gate takes the
// principal and the proof in the same call, so a proof obtained for one
// principal cannot be presented by an admission that names another -- which
// would otherwise let a holder of a capability write somebody else's name
// into the audit trail, and act under it.
#include "_prefix.hpp"

namespace {

[[nodiscard]] consteval auto proof_for_operator() noexcept
    -> authorization<resource_kind::devices, action::observe, operator_principal> {
    return meta_auth::authorize<negative_test::service_policy, operator_principal,
                                resource_kind::devices, action::observe>();
}

} // namespace

auto main() -> int {
    negative_test::device_authority root;
    auto capability = root.mint<rights_set{right::read}>();
    audit_trail trail;
    gate<resource_kind::devices> mediator{trail};
    const auto admission = mediator.admit<action::observe, rights_set{right::read},
                                          admin_principal>(capability, proof_for_operator());
    return admission.has_value() ? 0 : 1;
}
