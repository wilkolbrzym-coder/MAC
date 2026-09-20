// ===========================================================================
//  meta-auth-core -- runnable demonstration.
//
//  One program that walks the whole model in the order a real deployment would:
//  enrol a device, attest it, authenticate a person, elevate with a second
//  factor, hand out authority, use it through the mediation gate, revoke it,
//  and read back what happened.
//
//  The attacks are in the middle rather than in an appendix, because the point
//  of the library is the refusals: a demonstration that only shows the happy
//  path demonstrates nothing that a `return true` would not.
//
//  Exit code is 0 when every step behaved as documented, so this doubles as an
//  end-to-end test that the test suite runs as well as a human can.
// ===========================================================================
#include "meta_auth/auth/policy.hpp"
#include "meta_auth/auth/session.hpp"
#include "meta_auth/capability/capability.hpp"
#include "meta_auth/config.hpp"
#include "meta_auth/identity/device.hpp"
#include "meta_auth/sandbox/gate.hpp"
#include "meta_auth/version.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <string_view>

namespace {

using namespace meta_auth;

// ---------------------------------------------------------------------------
// The policy, declared in one place
// ---------------------------------------------------------------------------
using application_policy = policy<
    allow<resource_kind::devices, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::devices, action::modify, exactly<operator_principal>>,
    allow<resource_kind::devices, action::modify, exactly<admin_principal>>,
    allow<resource_kind::devices, action::delegate, exactly<operator_principal>>,
    allow<resource_kind::devices, action::revoke, exactly<admin_principal>>,
    allow<resource_kind::sessions, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::sessions, action::invoke, exactly<service_principal>>,
    allow<resource_kind::credentials, action::observe, exactly<admin_principal>>,
    allow<resource_kind::credentials, action::modify, exactly<admin_principal>>,
    allow<resource_kind::credentials, action::revoke, exactly<admin_principal>>,
    allow<resource_kind::audit_log, action::audit, any_principal<principal_kind::user>>,
    allow<resource_kind::audit_log, action::audit, any_principal<principal_kind::service>>,
    allow<resource_kind::policy_store, action::modify, exactly<admin_principal>>>;

// ---------------------------------------------------------------------------
// The enrolled devices, and the trust store built from them
// ---------------------------------------------------------------------------
constexpr device_descriptor bench_device{
    .manufacturer = "Acme Instruments",
    .model = "Thermo-1",
    .serial = "SN-0001",
    .firmware = 0x0001'0000U,
};

constexpr device_descriptor rogue_device{
    .manufacturer = "Acme Instruments",
    .model = "Thermo-1",
    .serial = "SN-0002",
    .firmware = 0x0001'0000U,
};

/// Only the bench device is enrolled. The rogue one is a real device with a
/// real key that simply is not trusted -- the interesting case, because it is
/// the one a naive verifier accepts.
using deployment_trust_store = trust_store<bench_device.digest()>;

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------
constexpr std::string_view operator_password = "correct horse battery staple";
constexpr std::string_view operator_totp = "123456";

constexpr credential_record<operator_principal> operator_credential =
    credential_record<operator_principal>::enrol(operator_password);
constexpr second_factor<operator_principal> operator_second_factor =
    second_factor<operator_principal>::enrol(operator_totp);

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------
int failures = 0;

void step(std::string_view title) {
    std::printf("\n== %.*s\n", static_cast<int>(title.size()), title.data());
}

void expect(bool condition, std::string_view what) {
    if (condition) {
        std::printf("   ok    %.*s\n", static_cast<int>(what.size()), what.data());
    } else {
        std::printf("   FAIL  %.*s\n", static_cast<int>(what.size()), what.data());
        ++failures;
    }
}

/// A proof that the policy allows an operation. A helper per request, because
/// `authorize` is `consteval` and has to be called in a constant expression.
[[nodiscard]] consteval auto allow_observe() noexcept
    -> authorization<resource_kind::devices, action::observe> {
    return authorize<application_policy, operator_principal, resource_kind::devices,
                     action::observe>();
}

[[nodiscard]] consteval auto allow_modify() noexcept
    -> authorization<resource_kind::devices, action::modify> {
    return authorize<application_policy, operator_principal, resource_kind::devices,
                     action::modify>();
}

using device_registry = protected_object<std::uint32_t, resource_kind::devices>;
using device_gate = gate<resource_kind::devices>;
using device_authority = authority<resource_for_t<resource_kind::devices>, rights_set::all()>;

} // namespace

auto main() -> int {
    std::printf("%.*s %.*s\n", static_cast<int>(project_name.size()), project_name.data(),
                static_cast<int>(version.size()), version.data());
    std::printf("dialect: %s\n", config::dialect_summary());

    // -- 1. The trust store is a compile-time value -------------------------
    step("1. what this build trusts");
    std::printf("   anchors: %zu\n", deployment_trust_store::size);
    expect(deployment_trust_store::contains(bench_device.digest()),
           "the enrolled device is an anchor");
    expect(!deployment_trust_store::contains(rogue_device.digest()),
           "a device that was never enrolled is not");

    // -- 2. Attestation ----------------------------------------------------
    step("2. attestation");
    const device_key bench_key = device_key::derive_for_testing("bench-enrolment-secret");
    const auto bench_claim = attest(bench_device, bench_key);
    expect(verify_attestation_against<deployment_trust_store>(bench_claim, bench_device, bench_key)
               .has_value(),
           "the enrolled device proves what it is");

    // The attack: describe yourself as the enrolled device while claiming its
    // identity. The verifier re-hashes the descriptor it was given.
    auto lying_device = bench_device;
    lying_device.firmware = 0x0002'0000U;
    const auto lying = verify_attestation(bench_claim, lying_device, bench_key);
    expect(!lying.has_value() && lying.error() == auth_error::attestation_failed,
           "a device that misdescribes itself is refused");

    // The attack: a real, correctly keyed device that is not enrolled.
    const device_key rogue_key = device_key::derive_for_testing("rogue-enrolment-secret");
    const auto rogue_claim = attest(rogue_device, rogue_key);
    const auto unenrolled =
        verify_attestation_against<deployment_trust_store>(rogue_claim, rogue_device, rogue_key);
    expect(!unenrolled.has_value() && unenrolled.error() == auth_error::trust_anchor_unknown,
           "a genuine but unenrolled device is refused");

    // -- 3. Authentication and elevation -----------------------------------
    step("3. the session type-state");
    auto anonymous = session<operator_principal, session_state::anonymous>::begin();
    const auto session_identifier = anonymous.identifier();
    std::printf("   session id: %llu\n",
                static_cast<unsigned long long>(session_identifier.value()));

    const auto rejected = std::move(anonymous).authenticate(operator_credential, "wrong");
    expect(!rejected.has_value(), "a wrong password is refused");
    expect(rejected.error() == auth_error::credential_rejected, "and says why");

    auto anonymous_again = session<operator_principal, session_state::anonymous>::begin();
    auto authenticated =
        std::move(anonymous_again).authenticate(operator_credential, operator_password);
    expect(authenticated.has_value(), "the right password authenticates");

    if (!authenticated.has_value()) {
        std::printf("\n%d step(s) failed\n", failures + 1);
        return EXIT_FAILURE;
    }

    const auto wrong_factor = std::move(*authenticated).elevate(operator_second_factor, "000000");
    expect(!wrong_factor.has_value(), "a wrong second factor does not elevate");

    auto authenticated_again =
        session<operator_principal, session_state::anonymous>::begin().authenticate(
            operator_credential, operator_password);
    auto elevated =
        std::move(*authenticated_again).elevate(operator_second_factor, operator_totp);
    expect(elevated.has_value(), "the right second factor elevates");
    if (!elevated.has_value()) {
        std::printf("\n%d step(s) failed\n", failures + 1);
        return EXIT_FAILURE;
    }
    std::printf("   elevated session: %s\n", std::format("{}", *elevated).c_str());

    // -- 4. Minting, attenuation and delegation ----------------------------
    step("4. capabilities");
    const device_authority root;
    auto strong = root.mint<rights_set::all()>();
    std::printf("   minted: %s\n", std::format("{}", strong).c_str());

    const auto delegated = strong.delegate<rights_set{right::read, right::grant}>();
    std::printf("   delegated: %s (from serial %llu)\n", std::format("{}", delegated).c_str(),
                static_cast<unsigned long long>(*delegated.parent_serial()));

    auto weakened = root.mint<rights_set::all()>().attenuate<rights_set{right::read}>();
    expect(weakened.rights_value() == rights_set{right::read}, "attenuation keeps only the subset");

    // -- 5. The gate --------------------------------------------------------
    step("5. mediation");
    audit_trail trail;
    device_gate mediator{trail};
    device_registry registry{0x1234U};

    const auto read = registry.read<rights_set{right::read}, operator_principal>(
        weakened, allow_observe(), mediator);
    expect(read.has_value() && *read == 0x1234U, "a read-only capability reads");

    const auto write = registry.write<rights_set{right::read}, operator_principal>(
        weakened, allow_modify(), mediator, 0x5678U);
    expect(!write.has_value() && write.error() == auth_error::insufficient_rights,
           "the same capability cannot write, even with a policy proof");

    const auto real_write = registry.write<rights_set::all(), operator_principal>(
        strong, allow_modify(), mediator, 0x5678U);
    expect(real_write.has_value(), "a write capability writes");

    // -- 6. Revocation ------------------------------------------------------
    step("6. revocation");
    static_cast<void>(revoke_all<resource_for_t<resource_kind::devices>>());

    const auto stale = registry.read<rights_set::all(), operator_principal>(strong, allow_observe(),
                                                                           mediator);
    expect(!stale.has_value() && stale.error() == auth_error::capability_revoked,
           "a capability minted before the revocation is refused");

    auto fresh = root.mint<rights_set::all()>();
    const auto after_revocation = registry.read<rights_set::all(), operator_principal>(
        fresh, allow_observe(), mediator);
    expect(after_revocation.has_value(), "a capability minted after it works");

    // -- 7. The record ------------------------------------------------------
    step("7. the audit trail");
    std::printf("   recorded %llu, dropped %llu\n",
                static_cast<unsigned long long>(trail.recorded()),
                static_cast<unsigned long long>(trail.dropped()));

    std::array<audit_event, audit_trail::capacity> records{};
    const std::size_t count = trail.snapshot(records);
    for (std::size_t index = 0; index < count; ++index) {
        std::printf("   %s\n", std::format("{}", records[index]).c_str());
    }

    std::size_t denials = 0;
    for (std::size_t index = 0; index < count; ++index) {
        if (is_denial(records[index].outcome)) {
            ++denials;
        }
    }
    expect(denials == 2, "both refusals are on the record, and only those");

    std::printf("\n%s: %d step(s) failed\n", failures == 0 ? "PASSED" : "FAILED", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
