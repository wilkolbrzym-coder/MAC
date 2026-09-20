// ===========================================================================
//  Tests of principals, devices and attestation.
//
//  The attestation tests are written as an attacker would approach them: for
//  each of the three things a verifier checks -- the descriptor, the MAC and
//  the trust store -- there is a case that presents a valid-looking claim and
//  violates exactly that one. A suite that only tested the happy path would
//  pass for a verifier that returned success unconditionally.
//
//  The trust store is exercised as a *compile-time* value, which is the whole
//  point of it: the anchors are `static_assert`ed to be present, and a device
//  that is not in the store cannot be added at run time because there is no
//  code path that adds anything.
// ===========================================================================
#include "meta_auth/identity/device.hpp"
#include "meta_auth/identity/principal.hpp"
#include "test_framework.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using meta_auth::device_descriptor;
using meta_auth::device_key;
using meta_auth::principal_kind;
using meta_auth::trust_store;

namespace {

/// A descriptor for a device the policy will trust. Declared at namespace
/// scope so that its digest can be a template argument.
inline constexpr device_descriptor known_device{
    .manufacturer = "Acme Instruments",
    .model = "Thermo-1",
    .serial = "SN-0001",
    .firmware = 0x0001'0000U,
};

inline constexpr meta_auth::crypto::sha256_digest known_digest = known_device.digest();

/// A second device, enrolled as well, so that "the store has more than one
/// entry" is exercised.
inline constexpr device_descriptor second_device{
    .manufacturer = "Acme Instruments",
    .model = "Thermo-2",
    .serial = "SN-0002",
    .firmware = 0x0002'0000U,
};

inline constexpr meta_auth::crypto::sha256_digest second_digest = second_device.digest();

using test_store = trust_store<known_digest, second_digest>;

inline constexpr std::string_view enrolment_secret = "enrolment-secret-for-sn-0001";

/// The key a device would hold. Derived rather than hard-coded so that the
/// test does not contain a key that looks like production material.
[[nodiscard]] auto device_enrolment_key() -> device_key {
    return device_key::derive_for_testing(enrolment_secret);
}

} // namespace

// ---------------------------------------------------------------------------
// Compile-time properties
// ---------------------------------------------------------------------------

/// The trust store is a compile-time value, and membership is a constant
/// expression. That is what makes "this device is trusted" a property of the
/// binary rather than of its configuration.
static_assert(test_store::size == 2);
static_assert(test_store::contains(known_digest));
static_assert(test_store::contains(second_digest));
static_assert(!test_store::contains(meta_auth::crypto::sha256_of("not-a-device")));
static_assert(test_store::index_of(known_digest) == 0);
static_assert(test_store::index_of(second_digest) == 1);
static_assert(test_store::index_of(meta_auth::crypto::sha256_of("not-a-device")) == 2);

/// A descriptor's digest is a pure function of its fields.
static_assert(known_device.digest() == known_digest);
static_assert(known_device.digest() != second_device.digest());

/// Principals: the kind is part of the identity.
static_assert(meta_auth::principal_name<meta_auth::admin_principal>() == "admin");
static_assert(meta_auth::admin_principal::kind == principal_kind::user);
static_assert(meta_auth::service_principal::kind == principal_kind::service);

// ---------------------------------------------------------------------------
// Descriptor encoding
// ---------------------------------------------------------------------------

/// The encoding is length-prefixed, and this is the case that makes the prefix
/// necessary: without it, ("ab","c") and ("a","bc") would encode identically
/// and two different devices would share an identity.
META_AUTH_TEST("device_descriptor", "length_prefixing_prevents_field_boundary_collisions") {
    constexpr device_descriptor left{.manufacturer = "ab", .model = "c", .serial = "",
                                     .firmware = 0};
    constexpr device_descriptor right{.manufacturer = "a", .model = "bc", .serial = "",
                                      .firmware = 0};

    META_AUTH_CHECK_NE(left.digest(), right.digest());

    std::array<std::byte, meta_auth::max_descriptor_bytes> left_bytes{};
    std::array<std::byte, meta_auth::max_descriptor_bytes> right_bytes{};
    const auto left_encoded = left.encode(left_bytes);
    const auto right_encoded = right.encode(right_bytes);
    META_AUTH_REQUIRE(left_encoded.has_value());
    META_AUTH_REQUIRE(right_encoded.has_value());

    META_AUTH_CHECK_EQ(*left_encoded, *right_encoded);
    const auto left_view = std::span<const std::byte>{left_bytes.data(), *left_encoded};
    const auto right_view = std::span<const std::byte>{right_bytes.data(), *right_encoded};
    META_AUTH_CHECK(!meta_auth::crypto::constant_time_equal(left_view, right_view));
}

META_AUTH_TEST("device_descriptor", "encoding_is_deterministic_and_matches_the_digest") {
    std::array<std::byte, meta_auth::max_descriptor_bytes> first{};
    std::array<std::byte, meta_auth::max_descriptor_bytes> second{};

    const auto first_size = known_device.encode(first);
    const auto second_size = known_device.encode(second);
    META_AUTH_REQUIRE(first_size.has_value());
    META_AUTH_REQUIRE(second_size.has_value());
    META_AUTH_CHECK_EQ(*first_size, *second_size);

    const auto first_view = std::span<const std::byte>{first.data(), *first_size};
    const auto second_view = std::span<const std::byte>{second.data(), *second_size};
    META_AUTH_CHECK(meta_auth::crypto::constant_time_equal(first_view, second_view));
    META_AUTH_CHECK_EQ(meta_auth::crypto::sha256(first_view), known_digest);
}

META_AUTH_TEST("device_descriptor", "every_field_changes_the_digest") {
    // A descriptor whose digest did not depend on one of its fields would make
    // that field unauthenticated: a device could claim any firmware version
    // and still verify.
    auto changed = known_device;
    changed.manufacturer = "Other Instruments";
    META_AUTH_CHECK_NE(changed.digest(), known_digest);

    changed = known_device;
    changed.model = "Thermo-3";
    META_AUTH_CHECK_NE(changed.digest(), known_digest);

    changed = known_device;
    changed.serial = "SN-0003";
    META_AUTH_CHECK_NE(changed.digest(), known_digest);

    changed = known_device;
    changed.firmware = 0x0001'0001U;
    META_AUTH_CHECK_NE(changed.digest(), known_digest);
}

META_AUTH_TEST("device_descriptor", "an_oversized_descriptor_is_refused") {
    // The refusal is explicit rather than a truncation: a truncated encoding
    // is the encoding of a *different* descriptor, which is a collision.
    std::string huge(meta_auth::max_descriptor_bytes, 'x');
    device_descriptor oversized{.manufacturer = huge, .model = "", .serial = "", .firmware = 0};

    std::array<std::byte, meta_auth::max_descriptor_bytes> buffer{};
    const auto encoded = oversized.encode(buffer);
    META_AUTH_REQUIRE(!encoded.has_value());
    META_AUTH_CHECK_EQ(encoded.error(), meta_auth::auth_error::buffer_too_small);
}

META_AUTH_TEST("device_descriptor", "a_descriptor_renders_with_its_digest") {
    const std::string rendered = std::format("{}", known_device);
    META_AUTH_CHECK(rendered.find("Acme Instruments") != std::string::npos);
    META_AUTH_CHECK(rendered.find("SN-0001") != std::string::npos);
    META_AUTH_CHECK(rendered.find(known_digest.hex().view()) != std::string::npos);
}

// ---------------------------------------------------------------------------
// Device keys
// ---------------------------------------------------------------------------
META_AUTH_TEST("device_key", "a_key_of_the_wrong_length_is_refused") {
    const std::vector<std::byte> short_material(16, std::byte{0x11});
    const auto short_key = device_key::from_bytes(short_material);
    META_AUTH_REQUIRE(!short_key.has_value());
    META_AUTH_CHECK_EQ(short_key.error(), meta_auth::auth_error::key_material_invalid);

    const std::vector<std::byte> long_material(64, std::byte{0x11});
    META_AUTH_CHECK_EQ(device_key::from_bytes(long_material).error(),
                       meta_auth::auth_error::key_material_invalid);
    META_AUTH_CHECK_EQ(device_key::from_bytes({}).error(),
                       meta_auth::auth_error::key_material_invalid);
}

META_AUTH_TEST("device_key", "an_all_zero_key_is_refused") {
    // A zero key is what a misconfigured keystore returns. A device attesting
    // under a key everybody knows is worse than one that fails to attest,
    // because the failure is silent.
    const std::vector<std::byte> zeroes(device_key::key_size, std::byte{0});
    const auto key = device_key::from_bytes(zeroes);
    META_AUTH_REQUIRE(!key.has_value());
    META_AUTH_CHECK_EQ(key.error(), meta_auth::auth_error::key_material_invalid);
}

META_AUTH_TEST("device_key", "a_valid_key_is_adopted_unchanged") {
    std::vector<std::byte> material(device_key::key_size);
    for (std::size_t index = 0; index < material.size(); ++index) {
        material[index] = static_cast<std::byte>(index + 1);
    }

    const auto key = device_key::from_bytes(material);
    META_AUTH_REQUIRE(key.has_value());
    META_AUTH_CHECK_EQ(key->bytes().size(), device_key::key_size);
    META_AUTH_CHECK(meta_auth::crypto::constant_time_equal(key->bytes(), material));
}

META_AUTH_TEST("device_key", "derivation_is_deterministic_and_seed_dependent") {
    const auto first = device_key::derive_for_testing("seed-a");
    const auto second = device_key::derive_for_testing("seed-a");
    const auto other = device_key::derive_for_testing("seed-b");

    META_AUTH_CHECK(meta_auth::crypto::constant_time_equal(first.bytes(), second.bytes()));
    META_AUTH_CHECK(!meta_auth::crypto::constant_time_equal(first.bytes(), other.bytes()));
}

META_AUTH_TEST("device_key", "a_moved_key_leaves_the_source_empty") {
    auto original = device_key::derive_for_testing("move-me");
    const auto material = std::vector<std::byte>{original.bytes().begin(), original.bytes().end()};

    auto moved = std::move(original);

    META_AUTH_CHECK(meta_auth::crypto::constant_time_equal(moved.bytes(), material));
    // The source holds nothing rather than a stale copy the destructor would
    // not reach.
    META_AUTH_CHECK(original.bytes().empty());
}

// ---------------------------------------------------------------------------
// Attestation: the happy path and each way of failing it
// ---------------------------------------------------------------------------
META_AUTH_TEST("attestation", "a_genuine_attestation_verifies") {
    const auto key = device_enrolment_key();
    const auto claimed = meta_auth::attest(known_device, key);

    META_AUTH_CHECK_EQ(claimed.device_digest, known_digest);
    META_AUTH_CHECK(meta_auth::verify_attestation(claimed, known_device, key).has_value());
    META_AUTH_CHECK(meta_auth::verify_attestation_against<test_store>(claimed, known_device, key)
                        .has_value());
}

META_AUTH_TEST("attestation", "a_descriptor_that_does_not_match_its_claimed_digest_is_refused") {
    // The attack: claim a trusted device's identity, then describe yourself as
    // something else. The verifier re-hashes the descriptor it was given, so
    // the claim and the description cannot disagree.
    const auto key = device_enrolment_key();
    const auto claimed = meta_auth::attest(known_device, key);

    auto lying = known_device;
    lying.firmware = 0xDEAD'BEEFU;

    const auto outcome = meta_auth::verify_attestation(claimed, lying, key);
    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::attestation_failed);
}

META_AUTH_TEST("attestation", "a_mac_under_the_wrong_key_is_refused") {
    const auto claimed = meta_auth::attest(known_device, device_enrolment_key());
    const auto other_key = device_key::derive_for_testing("a-different-enrolment-secret");

    const auto outcome = meta_auth::verify_attestation(claimed, known_device, other_key);
    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::credential_rejected);
}

META_AUTH_TEST("attestation", "every_single_bit_of_the_mac_matters") {
    // A verifier that compared a prefix would accept some of these. This walks
    // all 256 single-bit changes, which is the smallest exhaustive statement
    // that the MAC is checked in full.
    const auto key = device_enrolment_key();
    const auto genuine = meta_auth::attest(known_device, key);

    for (std::size_t byte_index = 0; byte_index < genuine.mac.bytes.size(); ++byte_index) {
        for (unsigned bit = 0; bit < 8U; ++bit) {
            auto forged = genuine;
            forged.mac.bytes[byte_index] = static_cast<std::byte>(
                std::to_integer<std::uint8_t>(forged.mac.bytes[byte_index]) ^ (1U << bit));
            const auto outcome = meta_auth::verify_attestation(forged, known_device, key);
            META_AUTH_REQUIRE(!outcome.has_value());
            META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::credential_rejected);
        }
    }
}

META_AUTH_TEST("attestation", "a_genuine_device_outside_the_trust_store_is_refused") {
    // The device is real, the key is right, the MAC verifies -- and it is
    // still rejected, because trust is a compile-time decision about which
    // devices exist rather than a run-time conclusion about which ones can
    // prove knowledge of a key.
    using narrow_store = trust_store<known_digest>;

    const auto second_key = device_key::derive_for_testing("second-device-secret");
    const auto claimed = meta_auth::attest(second_device, second_key);

    // It verifies without the store...
    META_AUTH_CHECK(meta_auth::verify_attestation(claimed, second_device, second_key).has_value());
    // ...and is refused by a store that does not list it.
    const auto outcome =
        meta_auth::verify_attestation_against<narrow_store>(claimed, second_device, second_key);
    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::trust_anchor_unknown);
}

META_AUTH_TEST("attestation", "an_empty_store_trusts_nothing") {
    const auto key = device_enrolment_key();
    const auto claimed = meta_auth::attest(known_device, key);

    const auto outcome =
        meta_auth::verify_attestation_against<meta_auth::empty_trust_store>(claimed, known_device,
                                                                            key);
    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::trust_anchor_unknown);
}

META_AUTH_TEST("attestation", "verification_does_not_modify_its_inputs") {
    // The verifier takes its inputs by const reference and must leave them
    // usable: a device descriptor is reused across many verifications.
    const auto key = device_enrolment_key();
    const auto claimed = meta_auth::attest(known_device, key);
    const auto digest_before = known_digest;
    const auto claimed_before = claimed;

    static_cast<void>(meta_auth::verify_attestation(claimed, known_device, key));

    META_AUTH_CHECK_EQ(known_device.digest(), digest_before);
    META_AUTH_CHECK_EQ(claimed, claimed_before);
}
