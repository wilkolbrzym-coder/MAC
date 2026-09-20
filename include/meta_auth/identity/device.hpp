// ===========================================================================
//  meta-auth-core -- devices and attestation.
//
//  A device proves what it is by proving knowledge of a key that the policy
//  already trusts. Concretely, and in this order:
//
//    1. The device describes itself: manufacturer, model, firmware, serial.
//       That description is encoded canonically and hashed. The digest is the
//       device's identity.
//    2. The device MACs the digest with its enrolment key. The result is the
//       attestation.
//    3. A verifier recomputes the digest from the descriptor it was given,
//       checks the MAC with the key it holds, and checks that the digest is in
//       its trust store.
//
//  Two design decisions carry the weight:
//
//    * **The trust store is a compile-time value.** `trust_store<anchors...>`
//      takes digests as template arguments, so a device that is not in the
//      store cannot be trusted no matter what it sends, and adding a device is
//      a source change rather than a configuration change. A trust anchor that
//      can be edited on the device is not an anchor.
//    * **The encoding is length-prefixed.** Concatenating fields would make
//      ("ab", "c") and ("a", "bc") the same descriptor, which is a collision
//      an attacker chooses. The encoding is specified and tested rather than
//      left to whatever the field order happens to produce.
//
//  Scope: this is the mechanism, not a key-management system. Where the
//  enrolment key comes from, how it is provisioned and how it is rotated are
//  the caller's problem; the library's job is to make the verification
//  unfoolable once the key is in hand.
// ===========================================================================
#ifndef META_AUTH_IDENTITY_DEVICE_HPP
#define META_AUTH_IDENTITY_DEVICE_HPP

#include "meta_auth/config.hpp"
#include "meta_auth/core/contract.hpp"
#include "meta_auth/core/error.hpp"
#include "meta_auth/core/fixed_string.hpp"
#include "meta_auth/crypto/constant_time.hpp"
#include "meta_auth/crypto/hmac.hpp"
#include "meta_auth/crypto/secure_erase.hpp"
#include "meta_auth/crypto/sha256.hpp"
#include "meta_auth/identity/principal.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace meta_auth {

// ---------------------------------------------------------------------------
// Device descriptors
// ---------------------------------------------------------------------------

/// The largest encoded descriptor this library accepts.
///
/// A fixed bound because the encoding is written into a stack buffer: the
/// alternative is an allocation on the attestation path, which is the path a
/// hostile device can drive.
inline constexpr std::size_t max_descriptor_bytes = 512;

/// What a device says it is.
///
/// The fields are views into storage the caller owns; a descriptor is a
/// *reference* to a description, not a container for one, so verifying an
/// attestation allocates nothing.
struct device_descriptor {
    std::string_view manufacturer{};
    std::string_view model{};
    std::string_view serial{};
    std::uint32_t firmware = 0;

    /// Canonical encoding: every field length-prefixed, the firmware fixed
    /// width.
    ///
    /// The length prefixes are the point. Without them, `("ab", "c")` and
    /// `("a", "bc")` encode identically, so two different devices would share
    /// an identity -- and an attacker gets to choose which pair collides. Each
    /// text field is a 4-byte big-endian length followed by its bytes; the
    /// firmware is a 4-byte big-endian integer. The encoding is a total
    /// function of the descriptor, so a verifier and a device that agree on
    /// the descriptor agree on the digest.
    ///
    /// Returns the number of bytes written, or `buffer_too_small` when the
    /// descriptor does not fit in `max_descriptor_bytes`.
    [[nodiscard]] constexpr auto encode(std::span<std::byte> buffer) const noexcept
        -> result<std::size_t> {
        std::size_t written = 0;

        const auto write_u32 = [&buffer, &written](std::uint32_t value) -> bool {
            if (buffer.size() - written < 4) {
                return false;
            }
            for (std::size_t index = 0; index < 4; ++index) {
                const auto shift = static_cast<unsigned>(24U - 8U * index);
                buffer[written + index] = static_cast<std::byte>((value >> shift) & 0xFFU);
            }
            written += 4;
            return true;
        };

        const auto write_text = [&buffer, &written, &write_u32](std::string_view text) -> bool {
            if (text.size() > 0xFFFFFFFFULL) {
                return false;
            }
            if (!write_u32(static_cast<std::uint32_t>(text.size()))) {
                return false;
            }
            if (buffer.size() - written < text.size()) {
                return false;
            }
            for (const char character : text) {
                buffer[written] = static_cast<std::byte>(static_cast<unsigned char>(character));
                ++written;
            }
            return true;
        };

        if (!write_text(manufacturer) || !write_text(model) || !write_text(serial)
            || !write_u32(firmware)) {
            return failure(auth_error::buffer_too_small);
        }
        return written;
    }

    /// The identity of the device: the digest of its canonical encoding.
    ///
    /// Deliberately not constexpr-comparable with a `constexpr` variable: the
    /// encoding needs a buffer, and a stack buffer in a constexpr function is
    /// fine, so this *is* constexpr and is used in `static_assert`s to build
    /// trust anchors from descriptors.
    [[nodiscard]] constexpr auto digest() const -> crypto::sha256_digest {
        std::array<std::byte, max_descriptor_bytes> buffer{};
        const auto encoded = encode(buffer);
        META_AUTH_ASSERT(encoded.has_value());
        return crypto::sha256(std::span<const std::byte>{buffer.data(), *encoded});
    }

    friend constexpr auto operator==(const device_descriptor&, const device_descriptor&) noexcept
        -> bool = default;
};

// ---------------------------------------------------------------------------
// Trust anchors
// ---------------------------------------------------------------------------

/// The set of device identities a verifier trusts, fixed at compile time.
///
/// The store is the reason a device cannot talk its way into being trusted: it
/// is a value in the binary, not a value on the wire, and a digest that is not
/// in it cannot be added at run time because there is no code path that adds
/// anything. Enrolling a device means changing this type and rebuilding, which
/// is the correct amount of friction for a trust decision.
template <crypto::sha256_digest... Anchors>
class trust_store {
public:
    static constexpr std::size_t size = sizeof...(Anchors);

    /// True when the digest is one of the anchors.
    [[nodiscard]] static constexpr auto contains(const crypto::sha256_digest& digest) noexcept
        -> bool {
        return ((Anchors == digest) || ...);
    }

    /// The index of the anchor, or `size` when it is not present.
    [[nodiscard]] static constexpr auto index_of(const crypto::sha256_digest& digest) noexcept
        -> std::size_t {
        std::size_t index = 0;
        std::size_t found = size;
        const std::array<crypto::sha256_digest, size> anchors{Anchors...};
        for (const auto& anchor : anchors) {
            if (anchor == digest) {
                found = index;
                break;
            }
            ++index;
        }
        return found;
    }

    /// The anchors themselves, for diagnostics and for a policy that names
    /// them.
    [[nodiscard]] static constexpr auto anchors() noexcept
        -> std::array<crypto::sha256_digest, size> {
        return {Anchors...};
    }
};

/// An empty store is a valid type and a useful one: it is what a build has
/// before any device is enrolled, and it trusts nothing.
using empty_trust_store = trust_store<>;

static_assert(empty_trust_store::size == 0);
static_assert(!empty_trust_store::contains(crypto::sha256_of("anything")));

// ---------------------------------------------------------------------------
// Device keys
// ---------------------------------------------------------------------------

/// The symmetric key a device uses to attest.
///
/// A `secret_buffer` underneath, so the key material is erased when the object
/// dies and cannot be copied by accident. The type is what the library puts
/// between a key and the code that uses it; where the bytes come from is the
/// caller's business.
class device_key {
public:
    static constexpr std::size_t key_size = 32;

    /// Adopt `key_size` bytes as a device key.
    ///
    /// Rejects the wrong length and the all-zero key. The second check is not
    /// decoration: a zero key is what a misconfigured keystore returns, and a
    /// device that attests under a key everybody knows is worse than a device
    /// that fails to attest, because the failure is silent.
    [[nodiscard]] static auto from_bytes(std::span<const std::byte> material) -> result<device_key> {
        if (material.size() != key_size) {
            return failure(auth_error::key_material_invalid);
        }
        if (crypto::constant_time_is_zero(material)) {
            return failure(auth_error::key_material_invalid);
        }
        device_key key;
        if (!key.material_.assign(material)) {
            return failure(auth_error::key_material_invalid);
        }
        return key;
    }

    /// A key derived from a passphrase-like input, for tests and examples.
    ///
    /// Public and clearly named so that it cannot be mistaken for key
    /// derivation fit for production: it is a hash of the input with a fixed
    /// context string, which is a deterministic way to write a test down, not
    /// a KDF.
    [[nodiscard]] static auto derive_for_testing(std::string_view seed) -> device_key {
        crypto::sha256_hasher hasher;
        hasher.update("meta-auth-core/test-key/1");
        hasher.update(seed);
        const auto digest = hasher.finish();

        device_key key;
        static_cast<void>(key.material_.assign(digest.span()));
        return key;
    }

    device_key(const device_key&) = delete;
    auto operator=(const device_key&) -> device_key& = delete;
    device_key(device_key&&) noexcept = default;
    auto operator=(device_key&&) noexcept -> device_key& = default;
    ~device_key() = default;

    [[nodiscard]] auto bytes() const noexcept -> std::span<const std::byte> {
        return material_.bytes();
    }

private:
    device_key() = default;

    crypto::secret_buffer<key_size> material_{};
};

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

/// A device's claim about itself, bound with its key.
struct attestation {
    /// The identity the device claims.
    crypto::sha256_digest device_digest{};

    /// The MAC over the device digest, under the enrolment key.
    crypto::sha256_digest mac{};

    friend constexpr auto operator==(const attestation&, const attestation&) noexcept
        -> bool = default;
};

/// Produce an attestation. Runs on the device.
[[nodiscard]] inline auto attest(const device_descriptor& descriptor, const device_key& key)
    -> attestation {
    const crypto::sha256_digest digest = descriptor.digest();
    const crypto::sha256_digest mac = crypto::hmac_sha256(key.bytes(), digest.span());
    return attestation{digest, mac};
}

/// Verify an attestation against a descriptor and a key.
///
/// The order of the checks is part of the design: the descriptor is re-hashed
/// and compared first, so that a device cannot claim one identity while
/// describing itself as another; then the MAC, compared in constant time, so
/// that the verification does not leak how much of a forged tag was correct.
/// Each failure maps to a distinct error code, because "the descriptor does not
/// match", "the key does not match" and "the device is not enrolled" call for
/// different responses -- the last is an enrolment question, the others are
/// incidents.
[[nodiscard]] inline auto verify_attestation(const attestation& claimed,
                                             const device_descriptor& descriptor,
                                             const device_key& key) noexcept -> status {
    const crypto::sha256_digest recomputed = descriptor.digest();

    if (!crypto::constant_time_equal(recomputed.span(), claimed.device_digest.span())) {
        return failure(auth_error::attestation_failed);
    }

    if (!crypto::verify_hmac(key.bytes(), recomputed.span(), claimed.mac)) {
        return failure(auth_error::credential_rejected);
    }

    return success();
}

/// Verify an attestation and check the claimed identity against a trust store.
///
/// The store is a template argument, so this is a compile-time decision about
/// *which* devices are trusted combined with a run-time decision about whether
/// this particular attestation is genuine.
template <typename Store>
[[nodiscard]] inline auto verify_attestation_against(const attestation& claimed,
                                                     const device_descriptor& descriptor,
                                                     const device_key& key) noexcept -> status {
    META_AUTH_TRY_VOID(verify_attestation(claimed, descriptor, key));

    if (!Store::contains(claimed.device_digest)) {
        return failure(auth_error::trust_anchor_unknown);
    }
    return success();
}

} // namespace meta_auth

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
template <>
struct std::formatter<meta_auth::device_descriptor, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(const meta_auth::device_descriptor& descriptor,
                std::format_context& context) const {
        const auto digest = descriptor.digest();
        const auto text = digest.hex();
        return std::format_to(context.out(), "{}/{}/{}@fw{} [{}]", descriptor.manufacturer,
                              descriptor.model, descriptor.serial, descriptor.firmware,
                              text.view());
    }
};

#endif // META_AUTH_IDENTITY_DEVICE_HPP
