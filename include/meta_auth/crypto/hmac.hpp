// ===========================================================================
//  meta-auth-core -- HMAC-SHA256.
//
//  A digest says what a value is; a MAC says who vouched for it. The
//  difference is the key, and it is what turns "this is the descriptor of a
//  device" into "this descriptor was produced by a device that holds the
//  enrolment key". Every binding in the identity and capability layers that an
//  attacker could otherwise recompute is a MAC here.
//
//  The construction is RFC 2104 with SHA-256, and it is validated against the
//  RFC 4231 vectors -- including the two that matter and are usually skipped:
//  a key longer than the block size (which must be hashed first, not
//  truncated) and a message longer than the block size.
//
//  Keys are handled as `std::span<const std::byte>` and are never copied into
//  the message. The hasher keeps the two padded key blocks, which is why it
//  offers `destroy()`: the caller who owns the key material is the one who
//  knows when the operation is over.
// ===========================================================================
#ifndef META_AUTH_CRYPTO_HMAC_HPP
#define META_AUTH_CRYPTO_HMAC_HPP

#include "meta_auth/config.hpp"
#include "meta_auth/crypto/constant_time.hpp"
#include "meta_auth/crypto/secure_erase.hpp"
#include "meta_auth/crypto/sha256.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace meta_auth::crypto {

/// Streaming HMAC-SHA256.
///
/// The key is absorbed in the constructor, so a caller cannot accidentally
/// start absorbing a message under a key that has not been set yet.
class hmac_sha256_hasher {
public:
    using digest_type = sha256_digest;

    static constexpr std::size_t block_size = sha256_hasher::block_size;

    explicit constexpr hmac_sha256_hasher(std::span<const std::byte> key) noexcept {
        std::array<std::byte, block_size> padded_key{};

        if (key.size() > block_size) {
            // RFC 2104: a key longer than the block is replaced by its digest,
            // not truncated. Truncating would make two different keys produce
            // the same MAC, which is a collision an attacker can choose.
            const sha256_digest hashed = sha256(key);
            for (std::size_t index = 0; index < hashed.bytes.size(); ++index) {
                padded_key[index] = hashed.bytes[index];
            }
        } else {
            for (std::size_t index = 0; index < key.size(); ++index) {
                padded_key[index] = key[index];
            }
        }

        inner_pad_.fill(std::byte{0});
        outer_pad_.fill(std::byte{0});
        constexpr auto pad_byte = std::byte{0x36};
        constexpr auto outer_byte = std::byte{0x5C};
        for (std::size_t index = 0; index < block_size; ++index) {
            inner_pad_[index] = static_cast<std::byte>(
                std::to_integer<std::uint8_t>(padded_key[index])
                ^ std::to_integer<std::uint8_t>(pad_byte));
            outer_pad_[index] = static_cast<std::byte>(
                std::to_integer<std::uint8_t>(padded_key[index])
                ^ std::to_integer<std::uint8_t>(outer_byte));
        }

        // The padded key is a derived value, but it is derived *from* the key:
        // erasing it costs nothing and removes a copy of key material from the
        // stack frame that the caller cannot reach. Guarded because erasure is
        // a run-time operation.
        if !consteval {
            secure_erase(padded_key);
        }

        inner_.reset();
        inner_.update(inner_pad_);
    }

    hmac_sha256_hasher(const hmac_sha256_hasher&) = delete;
    auto operator=(const hmac_sha256_hasher&) -> hmac_sha256_hasher& = delete;
    hmac_sha256_hasher(hmac_sha256_hasher&&) = delete;
    auto operator=(hmac_sha256_hasher&&) -> hmac_sha256_hasher& = delete;

    /// Erases the key material at run time and does nothing during constant
    /// evaluation, which is what keeps this class a literal type.
    constexpr ~hmac_sha256_hasher() {
        if !consteval {
            destroy();
        }
    }

    constexpr auto update(std::span<const std::byte> data) noexcept -> hmac_sha256_hasher& {
        inner_.update(data);
        return *this;
    }

    constexpr auto update(std::string_view text) noexcept -> hmac_sha256_hasher& {
        inner_.update(text);
        return *this;
    }

    /// Complete the MAC. The hasher is left unusable for further input until
    /// `destroy()` or re-construction, because the inner digest has been
    /// consumed; the destructor erases the key material either way.
    [[nodiscard]] constexpr auto finish() noexcept -> sha256_digest {
        const sha256_digest inner_digest = inner_.finish();

        sha256_hasher outer;
        outer.reset();
        outer.update(outer_pad_);
        outer.update(std::span<const std::byte>{inner_digest.bytes.data(),
                                                inner_digest.bytes.size()});
        return outer.finish();
    }

    /// Erase the key material this hasher holds. Called by the destructor;
    /// callable earlier by a caller that wants the window to be shorter.
    /// Not constexpr: erasure is an operation on run-time storage.
    void destroy() noexcept {
        secure_erase(inner_pad_);
        secure_erase(outer_pad_);
    }

private:
    std::array<std::byte, block_size> inner_pad_{};
    std::array<std::byte, block_size> outer_pad_{};
    sha256_hasher inner_{};
};

/// One-shot MAC.
[[nodiscard]] constexpr auto hmac_sha256(std::span<const std::byte> key,
                                         std::span<const std::byte> message) noexcept
    -> sha256_digest {
    // The hasher's destructor is not constexpr (it erases the key material),
    // so the one-shot form builds the pads itself and never leaves the key in
    // a long-lived object.
    std::array<std::byte, sha256_hasher::block_size> padded_key{};

    if (key.size() > sha256_hasher::block_size) {
        const sha256_digest hashed = sha256(key);
        for (std::size_t index = 0; index < hashed.bytes.size(); ++index) {
            padded_key[index] = hashed.bytes[index];
        }
    } else {
        for (std::size_t index = 0; index < key.size(); ++index) {
            padded_key[index] = key[index];
        }
    }

    std::array<std::byte, sha256_hasher::block_size> inner_pad{};
    std::array<std::byte, sha256_hasher::block_size> outer_pad{};
    for (std::size_t index = 0; index < sha256_hasher::block_size; ++index) {
        const auto key_byte = std::to_integer<std::uint8_t>(padded_key[index]);
        inner_pad[index] = static_cast<std::byte>(key_byte ^ 0x36U);
        outer_pad[index] = static_cast<std::byte>(key_byte ^ 0x5CU);
    }

    sha256_hasher inner;
    inner.reset();
    inner.update(inner_pad);
    inner.update(message);
    const sha256_digest inner_digest = inner.finish();

    sha256_hasher outer;
    outer.reset();
    outer.update(outer_pad);
    outer.update(std::span<const std::byte>{inner_digest.bytes.data(), inner_digest.bytes.size()});
    return outer.finish();
}

namespace detail {

/// Text as bytes, without `std::as_bytes`.
///
/// The standard conversion needs a `reinterpret_cast`, which constant
/// evaluation forbids, and the RFC 4231 vectors in the test suite are checked
/// by `static_assert`. Allocation during constant evaluation is permitted
/// since C++20, so the copy is legal in both contexts.
[[nodiscard]] constexpr auto to_bytes(std::string_view text) -> std::vector<std::byte> {
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const char character : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
    }
    return bytes;
}

} // namespace detail

/// One-shot MAC over textual input, for the common case where the message is a
/// descriptor rendered as text.
[[nodiscard]] constexpr auto hmac_sha256_of(std::string_view key,
                                            std::string_view message) -> sha256_digest {
    const std::vector<std::byte> key_bytes = detail::to_bytes(key);
    const std::vector<std::byte> message_bytes = detail::to_bytes(message);
    return hmac_sha256(key_bytes, message_bytes);
}

/// Verify a MAC in constant time.
///
/// This is the function the capability layer calls. Comparing MACs with `==`
/// would leak, byte by byte, how much of a forged tag was correct, which is
/// the difference between a 2^256 search and 256 guesses.
[[nodiscard]] constexpr auto verify_hmac(std::span<const std::byte> key,
                                         std::span<const std::byte> message,
                                         const sha256_digest& expected) noexcept -> bool {
    const sha256_digest computed = hmac_sha256(key, message);
    return constant_time_equal(computed.span(), expected.span());
}

} // namespace meta_auth::crypto

#endif // META_AUTH_CRYPTO_HMAC_HPP
