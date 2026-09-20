// ===========================================================================
//  meta-auth-core -- SHA-256, evaluated while compiling.
//
//  The digest is what makes a device descriptor, a trust anchor and an
//  attestation comparable: a device proves what it is by proving knowledge of
//  values that hash to the digest the policy was compiled against. Doing that
//  computation at compile time is not a performance trick, it is the point --
//  a trust anchor that is baked into the binary cannot be replaced by editing
//  a file on the device.
//
//  Correctness is established the way a cryptographic primitive has to be:
//  against the published vectors, asserted at compile time. FIPS 180-4's own
//  examples are `static_assert`s in tests/crypto/test_sha256.cpp, so a change
//  that breaks the algorithm fails the build rather than a run.
//
//  Scope, stated plainly: this is a correct implementation of SHA-256, not a
//  hardened one. It is not constant time (it does not need to be: it is applied
//  to public data, and a MAC over a secret uses the keyed construction below),
//  it does not defend against cache-timing attacks on the message schedule,
//  and it is not a substitute for a vetted cryptographic library in a system
//  that has one. It exists because a capability model needs a binding, and a
//  binding needs a hash.
// ===========================================================================
#ifndef META_AUTH_CRYPTO_SHA256_HPP
#define META_AUTH_CRYPTO_SHA256_HPP

#include "meta_auth/config.hpp"
#include "meta_auth/core/error.hpp"
#include "meta_auth/core/fixed_string.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string_view>

// ---------------------------------------------------------------------------
// Bounds-analysis suppression, optimized builds only, with the evidence
// ---------------------------------------------------------------------------
// GCC 16.0.1's value-range analysis reports two out-of-bounds accesses in this
// file when it is inlined at -O3 through HMAC's two hashers, and both are
// wrong:
//
//   * "array subscript [225, ...] is outside array bounds of 'const
//     sha256_digest [1]'" -- an access 225 bytes into a 32-byte digest, in a
//     function that reads four bytes of a fixed-extent four-byte span;
//   * "array subscript 64 is outside array bounds of 'std::array<std::byte,
//     64>'" in the remainder loop, whose condition is `remaining < block_size`.
//
// The suppression is scoped to this file and to optimized builds: `-O0` builds
// keep the diagnostic, and every other file in the library keeps it in every
// build. `-Warray-bounds` is a warning worth having, and giving it up globally
// to accommodate one function would be the wrong trade.
//
// What backs the code instead of the warning is stronger than the warning
// would be: the FIPS 180-4 vectors are `static_assert`s in
// tests/crypto/test_crypto.cpp, the padding boundaries (55, 56, 57, 63, 64, 65
// bytes) are tested explicitly, and the whole suite runs under
// AddressSanitizer and UndefinedBehaviorSanitizer in CI, where a real
// out-of-bounds access here would be a hard failure rather than a diagnostic.
#if defined(__GNUC__) && !defined(__clang__) && defined(__OPTIMIZE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#define META_AUTH_SHA256_SUPPRESSED_ARRAY_BOUNDS 1
#endif

namespace meta_auth::crypto {

namespace detail {

[[nodiscard]] constexpr auto rotate_right(std::uint32_t value, unsigned count) noexcept
    -> std::uint32_t {
    return (value >> count) | (value << (32U - count));
}

/// FIPS 180-4, section 4.2.2: the first 32 bits of the fractional parts of the
/// cube roots of the first 64 primes.
inline constexpr std::array<std::uint32_t, 64> sha256_round_constants = {
    0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U, 0x3956C25BU, 0x59F111F1U, 0x923F82A4U,
    0xAB1C5ED5U, 0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U, 0x72BE5D74U, 0x80DEB1FEU,
    0x9BDC06A7U, 0xC19BF174U, 0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU, 0x2DE92C6FU,
    0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU, 0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
    0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U, 0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU,
    0x53380D13U, 0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U, 0xA2BFE8A1U, 0xA81A664BU,
    0xC24B8B70U, 0xC76C51A3U, 0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U, 0x19A4C116U,
    0x1E376C08U, 0x2748774CU, 0x34B0BCB5U, 0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
    0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U, 0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U,
    0xC67178F2U};

/// FIPS 180-4, section 5.3.3: the first 32 bits of the fractional parts of the
/// square roots of the first 8 primes.
inline constexpr std::array<std::uint32_t, 8> sha256_initial_state = {
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U};

[[nodiscard]] constexpr auto choose(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    -> std::uint32_t {
    return (x & y) ^ (~x & z);
}

[[nodiscard]] constexpr auto majority(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    -> std::uint32_t {
    return (x & y) ^ (x & z) ^ (y & z);
}

/// Σ0, the upper-case sigma used on `a` in the round function.
[[nodiscard]] constexpr auto big_sigma0(std::uint32_t value) noexcept -> std::uint32_t {
    return rotate_right(value, 2) ^ rotate_right(value, 13) ^ rotate_right(value, 22);
}

/// Σ1, the upper-case sigma used on `e`.
[[nodiscard]] constexpr auto big_sigma1(std::uint32_t value) noexcept -> std::uint32_t {
    return rotate_right(value, 6) ^ rotate_right(value, 11) ^ rotate_right(value, 25);
}

/// σ0, the lower-case sigma used to extend the message schedule.
[[nodiscard]] constexpr auto small_sigma0(std::uint32_t value) noexcept -> std::uint32_t {
    return rotate_right(value, 7) ^ rotate_right(value, 18) ^ (value >> 3U);
}

/// σ1, the lower-case sigma used to extend the message schedule.
[[nodiscard]] constexpr auto small_sigma1(std::uint32_t value) noexcept -> std::uint32_t {
    return rotate_right(value, 17) ^ rotate_right(value, 19) ^ (value >> 10U);
}

/// Big-endian load of a 32-bit word, spelled out to avoid a reinterpret_cast
/// (which would also make the function unusable in a constant expression).
///
/// The parameter is a fixed-extent span rather than a pointer, so the width is
/// part of the type and every access below is in bounds by construction.
[[nodiscard]] constexpr auto load_big_endian(std::span<const std::byte, 4> data) noexcept
    -> std::uint32_t {
    return (std::to_integer<std::uint32_t>(data[0]) << 24U)
           | (std::to_integer<std::uint32_t>(data[1]) << 16U)
           | (std::to_integer<std::uint32_t>(data[2]) << 8U)
           | std::to_integer<std::uint32_t>(data[3]);
}

constexpr auto store_big_endian(std::uint32_t value, std::span<std::byte, 4> destination) noexcept
    -> void {
    destination[0] = static_cast<std::byte>((value >> 24U) & 0xFFU);
    destination[1] = static_cast<std::byte>((value >> 16U) & 0xFFU);
    destination[2] = static_cast<std::byte>((value >> 8U) & 0xFFU);
    destination[3] = static_cast<std::byte>(value & 0xFFU);
}

} // namespace detail

/// A SHA-256 digest: 32 bytes with a hex rendering.
///
/// Equality is the ordinary comparison, deliberately. A digest is a public
/// value -- it names a device or a policy, and it is written into audit
/// records -- so comparing it in variable time leaks nothing. Where a digest
/// is used as a *tag* that an attacker is trying to forge (a MAC), the
/// comparison is made with `crypto::constant_time_equal` instead, and that
/// difference is visible at the call site.
struct sha256_digest {
    static constexpr std::size_t size = 32;
    using bytes_type = std::array<std::byte, size>;

    bytes_type bytes{};

    [[nodiscard]] constexpr auto data() noexcept -> std::byte* { return bytes.data(); }
    [[nodiscard]] constexpr auto data() const noexcept -> const std::byte* { return bytes.data(); }
    [[nodiscard]] constexpr auto span() const noexcept -> std::span<const std::byte> {
        return bytes;
    }

    /// Lower-case hexadecimal, as a `fixed_string` so that it compares with a
    /// literal in a `static_assert` and needs no allocation anywhere.
    [[nodiscard]] constexpr auto hex() const noexcept -> fixed_string<2 * size + 1> {
        constexpr std::string_view digits = "0123456789abcdef";
        fixed_string<2 * size + 1> text{};
        for (std::size_t index = 0; index < size; ++index) {
            const auto value = std::to_integer<std::uint8_t>(bytes[index]);
            text.data[index * 2] = digits[value >> 4U];
            text.data[index * 2 + 1] = digits[value & 0x0FU];
        }
        text.data[2 * size] = '\0';
        return text;
    }

    /// Parse a hex rendering. Rejects anything that is not exactly 64 hex
    /// digits rather than accepting a prefix: a truncated digest is a digest
    /// of something else, and treating it as valid is how a check becomes a
    /// formality.
    [[nodiscard]] static constexpr auto from_hex(std::string_view text) noexcept
        -> result<sha256_digest> {
        if (text.size() != 2 * size) {
            return failure(auth_error::encoding_invalid);
        }

        sha256_digest digest{};
        for (std::size_t index = 0; index < size; ++index) {
            const auto high = hex_value(text[index * 2]);
            const auto low = hex_value(text[index * 2 + 1]);
            if (high > 0x0FU || low > 0x0FU) {
                return failure(auth_error::encoding_invalid);
            }
            digest.bytes[index] = static_cast<std::byte>((high << 4U) | low);
        }
        return digest;
    }

    friend constexpr auto operator==(const sha256_digest&, const sha256_digest&) noexcept
        -> bool = default;

private:
    /// 0-15 for a hex digit, 16 for anything else, so that the caller's check
    /// is a single comparison rather than a range test per character.
    [[nodiscard]] static constexpr auto hex_value(char character) noexcept -> std::uint8_t {
        if (character >= '0' && character <= '9') {
            return static_cast<std::uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<std::uint8_t>(character - 'a' + 10);
        }
        if (character >= 'A' && character <= 'F') {
            return static_cast<std::uint8_t>(character - 'A' + 10);
        }
        return 16;
    }
};

/// Streaming SHA-256.
///
/// Streaming rather than one-shot because two things in this library need it:
/// HMAC hashes a key and a message under one context, and the attestation of a
/// device descriptor hashes several fields without building a concatenated
/// buffer that would then have to be erased.
class sha256_hasher {
public:
    static constexpr std::size_t block_size = 64;

    constexpr sha256_hasher() noexcept { reset(); }

    constexpr void reset() noexcept {
        state_ = detail::sha256_initial_state;
        buffer_.fill(std::byte{0});
        buffered_ = 0;
        total_bytes_ = 0;
    }

    /// Absorb more data. Returns `*this` so that calls can be chained.
    constexpr auto update(std::span<const std::byte> data) noexcept -> sha256_hasher& {
        total_bytes_ += data.size();

        std::size_t offset = 0;

        // Top up the buffer first: a partial block is only compressed when it
        // is full, which is what makes the streaming result equal the one-shot
        // result.
        if (buffered_ != 0) {
            const std::size_t wanted = block_size - buffered_;
            const std::size_t taken = data.size() < wanted ? data.size() : wanted;
            for (std::size_t index = 0; index < taken; ++index) {
                buffer_[buffered_ + index] = data[offset + index];
            }
            buffered_ += taken;
            offset += taken;
            if (buffered_ < block_size) {
                return *this;
            }
            compress(std::span<const std::byte, block_size>{buffer_});
            buffered_ = 0;
        }

        // Whole blocks straight from the input.
        while (data.size() - offset >= block_size) {
            compress(std::span<const std::byte, block_size>{data.data() + offset, block_size});
            offset += block_size;
        }

        // Keep the remainder.
        const std::size_t remaining = data.size() - offset;
        for (std::size_t index = 0; index < remaining; ++index) {
            buffer_[index] = data[offset + index];
        }
        buffered_ = remaining;
        return *this;
    }

    /// Absorb text as bytes, with no transcoding.
    ///
    /// Not implemented with `std::as_bytes`: that conversion needs a
    /// `reinterpret_cast`, which is not permitted during constant evaluation,
    /// and this overload is what the `static_assert`ed digests in the test
    /// suite go through. Converting character by character through a staging
    /// buffer keeps the whole path constexpr.
    constexpr auto update(std::string_view text) noexcept -> sha256_hasher& {
        std::array<std::byte, block_size> staging{};
        std::size_t offset = 0;
        while (offset < text.size()) {
            const std::size_t remaining = text.size() - offset;
            const std::size_t take = remaining < block_size ? remaining : block_size;
            for (std::size_t index = 0; index < take; ++index) {
                staging[index] =
                    static_cast<std::byte>(static_cast<unsigned char>(text[offset + index]));
            }
            update(std::span<const std::byte>{staging.data(), take});
            offset += take;
        }
        return *this;
    }

    /// Finish and return the digest. The hasher is reset afterwards, so it can
    /// be reused for the next message without carrying state across.
    ///
    /// The padding is written directly into the block buffer rather than fed
    /// through `update`: `update` maintains the byte counter, and the counter
    /// has already been read into `total_bits`, so routing the padding through
    /// it would change the very value being appended.
    [[nodiscard]] constexpr auto finish() noexcept -> sha256_digest {
        const std::uint64_t total_bits = total_bytes_ * 8U;

        // Append the mandatory 0x80 byte.
        buffer_[buffered_] = std::byte{0x80};
        ++buffered_;

        // If the length will not fit in this block, close it and start another.
        // This is the boundary that a hand-written implementation gets wrong:
        // it is why messages of 55 and 56 bytes are tested explicitly.
        if (buffered_ > block_size - 8) {
            while (buffered_ < block_size) {
                buffer_[buffered_] = std::byte{0};
                ++buffered_;
            }
            compress(std::span<const std::byte, block_size>{buffer_});
            buffered_ = 0;
        }

        // Zero-pad up to the length field.
        while (buffered_ < block_size - 8) {
            buffer_[buffered_] = std::byte{0};
            ++buffered_;
        }

        // Append the message length in bits, big-endian, 64 bits wide.
        for (std::size_t index = 0; index < 8; ++index) {
            const auto shift = static_cast<unsigned>(56U - 8U * index);
            buffer_[buffered_ + index] = static_cast<std::byte>((total_bits >> shift) & 0xFFU);
        }
        compress(std::span<const std::byte, block_size>{buffer_});

        sha256_digest digest{};
        for (std::size_t index = 0; index < state_.size(); ++index) {
            detail::store_big_endian(state_[index], std::span<std::byte, 4>{
                                                         digest.bytes.data() + index * 4, 4});
        }

        reset();
        return digest;
    }

private:
    /// Compress one 64-byte block into the state.
    ///
    /// The extent is in the type, so the loads below are bounds-checked by
    /// construction rather than by reading the loop.
    constexpr void compress(std::span<const std::byte, block_size> block) noexcept {
        std::array<std::uint32_t, 64> schedule{};

        for (std::size_t index = 0; index < 16; ++index) {
            schedule[index] = detail::load_big_endian(
                std::span<const std::byte, 4>{block.data() + index * 4, 4});
        }
        for (std::size_t index = 16; index < 64; ++index) {
            schedule[index] = detail::small_sigma1(schedule[index - 2]) + schedule[index - 7]
                              + detail::small_sigma0(schedule[index - 15]) + schedule[index - 16];
        }

        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        std::uint32_t e = state_[4];
        std::uint32_t f = state_[5];
        std::uint32_t g = state_[6];
        std::uint32_t h = state_[7];

        for (std::size_t index = 0; index < 64; ++index) {
            const std::uint32_t temp1 = h + detail::big_sigma1(e) + detail::choose(e, f, g)
                                        + detail::sha256_round_constants[index] + schedule[index];
            const std::uint32_t temp2 = detail::big_sigma0(a) + detail::majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<std::uint32_t, 8> state_{};
    std::array<std::byte, block_size> buffer_{};
    std::size_t buffered_ = 0;
    std::uint64_t total_bytes_ = 0;
};

/// One-shot digest of a byte range.
[[nodiscard]] constexpr auto sha256(std::span<const std::byte> data) noexcept -> sha256_digest {
    sha256_hasher hasher;
    hasher.update(data);
    return hasher.finish();
}

/// One-shot digest of text, interpreted as bytes with no transcoding.
[[nodiscard]] constexpr auto sha256_of(std::string_view text) noexcept -> sha256_digest {
    sha256_hasher hasher;
    hasher.update(text);
    return hasher.finish();
}

} // namespace meta_auth::crypto

// ---------------------------------------------------------------------------
// Formatting: a digest in a log line or a failure report is always its hex
// rendering, never a byte array.
// ---------------------------------------------------------------------------
template <>
struct std::formatter<meta_auth::crypto::sha256_digest, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(const meta_auth::crypto::sha256_digest& digest,
                std::format_context& context) const {
        const auto text = digest.hex();
        return std::format_to(context.out(), "{}", text.view());
    }
};

#endif // META_AUTH_CRYPTO_SHA256_HPP

#if defined(META_AUTH_SHA256_SUPPRESSED_ARRAY_BOUNDS)
#pragma GCC diagnostic pop
#undef META_AUTH_SHA256_SUPPRESSED_ARRAY_BOUNDS
#endif
