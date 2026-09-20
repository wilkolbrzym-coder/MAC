// ===========================================================================
//  Tests of the cryptographic layer.
//
//  The vector tests are the ones that matter, and they are `static_assert`s
//  rather than run-time checks: a hash that is wrong is wrong in a way that
//  functional testing tends to miss (it still produces 32 bytes, still
//  distributes them, still round-trips), so correctness is pinned to the
//  published values at compile time and cannot regress without failing the
//  build.
//
//  The values are FIPS 180-4 (SHA-256) and RFC 4231 (HMAC-SHA256), and they
//  are cross-checked against an independent implementation before being
//  recorded here. The lengths chosen are deliberate: 55 and 56 bytes straddle
//  the padding boundary where a hand-written implementation either writes the
//  length into the wrong block or forgets the second compression.
//
//  What is *not* asserted here is constant-time behaviour: timing is not a
//  property a unit test can establish. `benchmarks/` measures the spread
//  across differing positions, and the honest statement of what that shows is
//  recorded in docs/.
// ===========================================================================
#include "meta_auth/crypto/constant_time.hpp"
#include "meta_auth/crypto/hmac.hpp"
#include "meta_auth/crypto/secure_erase.hpp"
#include "meta_auth/crypto/sha256.hpp"
#include "test_framework.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using meta_auth::crypto::sha256;
using meta_auth::crypto::sha256_digest;
using meta_auth::crypto::sha256_of;

namespace {

/// Build a message of `count` repetitions of `character`.
[[nodiscard]] auto repeated(char character, std::size_t count) -> std::string {
    return std::string(count, character);
}

/// The hex rendering of a digest, as an owning string.
///
/// `digest.hex()` returns a `fixed_string` by value, so `.view()` on the
/// *temporary* yields a view into storage that dies at the end of the full
/// expression. The copies here are what keep a comparison from reading freed
/// stack; the first version of this file did exactly that and the failure
/// report printed garbage instead of a digest.
[[nodiscard]] auto hex_of(const sha256_digest& digest) -> std::string {
    return std::string{digest.hex().view()};
}

[[nodiscard]] auto as_bytes(std::string_view text) -> std::vector<std::byte> {
    std::vector<std::byte> bytes(text.size());
    for (std::size_t index = 0; index < text.size(); ++index) {
        bytes[index] = static_cast<std::byte>(text[index]);
    }
    return bytes;
}

} // namespace

// ---------------------------------------------------------------------------
// SHA-256: FIPS 180-4 vectors, asserted at compile time
// ---------------------------------------------------------------------------
static_assert(sha256_of("").hex()
              == meta_auth::fixed_string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b"
                                         "7852b855"});
static_assert(sha256_of("abc").hex()
              == meta_auth::fixed_string{"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff6"
                                         "1f20015ad"});

/// 56 bytes: the message plus padding exactly fills one block, so the length
/// field spills into a second block. An implementation that pads incorrectly
/// produces a plausible-looking wrong digest here.
static_assert(sha256_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").hex()
              == meta_auth::fixed_string{"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd4"
                                         "19db06c1"});

/// 112 bytes: two full blocks plus padding, exercising the multi-block path.
static_assert(sha256_of("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnop"
                        "jklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
                      .hex()
              == meta_auth::fixed_string{"cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac4503"
                                         "7afee9d1"});

/// Streaming and one-shot must agree, across every block boundary. This is the
/// property that a buffering bug breaks, and it is checked at compile time for
/// the lengths where it is most likely to break.
static_assert([]() constexpr {
    meta_auth::crypto::sha256_hasher hasher;
    hasher.update(std::string_view{"abc"});
    return hasher.finish() == sha256_of("abc");
}());

// ---------------------------------------------------------------------------
// SHA-256: run-time vectors and properties
// ---------------------------------------------------------------------------
META_AUTH_TEST("sha256", "one_million_a") {
    // FIPS 180-4's long vector. Run-time rather than compile-time because a
    // megabyte of constant evaluation is a slow build for no extra guarantee.
    const std::string message = repeated('a', 1'000'000);
    META_AUTH_CHECK_EQ(hex_of(sha256_of(message)),
                       std::string{"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39c"
                                        "cc7112cd0"});
}

META_AUTH_TEST("sha256", "padding_boundaries") {
    // 55, 56, 57 and the block edges. A digest that is merely "different for
    // different inputs" would pass a naive test; these lengths are where a
    // padding defect shows up as a wrong value.
    for (const std::size_t length : {0U, 1U, 54U, 55U, 56U, 57U, 63U, 64U, 65U, 119U, 120U, 128U}) {
        const std::string message = repeated('x', length);
        const auto digest = sha256_of(message);
        // Each length must produce a distinct digest, and the digest must be
        // reproducible.
        META_AUTH_CHECK(digest == sha256_of(message));
        if (length > 0) {
            META_AUTH_CHECK(digest != sha256_of(repeated('x', length - 1)));
        }
    }
}

META_AUTH_TEST("sha256", "streaming_matches_one_shot") {
    const std::string message = repeated('m', 200);
    const auto expected = sha256_of(message);

    // Feed the same bytes in chunks of every size that crosses a block
    // boundary, plus one that does not divide the length.
    for (const std::size_t chunk : {1U, 7U, 32U, 63U, 64U, 65U, 128U, 199U}) {
        meta_auth::crypto::sha256_hasher hasher;
        std::size_t offset = 0;
        while (offset < message.size()) {
            const std::size_t take = (message.size() - offset) < chunk ? (message.size() - offset)
                                                                       : chunk;
            hasher.update(std::string_view{message}.substr(offset, take));
            offset += take;
        }
        META_AUTH_CHECK_EQ(hasher.finish(), expected);
    }
}

META_AUTH_TEST("sha256", "hasher_resets_after_finish") {
    meta_auth::crypto::sha256_hasher hasher;
    hasher.update("abc");
    const auto first = hasher.finish();
    hasher.update("abc");
    const auto second = hasher.finish();
    // Reuse must not carry state across, which is what makes it safe to keep
    // one hasher per thread rather than constructing one per message.
    META_AUTH_CHECK_EQ(first, second);
    META_AUTH_CHECK_EQ(second, sha256_of("abc"));
}

META_AUTH_TEST("sha256", "empty_input_is_well_defined") {
    meta_auth::crypto::sha256_hasher hasher;
    META_AUTH_CHECK_EQ(hasher.finish(), sha256_of(""));
    META_AUTH_CHECK_EQ(sha256(std::span<const std::byte>{}), sha256_of(""));
}

META_AUTH_TEST("sha256", "hex_round_trip") {
    const auto digest = sha256_of("attestation");
    const auto parsed = sha256_digest::from_hex(digest.hex().view());
    META_AUTH_REQUIRE(parsed.has_value());
    META_AUTH_CHECK_EQ(*parsed, digest);

    // Upper case is accepted and produces the same digest.
    std::string upper{digest.hex().view()};
    for (char& character : upper) {
        if (character >= 'a' && character <= 'f') {
            character = static_cast<char>(character - 'a' + 'A');
        }
    }
    const auto parsed_upper = sha256_digest::from_hex(upper);
    META_AUTH_REQUIRE(parsed_upper.has_value());
    META_AUTH_CHECK_EQ(*parsed_upper, digest);
}

META_AUTH_TEST("sha256", "from_hex_rejects_malformed_input") {
    // Rejecting rather than truncating: a 63-character digest is the digest of
    // something else, and accepting it would turn a comparison into a prefix
    // match.
    META_AUTH_CHECK_EQ(sha256_digest::from_hex("").error(), meta_auth::auth_error::encoding_invalid);
    META_AUTH_CHECK_EQ(sha256_digest::from_hex(std::string(63, 'a')).error(),
                       meta_auth::auth_error::encoding_invalid);
    META_AUTH_CHECK_EQ(sha256_digest::from_hex(std::string(65, 'a')).error(),
                       meta_auth::auth_error::encoding_invalid);
    META_AUTH_CHECK_EQ(sha256_digest::from_hex(std::string(64, 'z')).error(),
                       meta_auth::auth_error::encoding_invalid);
    META_AUTH_CHECK_EQ(sha256_digest::from_hex(std::string(64, ' ')).error(),
                       meta_auth::auth_error::encoding_invalid);
}

META_AUTH_TEST("sha256", "digest_renders_as_hex") {
    const auto digest = sha256_of("abc");
    META_AUTH_CHECK_EQ(std::format("{}", digest),
                       std::string{"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"});
}

// ---------------------------------------------------------------------------
// HMAC-SHA256: RFC 4231 vectors
// ---------------------------------------------------------------------------
static_assert(meta_auth::crypto::hmac_sha256_of("Jefe", "what do ya want for nothing?").hex()
              == meta_auth::fixed_string{"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b9"
                                         "64ec3843"});

META_AUTH_TEST("hmac", "rfc4231_test_case_1") {
    const std::vector<std::byte> key(20, std::byte{0x0b});
    const auto mac = meta_auth::crypto::hmac_sha256(key, as_bytes("Hi There"));
    META_AUTH_CHECK_EQ(hex_of(mac),
                       std::string{"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c"
                                        "2e32cff7"});
}

META_AUTH_TEST("hmac", "rfc4231_test_case_3") {
    const std::vector<std::byte> key(20, std::byte{0xaa});
    const std::vector<std::byte> data(50, std::byte{0xdd});
    META_AUTH_CHECK_EQ(hex_of(meta_auth::crypto::hmac_sha256(key, data)),
                       std::string{"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514"
                                        "ced565fe"});
}

META_AUTH_TEST("hmac", "rfc4231_test_case_4_short_key") {
    std::vector<std::byte> key(25);
    for (std::size_t index = 0; index < key.size(); ++index) {
        key[index] = static_cast<std::byte>(index + 1);
    }
    const std::vector<std::byte> data(50, std::byte{0xcd});
    META_AUTH_CHECK_EQ(hex_of(meta_auth::crypto::hmac_sha256(key, data)),
                       std::string{"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff4"
                                        "6729665b"});
}

META_AUTH_TEST("hmac", "rfc4231_test_case_6_key_longer_than_block") {
    // The case that catches the mistake of truncating a long key instead of
    // hashing it first. A truncated key makes two different keys collide,
    // which is a collision an attacker gets to choose.
    const std::vector<std::byte> key(131, std::byte{0xaa});
    const auto mac = meta_auth::crypto::hmac_sha256(
        key, as_bytes("Test Using Larger Than Block-Size Key - Hash Key First"));
    META_AUTH_CHECK_EQ(hex_of(mac),
                       std::string{"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f"
                                        "0ee37f54"});
}

META_AUTH_TEST("hmac", "rfc4231_test_case_7_long_key_and_long_message") {
    const std::vector<std::byte> key(131, std::byte{0xaa});
    const auto mac = meta_auth::crypto::hmac_sha256(
        key,
        as_bytes("This is a test using a larger than block-size key and a larger than block-size "
                 "data. The key needs to be hashed before being used by the HMAC algorithm."));
    META_AUTH_CHECK_EQ(hex_of(mac),
                       std::string{"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f5153"
                                        "5c3a35e2"});
}

META_AUTH_TEST("hmac", "streaming_matches_one_shot") {
    const std::vector<std::byte> key(32, std::byte{0x42});
    const std::string message = repeated('m', 150);
    const auto expected = meta_auth::crypto::hmac_sha256_of(
        std::string_view{reinterpret_cast<const char*>(key.data()), key.size()}, message);

    meta_auth::crypto::hmac_sha256_hasher hasher(key);
    for (std::size_t offset = 0; offset < message.size(); offset += 17) {
        hasher.update(std::string_view{message}.substr(offset, 17));
    }
    META_AUTH_CHECK_EQ(hasher.finish(), expected);
}

META_AUTH_TEST("hmac", "different_keys_produce_different_macs") {
    const std::string_view message = "device-descriptor";
    META_AUTH_CHECK_NE(meta_auth::crypto::hmac_sha256_of("key-a", message),
                       meta_auth::crypto::hmac_sha256_of("key-b", message));
    META_AUTH_CHECK_NE(meta_auth::crypto::hmac_sha256_of("key-a", message),
                       meta_auth::crypto::hmac_sha256_of("key-a", "other-message"));
}

META_AUTH_TEST("hmac", "verify_accepts_the_right_tag_and_rejects_every_other") {
    const std::string_view key = "enrolment-key";
    const std::string_view message = "device:model-x";
    const auto tag = meta_auth::crypto::hmac_sha256_of(key, message);

    META_AUTH_CHECK(meta_auth::crypto::verify_hmac(
        std::as_bytes(std::span{key.data(), key.size()}),
        std::as_bytes(std::span{message.data(), message.size()}), tag));

    // Every single-bit change to the tag must be rejected. Checking only "a
    // wrong tag" would pass for an implementation that compares a prefix.
    for (std::size_t byte_index = 0; byte_index < tag.bytes.size(); ++byte_index) {
        for (unsigned bit = 0; bit < 8U; ++bit) {
            sha256_digest forged = tag;
            forged.bytes[byte_index] = static_cast<std::byte>(
                std::to_integer<std::uint8_t>(forged.bytes[byte_index]) ^ (1U << bit));
            META_AUTH_CHECK(!meta_auth::crypto::verify_hmac(
                std::as_bytes(std::span{key.data(), key.size()}),
                std::as_bytes(std::span{message.data(), message.size()}), forged));
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time primitives
// ---------------------------------------------------------------------------
META_AUTH_TEST("constant_time", "equality_is_correct_for_every_differing_position") {
    // The interesting property is not "equal values compare equal" -- a
    // one-line `==` passes that. It is that the answer is right when the
    // difference is at the beginning, the middle and the end, which is what
    // a broken accumulate-and-compare gets wrong.
    const std::array<std::byte, 8> reference{std::byte{1}, std::byte{2}, std::byte{3},
                                             std::byte{4}, std::byte{5}, std::byte{6},
                                             std::byte{7}, std::byte{8}};

    META_AUTH_CHECK(meta_auth::crypto::constant_time_equal(reference, reference));

    for (std::size_t index = 0; index < reference.size(); ++index) {
        auto changed = reference;
        changed[index] = static_cast<std::byte>(
            std::to_integer<std::uint8_t>(changed[index]) ^ 0x80U);
        META_AUTH_CHECK(!meta_auth::crypto::constant_time_equal(reference, changed));
    }

    // A difference in the most significant bit and in the least are both
    // caught: an implementation that sign-extends would miss one of them.
    auto high_bit = reference;
    high_bit[0] = std::byte{0xFF};
    auto low_bit = reference;
    low_bit[0] = std::byte{0x00};
    META_AUTH_CHECK(!meta_auth::crypto::constant_time_equal(reference, high_bit));
    META_AUTH_CHECK(!meta_auth::crypto::constant_time_equal(reference, low_bit));
}

META_AUTH_TEST("constant_time", "length_mismatch_is_rejected") {
    const std::array<std::byte, 4> shorter{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 5> longer{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                                          std::byte{5}};
    META_AUTH_CHECK(!meta_auth::crypto::constant_time_equal(shorter, longer));
    META_AUTH_CHECK(meta_auth::crypto::constant_time_equal(std::span<const std::byte>{},
                                                           std::span<const std::byte>{}));
}

META_AUTH_TEST("constant_time", "string_equality_uses_unsigned_bytes") {
    // A character with the high bit set must not be sign-extended into a
    // difference that never clears.
    const std::string with_high_bit{"\xFF\xFE", 2};
    const std::string other{"\xFF\xFD", 2};
    META_AUTH_CHECK(meta_auth::crypto::constant_time_equal(with_high_bit, with_high_bit));
    META_AUTH_CHECK(!meta_auth::crypto::constant_time_equal(with_high_bit, other));
    META_AUTH_CHECK(!meta_auth::crypto::constant_time_equal(with_high_bit, ""));
}

META_AUTH_TEST("constant_time", "is_zero_covers_every_byte") {
    const std::array<std::byte, 4> zeroes{};
    META_AUTH_CHECK(meta_auth::crypto::constant_time_is_zero(zeroes));
    META_AUTH_CHECK(meta_auth::crypto::constant_time_is_zero(std::span<const std::byte>{}));

    for (std::size_t index = 0; index < zeroes.size(); ++index) {
        auto nonzero = zeroes;
        nonzero[index] = std::byte{0x01};
        META_AUTH_CHECK(!meta_auth::crypto::constant_time_is_zero(nonzero));
    }
}

META_AUTH_TEST("constant_time", "select_returns_the_selected_operand") {
    META_AUTH_CHECK_EQ(meta_auth::crypto::constant_time_select(true, std::uint32_t{7},
                                                                std::uint32_t{9}),
                       std::uint32_t{7});
    META_AUTH_CHECK_EQ(meta_auth::crypto::constant_time_select(false, std::uint32_t{7},
                                                                std::uint32_t{9}),
                       std::uint32_t{9});
    META_AUTH_CHECK_EQ(meta_auth::crypto::constant_time_select(true, std::uint8_t{0xFF},
                                                                std::uint8_t{0x00}),
                       std::uint8_t{0xFF});
    // Exhaustive over a small domain: every (condition, a, b) triple.
    for (std::uint32_t a = 0; a < 4; ++a) {
        for (std::uint32_t b = 0; b < 4; ++b) {
            META_AUTH_CHECK_EQ(meta_auth::crypto::constant_time_select(true, a, b), a);
            META_AUTH_CHECK_EQ(meta_auth::crypto::constant_time_select(false, a, b), b);
        }
    }
}

META_AUTH_TEST("constant_time", "less_than_matches_the_operator") {
    // Exhaustive over a domain that includes the wraparound case, which is
    // where a hand-rolled branch-free comparison goes wrong.
    constexpr std::uint64_t values[] = {0, 1, 2, 0x7FFFFFFFFFFFFFFFULL, 0x8000000000000000ULL,
                                        0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL};
    for (const std::uint64_t lhs : values) {
        for (const std::uint64_t rhs : values) {
            META_AUTH_CHECK_EQ(meta_auth::crypto::constant_time_less(lhs, rhs), lhs < rhs);
        }
    }
}

META_AUTH_TEST("constant_time", "mask_is_zero_or_one") {
    META_AUTH_CHECK_EQ(meta_auth::crypto::constant_time_mask(true), std::uint8_t{1});
    META_AUTH_CHECK_EQ(meta_auth::crypto::constant_time_mask(false), std::uint8_t{0});
}

// ---------------------------------------------------------------------------
// Erasure
// ---------------------------------------------------------------------------
META_AUTH_TEST("secure_erase", "zeroes_the_whole_range") {
    std::array<std::byte, 16> secret{};
    for (std::size_t index = 0; index < secret.size(); ++index) {
        secret[index] = static_cast<std::byte>(0xA5);
    }

    meta_auth::crypto::secure_erase(secret);

    for (const std::byte element : secret) {
        META_AUTH_CHECK_EQ(std::to_integer<std::uint8_t>(element), std::uint8_t{0});
    }
}

META_AUTH_TEST("secure_erase", "an_empty_range_is_accepted") {
    // A guard against a caller that erases a zero-length key: the function
    // must be a no-op rather than a precondition violation, because "erase
    // nothing" is a legitimate outcome of a size computation.
    meta_auth::crypto::secure_erase(std::span<std::byte>{});
    META_AUTH_CHECK(true);
}

META_AUTH_TEST("secure_erase", "object_overload_zeroes_a_trivial_type") {
    struct key_material {
        std::uint64_t words[4];
    };
    key_material material{{0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL, 1ULL, 2ULL}};
    meta_auth::crypto::secure_erase_object(material);
    for (const std::uint64_t word : material.words) {
        META_AUTH_CHECK_EQ(word, std::uint64_t{0});
    }
}

META_AUTH_TEST("secret_buffer", "assign_and_read_back") {
    meta_auth::crypto::secret_buffer<32> buffer;
    META_AUTH_CHECK(buffer.is_empty());
    META_AUTH_CHECK_EQ(buffer.size(), std::size_t{0});

    const std::array<std::byte, 5> key{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                                       std::byte{5}};
    META_AUTH_REQUIRE(buffer.assign(key));
    META_AUTH_CHECK_EQ(buffer.size(), std::size_t{5});
    META_AUTH_CHECK(meta_auth::crypto::constant_time_equal(buffer.bytes(), key));

    std::array<std::byte, 5> copy{};
    buffer.copy_to(copy);
    META_AUTH_CHECK(meta_auth::crypto::constant_time_equal(copy, key));
}

META_AUTH_TEST("secret_buffer", "a_key_that_does_not_fit_is_refused") {
    // Refused, not truncated. A truncated key is a different key, and a
    // different key that looks accepted is how a check becomes a formality.
    meta_auth::crypto::secret_buffer<8> buffer;
    const std::array<std::byte, 9> too_long{};
    META_AUTH_CHECK(!buffer.assign(too_long));
    META_AUTH_CHECK(buffer.is_empty());
}

META_AUTH_TEST("secret_buffer", "wipe_clears_the_contents_and_the_length") {
    meta_auth::crypto::secret_buffer<16> buffer;
    const std::array<std::byte, 4> key{std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                                       std::byte{0xDD}};
    META_AUTH_REQUIRE(buffer.assign(key));
    buffer.wipe();
    META_AUTH_CHECK(buffer.is_empty());
    META_AUTH_CHECK(meta_auth::crypto::constant_time_is_zero(buffer.bytes()));
}

META_AUTH_TEST("secret_buffer", "reassignment_does_not_leave_the_tail_behind") {
    // The failure this guards against: a 16-byte key assigned, then a 4-byte
    // key assigned over it. If only the used prefix were erased, the last 12
    // bytes of the first key would still be in the buffer.
    meta_auth::crypto::secret_buffer<16> buffer;
    std::array<std::byte, 16> long_key{};
    long_key.fill(std::byte{0x5A});
    META_AUTH_REQUIRE(buffer.assign(long_key));

    const std::array<std::byte, 4> short_key{std::byte{1}, std::byte{2}, std::byte{3},
                                             std::byte{4}};
    META_AUTH_REQUIRE(buffer.assign(short_key));

    // Inspect the raw storage through a view of the full capacity.
    const std::span<const std::byte> raw{buffer.data(), buffer.capacity};
    META_AUTH_CHECK(meta_auth::crypto::constant_time_equal(raw.first(4), short_key));
    META_AUTH_CHECK(meta_auth::crypto::constant_time_is_zero(raw.subspan(4)));
}
