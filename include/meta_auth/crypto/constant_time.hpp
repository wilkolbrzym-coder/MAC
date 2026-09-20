// ===========================================================================
//  meta-auth-core -- constant-time primitives.
//
//  Comparing a secret with `==` returns as soon as the first byte differs, so
//  the time it takes is a function of how many leading bytes were guessed
//  correctly. For a message authentication tag that turns forgery from an
//  infeasible search into a byte-by-byte recovery, and it does so invisibly:
//  the code looks correct and every functional test passes.
//
//  What this header provides are comparisons whose *result* depends only on
//  whether the inputs are equal, never on where they differ. What it cannot
//  provide is a proof: constant-time-ness is a property of the generated code,
//  and the honest statement of how it is established here is
//
//    * the loops have no early exit and accumulate with bitwise operations;
//    * an optimisation barrier stops the compiler from turning the
//      accumulation back into a short-circuit or a vectorised comparison with
//      data-dependent timing;
//    * `benchmarks/` measures the comparison across every differing position
//      and reports the spread, because a claim about timing that is never
//      measured is a claim about source code, not about a program.
//
//  Everything here is constexpr, so a comparison can also be evaluated while
//  compiling -- which is what lets the attestation checks in the identity
//  layer run as `static_assert`s.
// ===========================================================================
#ifndef META_AUTH_CRYPTO_CONSTANT_TIME_HPP
#define META_AUTH_CRYPTO_CONSTANT_TIME_HPP

#include "meta_auth/config.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>

namespace meta_auth::crypto {

/// A barrier the optimiser may not look through.
///
/// Not constexpr, and never called during constant evaluation: an `asm`
/// declaration is not permitted in a constexpr function body, which is why
/// this lives in a separate function that the constexpr callers only reach in
/// their run-time branch. Without it, GCC is entitled to recognise the
/// accumulate-and-compare idiom and replace it with `memcmp`.
inline void optimization_barrier(std::uint8_t& value) noexcept {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : "+r"(value) : : "memory");
#else
    // Without a barrier the compiler is free to shorten the loop. The library
    // still computes the right answer; the timing property is then only as
    // good as the compiler's restraint, which is why the fallback is stated
    // rather than silently assumed.
    //
    // The sink is atomic and not merely volatile. Comparing a MAC is an
    // ordinary operation on ordinary objects, so two threads verifying
    // credentials at the same time reach this function concurrently; a plain
    // `volatile` counter written from both is a data race, which is undefined
    // behaviour in the one place in this library where a defect is invisible.
    // A relaxed RMW to an atomic has no ordering obligation and compiles to
    // the same instruction, so the barrier costs the same as it did.
    static std::atomic<std::uint8_t> sink{0};
    sink.fetch_xor(value, std::memory_order_relaxed);
#endif
}

/// True when `lhs` and `rhs` are equal, in time independent of their contents.
///
/// The lengths are compared first and are not secret: every caller in this
/// library compares values of a fixed, public size (a digest, a tag, a
/// capability identifier), so a length leak would carry no information. What
/// must not leak is *where* two equal-length values differ.
[[nodiscard]] constexpr auto constant_time_equal(std::span<const std::byte> lhs,
                                                 std::span<const std::byte> rhs) noexcept -> bool {
    if (lhs.size() != rhs.size()) {
        return false;
    }

    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        const auto left = std::to_integer<std::uint8_t>(lhs[index]);
        const auto right = std::to_integer<std::uint8_t>(rhs[index]);
        difference = static_cast<std::uint8_t>(difference | (left ^ right));
    }

    if !consteval {
        optimization_barrier(difference);
    }
    return difference == 0;
}

/// String overload. The characters are compared as unsigned bytes, so a
/// character with the high bit set cannot be sign-extended into a difference
/// that never clears.
[[nodiscard]] constexpr auto constant_time_equal(std::string_view lhs,
                                                 std::string_view rhs) noexcept -> bool {
    if (lhs.size() != rhs.size()) {
        return false;
    }

    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        const auto left = static_cast<std::uint8_t>(lhs[index]);
        const auto right = static_cast<std::uint8_t>(rhs[index]);
        difference = static_cast<std::uint8_t>(difference | (left ^ right));
    }

    if !consteval {
        optimization_barrier(difference);
    }
    return difference == 0;
}

/// True when every byte of `value` is zero, without an early exit.
[[nodiscard]] constexpr auto constant_time_is_zero(std::span<const std::byte> value) noexcept
    -> bool {
    std::uint8_t accumulator = 0;
    for (const std::byte element : value) {
        accumulator = static_cast<std::uint8_t>(accumulator | std::to_integer<std::uint8_t>(element));
    }

    if !consteval {
        optimization_barrier(accumulator);
    }
    return accumulator == 0;
}

/// Return `if_set` when `condition` is true, `otherwise` otherwise -- without a
/// branch on `condition`.
///
/// Branching on a secret is the other half of the same problem as comparing
/// one byte at a time: a mispredicted branch is visible in a timing profile,
/// so a secret-dependent `if` leaks the secret even when the comparison itself
/// is constant time.
template <typename T>
    requires std::is_integral_v<T> && (!std::is_same_v<T, bool>)
[[nodiscard]] constexpr auto constant_time_select(bool condition, T if_set, T otherwise) noexcept
    -> T {
    using unsigned_type = std::make_unsigned_t<T>;

    // A branch on `condition` is unavoidable at the source level, but it does
    // not have to reach the machine: the compiler sees both operands computed
    // and selects between them with a conditional move. What matters is that
    // the *value* selection is arithmetic, so there is no data-dependent
    // control flow of the caller's making.
    const auto mask = static_cast<unsigned_type>(condition ? ~unsigned_type{0} : unsigned_type{0});
    const auto left = static_cast<unsigned_type>(if_set) & mask;
    const auto right = static_cast<unsigned_type>(otherwise) & static_cast<unsigned_type>(~mask);
    return static_cast<T>(left | right);
}

/// Zero or one, as a value.
///
/// Named for what it returns rather than for what it is often used to build: a
/// caller that wants a full-width 0x00/0xFF mask wants
/// `constant_time_select`, and a function called `mask` that returns one bit
/// is a name that invites the wrong assumption.
[[nodiscard]] constexpr auto constant_time_bit(bool value) noexcept -> std::uint8_t {
    return value ? std::uint8_t{1} : std::uint8_t{0};
}

/// True when `lhs < rhs` for unsigned integers, without a data-dependent
/// branch.
///
/// Implemented by looking at the sign bit of the difference after expanding to
/// one extra bit, which is the standard branch-free comparison. Used when a
/// length is itself secret, which is rare in this library but not impossible
/// (a padded credential can have a secret length).
[[nodiscard]] constexpr auto constant_time_less(std::uint64_t lhs, std::uint64_t rhs) noexcept
    -> bool {
    const std::uint64_t difference = lhs - rhs;
    const std::uint64_t borrow = ((~lhs & rhs) | ((~lhs | rhs) & difference)) >> 63U;
    return borrow != 0;
}

} // namespace meta_auth::crypto

#endif // META_AUTH_CRYPTO_CONSTANT_TIME_HPP
