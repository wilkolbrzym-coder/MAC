// ===========================================================================
//  meta-auth-core -- structural strings.
//
//  Policies, principals, devices and resources are identified by names, and
//  every one of those names is known when the program is compiled. Expressing
//  them as `fixed_string` non-type template parameters is what lets the policy
//  engine compare, index and validate them with no run-time cost and no
//  allocation, and what lets a typo in a resource name be a compile error
//  rather than a request that is silently denied at three in the morning.
//
//  The type is *structural* on purpose: every special member is trivial or
//  constexpr, and the single data member is public, which is what C++20
//  requires for a class type to be usable as a template argument.
// ===========================================================================
#ifndef META_AUTH_CORE_FIXED_STRING_HPP
#define META_AUTH_CORE_FIXED_STRING_HPP

#include "meta_auth/config.hpp"
#include "meta_auth/core/contract.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string_view>

namespace meta_auth {

/// A string literal whose length is part of its type.
///
/// `fixed_string<N>` stores N characters including the terminator, so
/// `fixed_string{"admin"}` has N == 6. The terminator is kept so that `c_str()`
/// is free and the object can be handed to a C API; `size()` reports the
/// length without it.
template <std::size_t N>
struct fixed_string {
    /// Storage, including the terminator. Public because a structural type has
    /// no private members, which is a language requirement rather than a
    /// design choice.
    char data[N]{};

    constexpr fixed_string() noexcept = default;

    /// Construct from a string literal. The literal's own size fixes N, so a
    /// name that is too long for a consumer fails at the consumer's boundary.
    constexpr fixed_string(const char (&text)[N]) noexcept {
        std::copy_n(text, N, data);
    }

    /// Number of characters, excluding the terminator.
    [[nodiscard]] constexpr auto size() const noexcept -> std::size_t { return N - 1; }

    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return N == 1; }

    [[nodiscard]] constexpr auto view() const noexcept -> std::string_view {
        return std::string_view{data, N - 1};
    }

    [[nodiscard]] constexpr auto c_str() const noexcept -> const char* { return data; }

    [[nodiscard]] constexpr operator std::string_view() const noexcept { return view(); }

    [[nodiscard]] constexpr auto operator[](std::size_t index) const noexcept -> char {
        return index < size() ? data[index] : '\0';
    }

    /// Member-wise equality. Also spelled as a defaulted comparison so that
    /// the type works as a template argument and in containers without a
    /// hand-written comparison.
    friend constexpr auto operator==(const fixed_string&, const fixed_string&) noexcept
        -> bool = default;

    /// Comparison with a shorter or longer literal, so that
    /// `resource == "devices"` reads naturally without constructing a
    /// `fixed_string` first.
    template <std::size_t M>
    friend constexpr auto operator==(const fixed_string& lhs,
                                     const fixed_string<M>& rhs) noexcept -> bool {
        return lhs.view() == rhs.view();
    }

    [[nodiscard]] constexpr auto starts_with(std::string_view prefix) const noexcept -> bool {
        return view().substr(0, prefix.size()) == prefix;
    }

    [[nodiscard]] constexpr auto ends_with(std::string_view suffix) const noexcept -> bool {
        return view().size() >= suffix.size()
               && view().substr(view().size() - suffix.size()) == suffix;
    }

    [[nodiscard]] constexpr auto contains(std::string_view needle) const noexcept -> bool {
        return view().find(needle) != std::string_view::npos;
    }
};

/// Deduction guide: `fixed_string{"admin"}` deduces N from the literal.
template <std::size_t N>
fixed_string(const char (&)[N]) -> fixed_string<N>;

/// Concatenation. The result's capacity is the sum of the inputs' lengths plus
/// the terminator, so the result type is exact rather than rounded up.
template <std::size_t N, std::size_t M>
[[nodiscard]] constexpr auto concat(const fixed_string<N>& lhs, const fixed_string<M>& rhs) noexcept
    -> fixed_string<N + M - 1> {
    fixed_string<N + M - 1> result{};
    std::copy_n(lhs.data, lhs.size(), result.data);
    std::copy_n(rhs.data, rhs.size(), result.data + lhs.size());
    result.data[N + M - 2] = '\0';
    return result;
}

/// ASCII lower-casing of one character.
///
/// Deliberately ASCII-only: resource, action and principal names in this
/// library are identifiers that a build produces, not user data. Locale-aware
/// case folding would introduce a dependency on global state and a class of
/// ambiguity (which "i" is the same as which "I") that has no place in an
/// authorisation decision.
[[nodiscard]] constexpr auto lower_ascii(char value) noexcept -> char {
    constexpr char upper_a = 'A';
    constexpr char upper_z = 'Z';
    constexpr char case_offset = 'a' - 'A';
    return value >= upper_a && value <= upper_z ? static_cast<char>(value + case_offset) : value;
}

/// Case-insensitive ASCII comparison of two names.
[[nodiscard]] constexpr auto equals_ignore_ascii_case(std::string_view lhs,
                                                      std::string_view rhs) noexcept -> bool {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        if (lower_ascii(lhs[index]) != lower_ascii(rhs[index])) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Compile-time hashing
//
// FNV-1a, 64-bit. The purpose is not cryptographic: it is a compact, stable
// identifier for a name, used where a name has to appear in a fixed-size
// record (an audit entry, a capability table slot). Anything that must resist
// an adversary uses the keyed MAC in crypto/mac.hpp instead, and the
// distinction is stated here so that the weaker primitive is not mistaken for
// the stronger one.
// ---------------------------------------------------------------------------
struct fnv1a_64 {
    static constexpr std::uint64_t offset_basis = 0xCBF29CE484222325ULL;
    static constexpr std::uint64_t prime = 0x00000100000001B3ULL;

    [[nodiscard]] static constexpr auto hash(std::string_view text) noexcept -> std::uint64_t {
        std::uint64_t state = offset_basis;
        for (const char character : text) {
            state ^= static_cast<std::uint64_t>(static_cast<unsigned char>(character));
            state *= prime;
        }
        return state;
    }
};

template <std::size_t N>
[[nodiscard]] constexpr auto hash_name(const fixed_string<N>& name) noexcept -> std::uint64_t {
    return fnv1a_64::hash(name.view());
}

} // namespace meta_auth

// ---------------------------------------------------------------------------
// Formatting: a name renders as itself, so a failure report or a log line
// shows the resource rather than an address.
// ---------------------------------------------------------------------------
template <std::size_t N>
struct std::formatter<meta_auth::fixed_string<N>, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(const meta_auth::fixed_string<N>& value, std::format_context& context) const {
        return std::format_to(context.out(), "{}", value.view());
    }
};

#endif // META_AUTH_CORE_FIXED_STRING_HPP
