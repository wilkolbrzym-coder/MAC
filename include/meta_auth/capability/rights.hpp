// ===========================================================================
//  meta-auth-core -- the rights lattice.
//
//  Rights are the atoms of authority. They form a finite set, and subsets of
//  that set form a lattice under inclusion: `⊆`, `∪`, `∩` and complement are
//  total, associative and mutually consistent. That is not decoration. It is
//  what makes "this capability cannot be stronger than that one" a statement
//  about a partial order rather than a claim about a code path, and it is what
//  the property tests in tests/capability/test_rights.cpp check exhaustively
//  over all 2^7 subsets rather than by sampling.
//
//  `rights_set` is a *structural* type -- its single member is public and
//  everything else is constexpr -- so a set of rights can be a non-type
//  template parameter. That is the mechanism behind the central claim of this
//  library: `capability<Resource, rights>` carries its rights in its type, so
//  a capability that is too weak for an operation fails to compile rather than
//  failing a run-time check.
// ===========================================================================
#ifndef META_AUTH_CAPABILITY_RIGHTS_HPP
#define META_AUTH_CAPABILITY_RIGHTS_HPP

#include "meta_auth/config.hpp"
#include "meta_auth/core/contract.hpp"
#include "meta_auth/core/fixed_string.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <string_view>

namespace meta_auth {

/// One atom of authority.
///
/// The set is closed and small on purpose. A right that is never checked is
/// indistinguishable from no right at all, so this enumeration is the complete
/// vocabulary of what can be authorised, and the policy engine's exhaustiveness
/// check (built on reflection) refuses a policy that does not account for the
/// resources it mediates.
enum class right : std::uint32_t {
    read = 1U << 0U,       ///< observe the resource's state
    write = 1U << 1U,      ///< change the resource's state
    execute = 1U << 2U,    ///< cause the resource to perform an operation
    grant = 1U << 3U,      ///< hand a weaker capability to somebody else
    revoke = 1U << 4U,     ///< advance the resource's revocation epoch
    audit = 1U << 5U,      ///< read the resource's audit trail
    administer = 1U << 6U, ///< change the resource's policy-relevant state
};

/// Every defined right, as a bit mask.
inline constexpr std::uint32_t all_right_bits = 0x7FU;

/// Number of distinct rights. Used by the exhaustive property tests, and by the
/// compile-time check that the enumeration above and this constant agree.
inline constexpr std::size_t right_count = 7;

/// Name table. Indexed by bit position, so a lookup is a shift rather than a
/// search, and a new right is one line here plus one enumerator above.
inline constexpr std::string_view right_names[right_count] = {
    "read", "write", "execute", "grant", "revoke", "audit", "administer"};

/// Bit position of a right, or `right_count` when the value is not a single
/// bit. Returning an out-of-range index rather than asserting keeps this
/// constexpr-friendly and pushes the decision to the caller.
[[nodiscard]] constexpr auto right_index(right value) noexcept -> std::size_t {
    const auto bits = static_cast<std::uint32_t>(value);
    if (bits == 0U || (bits & (bits - 1U)) != 0U) {
        return right_count;
    }
    std::size_t index = 0;
    std::uint32_t remaining = bits;
    while ((remaining >>= 1U) != 0U) {
        ++index;
    }
    return index;
}

[[nodiscard]] constexpr auto to_string(right value) noexcept -> std::string_view {
    const std::size_t index = right_index(value);
    return index < right_count ? right_names[index] : std::string_view{"<invalid right>"};
}

/// Every right, in declaration order. Iterating this is how the tests and the
/// policy exhaustiveness check reach the whole vocabulary without reflection
/// being available.
inline constexpr auto all_rights = []() constexpr {
    std::array<right, right_count> values{};
    for (std::size_t index = 0; index < right_count; ++index) {
        values[index] = static_cast<right>(1U << index);
    }
    return values;
}();

/// A set of rights.
///
/// Structural: the representation is public, so the type can be a non-type
/// template parameter, and the compiler compares two sets member-wise when it
/// compares template arguments. There is no private state to keep consistent
/// with the public member, which is why the class is written as a thin wrapper
/// over `bits_` rather than as a class with invariants.
class rights_set {
public:
    /// The empty set.
    constexpr rights_set() noexcept = default;

    /// A single right.
    constexpr rights_set(right value) noexcept
        : bits_(static_cast<std::uint32_t>(value)) {}

    /// A set from several rights: `rights_set{right::read, right::audit}`.
    template <typename... Rights>
        requires(sizeof...(Rights) > 0 && (std::is_same_v<Rights, right> && ...))
    constexpr explicit rights_set(Rights... values) noexcept
        : bits_((static_cast<std::uint32_t>(values) | ...)) {}

    /// The empty set, named.
    [[nodiscard]] static constexpr auto none() noexcept -> rights_set { return rights_set{}; }

    /// Every right.
    [[nodiscard]] static constexpr auto all() noexcept -> rights_set {
        return rights_set{static_cast<right>(all_right_bits)};
    }

    [[nodiscard]] constexpr auto bits() const noexcept -> std::uint32_t { return bits_; }

    [[nodiscard]] constexpr auto is_empty() const noexcept -> bool { return bits_ == 0U; }

    [[nodiscard]] constexpr auto is_full() const noexcept -> bool {
        return bits_ == all_right_bits;
    }

    /// True when `value` is in the set.
    [[nodiscard]] constexpr auto contains(right value) const noexcept -> bool {
        return (bits_ & static_cast<std::uint32_t>(value)) == static_cast<std::uint32_t>(value);
    }

    /// True when every right of `other` is in this set. The lattice's `⊆`.
    [[nodiscard]] constexpr auto contains(rights_set other) const noexcept -> bool {
        return (bits_ & other.bits_) == other.bits_;
    }

    /// `⊆`, spelled for the direction it is read in.
    [[nodiscard]] constexpr auto is_subset_of(rights_set other) const noexcept -> bool {
        return other.contains(*this);
    }

    /// `⊊`.
    [[nodiscard]] constexpr auto is_proper_subset_of(rights_set other) const noexcept -> bool {
        return bits_ != other.bits_ && other.contains(*this);
    }

    /// Number of rights in the set.
    [[nodiscard]] constexpr auto size() const noexcept -> std::size_t {
        std::size_t count = 0;
        std::uint32_t remaining = bits_;
        while (remaining != 0U) {
            count += (remaining & 1U);
            remaining >>= 1U;
        }
        return count;
    }

    constexpr auto operator|=(rights_set other) noexcept -> rights_set& {
        bits_ |= other.bits_;
        return *this;
    }

    constexpr auto operator&=(rights_set other) noexcept -> rights_set& {
        bits_ &= other.bits_;
        return *this;
    }

    friend constexpr auto operator|(rights_set lhs, rights_set rhs) noexcept -> rights_set {
        return rights_set{static_cast<right>(lhs.bits_ | rhs.bits_)};
    }

    friend constexpr auto operator&(rights_set lhs, rights_set rhs) noexcept -> rights_set {
        return rights_set{static_cast<right>(lhs.bits_ & rhs.bits_)};
    }

    /// Set difference: the rights in `lhs` that are not in `rhs`.
    friend constexpr auto operator-(rights_set lhs, rights_set rhs) noexcept -> rights_set {
        return rights_set{static_cast<right>(lhs.bits_ & ~rhs.bits_)};
    }

    /// Complement within the universe of defined rights.
    ///
    /// Complement against `all_right_bits` rather than against the full 32-bit
    /// range: a set containing an undefined bit would be a right nobody can
    /// name, and this library has no such thing.
    [[nodiscard]] constexpr auto complement() const noexcept -> rights_set {
        return rights_set{static_cast<right>(all_right_bits & ~bits_)};
    }

    friend constexpr auto operator==(rights_set lhs, rights_set rhs) noexcept -> bool = default;

    /// A human-readable rendering: `read|audit`, `none`, or `all`.
    ///
    /// Writes into the caller's buffer rather than allocating, because the
    /// audit trail records right sets and the audit trail does not allocate.
    [[nodiscard]] constexpr auto write_to(std::span<char> buffer) const noexcept -> std::string_view {
        if (buffer.empty()) {
            return {};
        }
        if (bits_ == 0U) {
            return write_literal(buffer, "none");
        }
        if (is_full()) {
            return write_literal(buffer, "all");
        }

        std::size_t written = 0;
        bool first = true;
        for (std::size_t index = 0; index < right_count; ++index) {
            if ((bits_ & (1U << index)) == 0U) {
                continue;
            }
            if (!first) {
                if (written >= buffer.size()) {
                    return std::string_view{buffer.data(), written};
                }
                buffer[written] = '|';
                ++written;
            }
            first = false;
            const std::string_view name = right_names[index];
            for (const char character : name) {
                if (written >= buffer.size()) {
                    return std::string_view{buffer.data(), written};
                }
                buffer[written] = character;
                ++written;
            }
        }
        return std::string_view{buffer.data(), written};
    }

    /// Owning rendering, for tests and log lines. Allocates; the audit path
    /// uses `write_to` instead.
    [[nodiscard]] auto to_string() const -> std::string {
        std::array<char, 128> buffer{};
        const std::string_view text = write_to(buffer);
        return std::string{text};
    }

    /// The representation.
    ///
    /// Public because a structural type must have no private non-static data
    /// members -- that is a language requirement for being usable as a
    /// non-type template parameter, and it is the whole reason this class
    /// exists. It is treated as private by convention: every set is produced
    /// by one of the named operations above, so there is no invariant for a
    /// caller to break by reading it, and writing to it directly is a defect a
    /// reviewer will see.
    std::uint32_t bits_ = 0;

private:
    static constexpr auto write_literal(std::span<char> buffer, std::string_view text) noexcept
        -> std::string_view {
        const std::size_t count = text.size() < buffer.size() ? text.size() : buffer.size();
        for (std::size_t index = 0; index < count; ++index) {
            buffer[index] = text[index];
        }
        return std::string_view{buffer.data(), count};
    }
};

/// Visit each right in a set, in declaration order.
///
/// A function rather than an iterator pair: the sets are tiny, the loop bodies
/// are short, and an abstraction that has to allocate to be iterated would
/// give the audit path an allocation it cannot afford.
template <typename Function>
constexpr void for_each_right(rights_set set, Function&& function) {
    for (std::size_t index = 0; index < right_count; ++index) {
        const auto candidate = static_cast<right>(1U << index);
        if (set.contains(candidate)) {
            function(candidate);
        }
    }
}

/// The rights a delegating holder must have for `delegate` to be permitted.
/// Named here because "you cannot give away what you cannot give away" is a
/// rule of the model, not a detail of one function.
inline constexpr right delegation_right = right::grant;

} // namespace meta_auth

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
template <>
struct std::formatter<meta_auth::right, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(meta_auth::right value, std::format_context& context) const {
        return std::format_to(context.out(), "{}", meta_auth::to_string(value));
    }
};

template <>
struct std::formatter<meta_auth::rights_set, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(const meta_auth::rights_set& value, std::format_context& context) const {
        std::array<char, 128> buffer{};
        return std::format_to(context.out(), "{}", value.write_to(buffer));
    }
};

#endif // META_AUTH_CAPABILITY_RIGHTS_HPP
