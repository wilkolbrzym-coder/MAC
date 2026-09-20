// ===========================================================================
//  meta-auth-core -- phantom-typed identifiers.
//
//  A principal, a device and a capability are all "a number" to a compiler,
//  and passing one where another was meant is a defect that no amount of
//  careful reading reliably catches -- least of all in a diff. `strong_id`
//  makes the tag part of the type, so mixing them is an error, and the error
//  arrives at the call site rather than at the authorisation decision.
//
//  The type carries no run-time overhead: it is a single integer with a tag
//  that exists only for the type system, so `sizeof(strong_id<Tag>)` equals
//  `sizeof(std::uint64_t)` and every operation is constexpr.
// ===========================================================================
#ifndef META_AUTH_CORE_STRONG_ID_HPP
#define META_AUTH_CORE_STRONG_ID_HPP

#include "meta_auth/config.hpp"

#include <compare>
#include <cstdint>
#include <format>
#include <string_view>

#if META_AUTH_HAS_REFLECTION
#include <meta>
#endif

namespace meta_auth {

/// An identifier that cannot be confused with an identifier of another kind.
///
/// `Tag` is an incomplete type used only for its identity; `Rep` is the
/// representation, defaulting to a 64-bit unsigned integer, which is what the
/// audit trail and the capability tables store.
template <typename Tag, typename Rep = std::uint64_t>
class strong_id {
public:
    using tag_type = Tag;
    using rep_type = Rep;

    /// The representation reserved for "no identifier". Zero rather than a
    /// separate validity flag, so that a zero-initialised identifier is
    /// invalid everywhere without a per-type decision about what invalid
    /// means.
    static constexpr Rep invalid_value = 0;

    constexpr strong_id() noexcept = default;

    /// Construct from a raw value. Explicit: an identifier arriving from a
    /// wire format or a test needs a deliberate conversion, and that is the
    /// point at which its provenance should be visible in the source.
    [[nodiscard]] static constexpr auto from_value(Rep value) noexcept -> strong_id {
        return strong_id{value};
    }

    /// The reserved invalid identifier.
    [[nodiscard]] static constexpr auto invalid() noexcept -> strong_id { return strong_id{}; }

    [[nodiscard]] constexpr auto value() const noexcept -> Rep { return value_; }

    [[nodiscard]] constexpr auto is_valid() const noexcept -> bool { return value_ != invalid_value; }

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return is_valid(); }

    friend constexpr auto operator==(strong_id, strong_id) noexcept -> bool = default;

    /// Ordering, so that identifiers can key a sorted container. Only
    /// same-tagged identifiers compare, which is what makes a heterogeneous
    /// container of identifiers impossible to build by accident.
    friend constexpr auto operator<=>(strong_id, strong_id) noexcept
        -> std::strong_ordering = default;

private:
    explicit constexpr strong_id(Rep value) noexcept : value_(value) {}

    Rep value_ = invalid_value;
};

namespace detail {

/// The fallback name of a tag: reflection when the build has it, so that a
/// failure report says "device_tag#7" rather than "strong_id#7", which is the
/// difference between a report that identifies the value and one that
/// identifies only the type.
template <typename Tag>
[[nodiscard]] consteval auto reflected_tag_name() noexcept -> std::string_view {
#if META_AUTH_HAS_REFLECTION
    return std::meta::has_identifier(^^Tag) ? std::meta::identifier_of(^^Tag)
                                            : std::meta::display_string_of(^^Tag);
#else
    return "id";
#endif
}

/// Resolve a tag's name.
///
/// `if constexpr` rather than a ternary: a tag that does not override the name
/// is often an incomplete type, and the false branch of a ternary is still
/// instantiated, which turns "this tag has no name of its own" into an error
/// about an incomplete type.
template <typename Tag>
[[nodiscard]] consteval auto resolved_tag_name() noexcept -> std::string_view {
    if constexpr (requires { Tag::tag_name; }) {
        return std::string_view{Tag::tag_name};
    } else {
        return reflected_tag_name<Tag>();
    }
}

} // namespace detail

/// The name of an identifier's tag, for diagnostics.
///
/// A tag may override it by declaring `static constexpr std::string_view
/// tag_name`, which is how a tag parameterised by a name -- a principal, a
/// resource -- renders as the name it stands for rather than as the name of
/// the template that produced it.
template <typename Tag>
inline constexpr std::string_view tag_name = detail::resolved_tag_name<Tag>();

} // namespace meta_auth

// ---------------------------------------------------------------------------
// Formatting: tag and value, so that a log line is unambiguous about which
// kind of identifier it carries.
// ---------------------------------------------------------------------------
template <typename Tag, typename Rep>
struct std::formatter<meta_auth::strong_id<Tag, Rep>, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(const meta_auth::strong_id<Tag, Rep>& identifier,
                std::format_context& context) const {
        if (!identifier.is_valid()) {
            return std::format_to(context.out(), "{}#invalid", meta_auth::tag_name<Tag>);
        }
        return std::format_to(context.out(), "{}#{}", meta_auth::tag_name<Tag>,
                              identifier.value());
    }
};

#endif // META_AUTH_CORE_STRONG_ID_HPP
