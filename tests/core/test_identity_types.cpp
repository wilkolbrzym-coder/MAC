// ===========================================================================
//  Tests of the structural-string and phantom-identifier layers.
//
//  Both types exist to make mistakes impossible, so most of what they
//  guarantee is checked by the compiler: the tests here assert the positive
//  behaviour (what the types do) and the compile-failure suite asserts the
//  negative (what they refuse). A test file that only checked the positive
//  half would pass for a type that permitted everything.
// ===========================================================================
#include "meta_auth/core/fixed_string.hpp"
#include "meta_auth/core/strong_id.hpp"
#include "test_framework.hpp"

#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <type_traits>

namespace {

// Tags for the identifier tests. Incomplete types: an identifier's tag is
// never instantiated, which is what keeps the abstraction free at run time.
struct principal_tag;
struct device_tag;

using principal_id = meta_auth::strong_id<principal_tag>;
using device_id = meta_auth::strong_id<device_tag>;
using narrow_id = meta_auth::strong_id<device_tag, std::uint32_t>;

} // namespace

// ---------------------------------------------------------------------------
// Compile-time properties
// ---------------------------------------------------------------------------

/// The whole point of `fixed_string` is being usable as a template argument,
/// so that a resource name is part of a type rather than a value.
template <meta_auth::fixed_string Name>
[[nodiscard]] constexpr auto name_length() noexcept -> std::size_t {
    return Name.size();
}

static_assert(name_length<"devices">() == 7);
static_assert(name_length<"">() == 0);

static_assert(meta_auth::fixed_string{"admin"}.size() == 5);
static_assert(meta_auth::fixed_string{"admin"}.view() == "admin");
static_assert(meta_auth::fixed_string{"admin"}[0] == 'a');
static_assert(meta_auth::fixed_string{"admin"}[99] == '\0');
static_assert(meta_auth::fixed_string{""}.empty());

static_assert(meta_auth::fixed_string{"devices"} == meta_auth::fixed_string{"devices"});
static_assert(meta_auth::fixed_string{"devices"} != meta_auth::fixed_string{"device"});

static_assert(meta_auth::concat(meta_auth::fixed_string{"device"}, meta_auth::fixed_string{":"})
                  == meta_auth::fixed_string{"device:"});
static_assert(meta_auth::concat(meta_auth::fixed_string{""}, meta_auth::fixed_string{"x"})
              == meta_auth::fixed_string{"x"});

static_assert(meta_auth::fixed_string{"device.enroll"}.starts_with("device."));
static_assert(meta_auth::fixed_string{"device.enroll"}.ends_with(".enroll"));
static_assert(meta_auth::fixed_string{"device.enroll"}.contains("."));
static_assert(!meta_auth::fixed_string{"device.enroll"}.contains("/"));

static_assert(meta_auth::equals_ignore_ascii_case("Device", "DEVICE"));
static_assert(!meta_auth::equals_ignore_ascii_case("Device", "Devices"));
static_assert(meta_auth::lower_ascii('A') == 'a');
static_assert(meta_auth::lower_ascii('a') == 'a');
static_assert(meta_auth::lower_ascii('7') == '7');
static_assert(meta_auth::lower_ascii('[') == '[');

static_assert(meta_auth::fnv1a_64::hash("") == meta_auth::fnv1a_64::offset_basis);
static_assert(meta_auth::hash_name(meta_auth::fixed_string{"devices"})
              != meta_auth::hash_name(meta_auth::fixed_string{"device"}));

/// Identifiers carry no run-time cost. Asserted rather than assumed, because
/// the abstraction is only free if the tag stays out of the layout.
static_assert(sizeof(principal_id) == sizeof(std::uint64_t));
static_assert(sizeof(narrow_id) == sizeof(std::uint32_t));
static_assert(std::is_trivially_copyable_v<principal_id>);
static_assert(std::is_standard_layout_v<principal_id>);

/// A default-constructed identifier is invalid, and zero is what makes it so.
static_assert(!principal_id{}.is_valid());
static_assert(principal_id{}.value() == principal_id::invalid_value);
static_assert(principal_id::from_value(7).is_valid());

/// Comparison and ordering are available, and are defaulted rather than
/// hand-written, so they cannot drift from the representation.
static_assert(principal_id::from_value(7) == principal_id::from_value(7));
static_assert(principal_id::from_value(7) != principal_id::from_value(8));
static_assert(principal_id::from_value(7) < principal_id::from_value(8));

/// Distinct tags produce distinct types. This is the property the compile-fail
/// suite exercises from the other side, by trying to mix them.
static_assert(!std::is_same_v<principal_id, device_id>);
static_assert(!std::is_convertible_v<principal_id, device_id>);
static_assert(!std::is_constructible_v<device_id, principal_id>);

/// No implicit conversion from the representation: an identifier must be
/// built deliberately, at a point where its provenance is visible.
static_assert(!std::is_convertible_v<std::uint64_t, principal_id>);
static_assert(!std::is_constructible_v<principal_id, std::uint64_t>);

// ---------------------------------------------------------------------------
// Runtime behaviour
// ---------------------------------------------------------------------------
META_AUTH_TEST("fixed_string", "renders_as_its_text") {
    META_AUTH_CHECK_EQ(std::format("{}", meta_auth::fixed_string{"devices"}),
                       std::string{"devices"});
    META_AUTH_CHECK_EQ(std::format("{}", meta_auth::fixed_string{""}), std::string{""});
}

META_AUTH_TEST("fixed_string", "conversion_to_string_view") {
    constexpr meta_auth::fixed_string name{"device.enroll"};
    const std::string_view view = name;
    META_AUTH_CHECK_EQ(view, std::string_view{"device.enroll"});
    META_AUTH_CHECK_EQ(std::string_view{name.c_str()}, view);
}

META_AUTH_TEST("fixed_string", "hash_is_stable_and_distinguishes") {
    // Stability matters: a hash written into an audit record by one build has
    // to mean the same thing to the next one.
    constexpr auto devices = meta_auth::hash_name(meta_auth::fixed_string{"devices"});
    META_AUTH_CHECK_EQ(meta_auth::hash_name(meta_auth::fixed_string{"devices"}), devices);
    META_AUTH_CHECK_NE(meta_auth::hash_name(meta_auth::fixed_string{"devices"}),
                       meta_auth::hash_name(meta_auth::fixed_string{"sessions"}));
    META_AUTH_CHECK_NE(devices, meta_auth::fnv1a_64::offset_basis);
}

META_AUTH_TEST("strong_id", "validity_follows_from_the_value") {
    constexpr principal_id missing;
    constexpr principal_id present = principal_id::from_value(42);

    META_AUTH_CHECK(!missing.is_valid());
    META_AUTH_CHECK(present.is_valid());
    META_AUTH_CHECK_EQ(present.value(), std::uint64_t{42});
    // `explicit operator bool` means an identifier can be tested directly but
    // never converts to an integer by accident.
    META_AUTH_CHECK(present ? true : false);
}

META_AUTH_TEST("strong_id", "the_invalid_value_is_the_named_constant") {
    META_AUTH_CHECK(!principal_id::invalid().is_valid());
    META_AUTH_CHECK_EQ(principal_id::invalid_value, std::uint64_t{0});
}

META_AUTH_TEST("strong_id", "renders_tag_and_value") {
    // The rendering names the tag, which is what makes a heterogeneous log
    // readable: "device#7" cannot be mistaken for "principal#7".
    const std::string rendered = meta_auth::test::stringify(device_id::from_value(7));
    META_AUTH_CHECK(rendered.find("#7") != std::string::npos);
#if META_AUTH_HAS_REFLECTION
    META_AUTH_CHECK(rendered.find("device_tag") != std::string::npos);
#endif
    const std::string invalid = meta_auth::test::stringify(device_id{});
    META_AUTH_CHECK(invalid.find("invalid") != std::string::npos);
}

META_AUTH_TEST("strong_id", "identifiers_are_usable_as_keys") {
    // Ordered comparison exists so that identifiers can key a sorted
    // container; without it the capability tables would need a hash.
    META_AUTH_CHECK(device_id::from_value(1) < device_id::from_value(2));
    META_AUTH_CHECK(device_id::from_value(2) > device_id::from_value(1));
    META_AUTH_CHECK(device_id::from_value(2) <= device_id::from_value(2));
    META_AUTH_CHECK_EQ(device_id::from_value(2) <=> device_id::from_value(2),
                       std::strong_ordering::equal);
}
