// ===========================================================================
//  Tests of capabilities and authorities.
//
//  Division of labour with the compile-failure suite, stated so that a reader
//  knows where to look: everything a *program that should compile* must do is
//  checked here, and everything a program must be *refused* is checked by
//  tests/compile_fail/, which compiles the offending program and inspects the
//  diagnostic. A test file that only checked the positive half would pass for
//  an implementation that permitted everything.
//
//  The properties asserted here are the ones the model rests on:
//
//    * minting grants exactly what was asked for, never more;
//    * a capability's rights are a compile-time constant, checked with
//      `static_assert` rather than at run time;
//    * attenuation and delegation preserve provenance, so an audit record can
//      name the capability and the one it came from;
//    * serials are unique per resource type, which is what makes an audit
//      trail unambiguous;
//    * moving neutralises the source, so two capabilities never claim one
//      serial.
// ===========================================================================
#include "meta_auth/capability/capability.hpp"
#include "test_framework.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

using meta_auth::authority;
using meta_auth::capability;
using meta_auth::named_resource;
using meta_auth::resource_name;
using meta_auth::revocation_epoch;
using meta_auth::right;
using meta_auth::rights_set;

using device_resource = named_resource<"devices">;
using session_resource = named_resource<"sessions">;
using audit_resource = named_resource<"audit-log">;

/// A resource no other test uses, so that its serial counter is observably at
/// its origin. A local class cannot carry static data members, hence its
/// placement here.
struct fresh_resource {
    static constexpr std::string_view name = "fresh";
};

constexpr rights_set read_only{right::read};
constexpr rights_set read_write{right::read, right::write};
constexpr rights_set everything = rights_set::all();
constexpr rights_set read_and_grant{right::read, right::grant};
constexpr rights_set write_and_grant{right::write, right::grant};
constexpr rights_set write_only{right::write};
constexpr rights_set grant_only{right::grant};
constexpr rights_set read_write_grant{right::read, right::write, right::grant};

/// A helper that turns a compile-time pair of sets into a run-time observation
/// of what attenuation produced. The `requires` clause on `attenuate` is the
/// real check; this exists so that the *result* is asserted as well.
template <rights_set Held, rights_set Requested>
    requires(Requested.is_subset_of(Held))
[[nodiscard]] constexpr auto attenuate_and_report() noexcept -> rights_set {
    authority<device_resource, Held> source;
    auto strong = source.template mint_consteval<Held>();
    auto weak = std::move(strong).template attenuate<Requested>();
    return weak.rights_value();
}

} // namespace

// ---------------------------------------------------------------------------
// Compile-time properties
// ---------------------------------------------------------------------------

/// Resources name themselves, and two resources are two types.
static_assert(resource_name<device_resource>() == "devices");
static_assert(resource_name<session_resource>() == "sessions");
static_assert(!std::is_same_v<device_resource, session_resource>);
static_assert(device_resource::identifier() != session_resource::identifier());
static_assert(device_resource::identifier() == meta_auth::hash_name(meta_auth::fixed_string{"devices"}));

/// Rights are part of the capability's type, so the question "does this
/// capability grant write?" is answered by the compiler.
static_assert(capability<device_resource, read_write>::rights == read_write);
static_assert(capability<device_resource, read_write>::template grants<read_only>());
static_assert(!capability<device_resource, read_only>::template grants<read_write>());
static_assert(capability<device_resource, everything>::template grants<everything>());
static_assert(capability<device_resource, read_only>::template grants<rights_set{}>());

/// Attenuation is a *type* change, and the result carries exactly the
/// requested rights -- verified for every subset of a held set that has 3
/// atoms, which is the whole sublattice rather than a sample.
static_assert(attenuate_and_report<everything, read_only>() == read_only);
static_assert(attenuate_and_report<everything, read_write>() == read_write);
static_assert(attenuate_and_report<read_write, read_only>() == read_only);
static_assert(attenuate_and_report<rights_set{right::read, right::write, right::execute},
                                   rights_set{right::write, right::execute}>()
              == rights_set{right::write, right::execute});

/// Capabilities are affine.
static_assert(!std::is_copy_constructible_v<capability<device_resource, read_only>>);
static_assert(!std::is_copy_assignable_v<capability<device_resource, read_only>>);
static_assert(std::is_move_constructible_v<capability<device_resource, read_only>>);
static_assert(std::is_move_assignable_v<capability<device_resource, read_only>>);
static_assert(std::is_nothrow_move_constructible_v<capability<device_resource, read_only>>);

/// Two capabilities over different resources, or with different rights, are
/// different types. This is what makes a mix-up a compile error.
static_assert(!std::is_same_v<capability<device_resource, read_only>,
                              capability<session_resource, read_only>>);
static_assert(!std::is_same_v<capability<device_resource, read_only>,
                              capability<device_resource, read_write>>);

// ---------------------------------------------------------------------------
// Minting
// ---------------------------------------------------------------------------
META_AUTH_TEST("capability", "mint_grants_exactly_what_was_requested") {
    authority<device_resource, everything> root;

    auto read_capability = root.mint<read_only>();
    META_AUTH_CHECK_EQ(read_capability.rights_value(), read_only);
    META_AUTH_CHECK(read_capability.has(right::read));
    META_AUTH_CHECK(!read_capability.has(right::write));

    auto all_capability = root.mint<everything>();
    META_AUTH_CHECK_EQ(all_capability.rights_value(), everything);
    META_AUTH_CHECK_EQ(all_capability.rights_value().size(), meta_auth::right_count);
}

META_AUTH_TEST("capability", "a_restricted_authority_mints_only_within_its_range") {
    authority<device_resource, everything> root;
    const auto narrow = root.restrict<read_only>();

    auto minted = narrow.mint<read_only>();
    META_AUTH_CHECK_EQ(minted.rights_value(), read_only);
    // Minting more than the restricted authority holds is a compile error,
    // asserted by tests/compile_fail/authority_mint_beyond_max.cpp.
}

META_AUTH_TEST("capability", "serials_are_unique_per_resource") {
    authority<device_resource, read_only> device_authority;
    authority<session_resource, read_only> session_authority;

    std::vector<std::uint64_t> serials;
    for (int index = 0; index < 64; ++index) {
        serials.push_back(device_authority.mint<read_only>().serial());
    }

    // Uniqueness is what makes an audit record able to name the exact
    // capability that was used rather than a class of them.
    for (std::size_t lhs = 0; lhs < serials.size(); ++lhs) {
        META_AUTH_CHECK_NE(serials[lhs], std::uint64_t{0});
        for (std::size_t rhs = lhs + 1; rhs < serials.size(); ++rhs) {
            META_AUTH_CHECK_NE(serials[lhs], serials[rhs]);
        }
    }

    // Counters are per resource type, so the two authorities do not share a
    // sequence -- which is what lets a serial be interpreted without also
    // knowing the resource.
    //
    // The claim is an *independence* claim, and the previous version of this
    // test could not see it: `device_serial >= 64` and `session_serial >= 1`
    // are both satisfied by one global counter, so the test passed for an
    // implementation that shared a sequence -- which is the defect it exists
    // to catch. A resource type used nowhere else is what makes a counter's
    // origin observable: its first mint carries serial one however much
    // minting has happened for other resources.
    authority<fresh_resource, read_only> fresh_authority;
    META_AUTH_CHECK_EQ(fresh_authority.mint<read_only>().serial(), std::uint64_t{1});

    // Minting for one resource does not disturb another's sequence.
    const auto device_before = device_authority.mint<read_only>().serial();
    static_cast<void>(session_authority.mint<read_only>());
    const auto device_after = device_authority.mint<read_only>().serial();
    META_AUTH_CHECK_EQ(device_after, device_before + 1U);
}

/// The compile-time entry point reserves serial zero, which is what makes it
/// distinguishable from every run-time capability.
consteval auto compile_time_serial() noexcept -> std::uint64_t {
    authority<device_resource, read_only> root;
    return root.mint_consteval<read_only>().serial();
}

static_assert(compile_time_serial() == 0);

META_AUTH_TEST("capability", "a_const_initialised_mint_still_allocates_a_serial") {
    // Regression test for the trap documented in capability.hpp. An
    // implementation that branches on `if consteval` inside `mint` is
    // constant-folded here -- `const auto` is the trigger -- and returns the
    // compile-time placeholder instead of allocating. The assertion is
    // therefore not about the value but about which of the two contexts ran.
    authority<device_resource, read_only> root;

    const auto first = root.mint<read_only>();
    const auto second = root.mint<read_only>();

    META_AUTH_CHECK_NE(first.serial(), std::uint64_t{0});
    META_AUTH_CHECK_EQ(second.serial(), first.serial() + 1U);
    META_AUTH_CHECK_EQ(compile_time_serial(), std::uint64_t{0});
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------
META_AUTH_TEST("capability", "a_minted_capability_has_no_parent") {
    authority<device_resource, read_only> root;
    const auto minted = root.mint<read_only>();
    META_AUTH_CHECK(!minted.parent_serial().has_value());
}

META_AUTH_TEST("capability", "attenuation_preserves_provenance_and_serial") {
    authority<device_resource, everything> root;
    auto strong = root.mint<everything>();
    const std::uint64_t original_serial = strong.serial();

    auto weak = std::move(strong).attenuate<read_only>();

    META_AUTH_CHECK_EQ(weak.rights_value(), read_only);
    // The serial is inherited: attenuation is the same authority, weakened,
    // not a new grant of authority. The audit trail depends on that reading.
    META_AUTH_CHECK_EQ(weak.serial(), original_serial);
    META_AUTH_REQUIRE(weak.parent_serial().has_value());
    META_AUTH_CHECK_EQ(*weak.parent_serial(), original_serial);
}

META_AUTH_TEST("capability", "attenuation_consumes_the_capability_it_weakened") {
    // The difference between attenuation and delegation is that one consumes
    // and the other does not. It did not: `std::move(strong).attenuate<...>()`
    // left `strong` fully usable, so any capability could be duplicated
    // without `grant` -- and the documentation promised that duplication
    // requires delegation.
    authority<device_resource, everything> root;
    auto strong = root.mint<everything>();

    auto weak = std::move(strong).attenuate<read_only>();

    META_AUTH_CHECK(weak.is_valid());
    META_AUTH_CHECK(weak.has(right::read));

    META_AUTH_CHECK(!strong.is_valid());
    META_AUTH_CHECK_EQ(strong.serial(), std::uint64_t{0});
    // `has` answers from the object's state, so a spent capability holds
    // nothing -- not even the rights its type still names. Without this the
    // type would keep granting what the value has already given away.
    META_AUTH_CHECK(!strong.has(right::read));
    META_AUTH_CHECK(!strong.has(right::revoke));
}

META_AUTH_TEST("capability", "a_neutralised_capability_is_not_live") {
    // Liveness is asked before every admission, and a spent capability is not
    // live even in an epoch where nothing has been revoked -- the distinction
    // between "still current" and "still a capability" has to survive the
    // epoch check, or a revoked-capability test would be the only thing
    // catching a spent one.
    authority<device_resource, read_only> root;
    auto original = root.mint<read_only>();

    META_AUTH_CHECK(original.is_live());
    auto moved = std::move(original);
    META_AUTH_CHECK(moved.is_live());
    META_AUTH_CHECK(!original.is_live());
}

META_AUTH_TEST("capability", "delegation_does_not_consume_the_delegator") {
    // The other half of the pair: delegation leaves the delegator usable,
    // which is the whole reason it requires `grant`.
    authority<device_resource, read_and_grant> root;
    auto delegator = root.mint<read_and_grant>();

    auto handed_out = delegator.delegate<read_only>();

    META_AUTH_CHECK(delegator.is_valid());
    META_AUTH_CHECK(delegator.has(right::read));
    META_AUTH_CHECK(delegator.has(right::grant));
    META_AUTH_CHECK(handed_out.is_valid());
    META_AUTH_CHECK(handed_out.has(right::read));
}

META_AUTH_TEST("capability", "delegation_preserves_provenance_and_leaves_the_original_intact") {
    authority<device_resource, everything> root;
    const auto strong = root.mint<everything>();
    const std::uint64_t original_serial = strong.serial();

    const auto handed_out = strong.delegate<read_only>();

    // The delegator keeps its capability, and the delegatee gets a weaker one
    // that records where it came from.
    META_AUTH_CHECK_EQ(strong.rights_value(), everything);
    META_AUTH_CHECK_EQ(handed_out.rights_value(), read_only);
    META_AUTH_CHECK_EQ(handed_out.serial(), original_serial);
    META_AUTH_REQUIRE(handed_out.parent_serial().has_value());
    META_AUTH_CHECK_EQ(*handed_out.parent_serial(), original_serial);
}

META_AUTH_TEST("capability", "a_chain_of_attenuations_keeps_the_original_serial") {
    authority<device_resource, everything> root;
    auto level0 = root.mint<everything>();
    const std::uint64_t root_serial = level0.serial();

    auto level1 = std::move(level0).attenuate<rights_set{right::read, right::write, right::grant}>();
    auto level2 = std::move(level1).attenuate<rights_set{right::read, right::grant}>();
    auto level3 = std::move(level2).attenuate<read_only>();

    META_AUTH_CHECK_EQ(level3.rights_value(), read_only);
    // Every step points at the same origin, so provenance does not decay into
    // "derived from something".
    META_AUTH_CHECK_EQ(level3.serial(), root_serial);
    META_AUTH_REQUIRE(level3.parent_serial().has_value());
    META_AUTH_CHECK_EQ(*level3.parent_serial(), root_serial);
}

// ---------------------------------------------------------------------------
// Move semantics
// ---------------------------------------------------------------------------
META_AUTH_TEST("capability", "moving_neutralises_the_source") {
    authority<device_resource, read_only> root;
    auto original = root.mint<read_only>();
    const std::uint64_t serial = original.serial();

    auto moved = std::move(original);

    META_AUTH_CHECK_EQ(moved.serial(), serial);
    // Two capabilities claiming one serial would make an audit trail ambiguous
    // exactly where it matters, so the moved-from object gives its serial up.
    META_AUTH_CHECK_EQ(original.serial(), std::uint64_t{0});
    META_AUTH_CHECK(!original.parent_serial().has_value());
}

META_AUTH_TEST("capability", "move_assignment_transfers_and_neutralises") {
    authority<device_resource, read_only> root;
    auto first = root.mint<read_only>();
    auto second = root.mint<read_only>();
    const std::uint64_t first_serial = first.serial();

    second = std::move(first);

    META_AUTH_CHECK_EQ(second.serial(), first_serial);
    META_AUTH_CHECK_EQ(first.serial(), std::uint64_t{0});
}

META_AUTH_TEST("capability", "self_move_assignment_is_harmless") {
    // Not a recommended operation, but it must not corrupt the object: a
    // self-move that zeroed the serial would leave a capability that cannot be
    // found in the audit trail.
    authority<device_resource, read_only> root;
    auto value = root.mint<read_only>();
    const std::uint64_t serial = value.serial();

    auto& reference = value;
    value = std::move(reference);

    META_AUTH_CHECK_EQ(value.serial(), serial);
}

// ---------------------------------------------------------------------------
// Epoch binding at mint
// ---------------------------------------------------------------------------
META_AUTH_TEST("capability", "a_minted_capability_records_the_current_epoch") {
    const revocation_epoch before = meta_auth::current_epoch<audit_resource>();
    authority<audit_resource, read_only> root;
    const auto minted = root.mint<read_only>();

    META_AUTH_CHECK_EQ(minted.epoch(), before);
    META_AUTH_CHECK(minted.is_live());
}

META_AUTH_TEST("capability", "a_capability_minted_after_a_revocation_is_live") {
    static_cast<void>(meta_auth::revoke_all<audit_resource>());

    authority<audit_resource, read_only> root;
    const auto minted = root.mint<read_only>();

    META_AUTH_CHECK(minted.is_live());
    META_AUTH_CHECK(!minted.epoch().is_initial());
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
META_AUTH_TEST("capability", "renders_resource_rights_serial_and_epoch") {
    authority<device_resource, read_only> root;
    const auto minted = root.mint<read_only>();
    const std::string rendered = std::format("{}", minted);

    META_AUTH_CHECK(rendered.find("capability<devices>") != std::string::npos);
    META_AUTH_CHECK(rendered.find("read") != std::string::npos);
    META_AUTH_CHECK(rendered.find(std::to_string(minted.serial())) != std::string::npos);
}

META_AUTH_TEST("capability", "the_harness_can_render_a_capability_in_a_report") {
    authority<device_resource, everything> root;
    const auto minted = root.mint<everything>();
    const std::string rendered = meta_auth::test::stringify(minted);
    META_AUTH_CHECK(rendered.find("capability<devices>") != std::string::npos);
}

// ---------------------------------------------------------------------------
// The law that makes delegation safe
// ---------------------------------------------------------------------------
META_AUTH_TEST("capability", "delegation_reduces_rights_for_every_subset") {
    // Exhaustive over the lattice: for every held set that includes `grant`,
    // every subset can be delegated, and the result grants exactly that
    // subset. This is the property that makes "authority is monotonically
    // non-increasing along a delegation chain" true rather than hopeful.
    // Named constants rather than brace lists in the template arguments: a
    // comma inside `delegate<rights_set{a, b}>()` would be read as an argument
    // separator by the CHECK_EQ macro, which is a defect the compiler reports
    // at the macro rather than at the template.
    constexpr rights_set delegable = read_write_grant;
    authority<device_resource, delegable> root;
    const auto holder = root.mint<delegable>();

    META_AUTH_CHECK_EQ(holder.delegate<rights_set{}>().rights_value(), rights_set::none());
    META_AUTH_CHECK_EQ(holder.delegate<read_only>().rights_value(), read_only);
    META_AUTH_CHECK_EQ(holder.delegate<write_only>().rights_value(), write_only);
    META_AUTH_CHECK_EQ(holder.delegate<grant_only>().rights_value(), grant_only);
    META_AUTH_CHECK_EQ(holder.delegate<delegable>().rights_value(), delegable);
    META_AUTH_CHECK_EQ(holder.delegate<read_and_grant>().rights_value(), read_and_grant);
    META_AUTH_CHECK_EQ(holder.delegate<write_and_grant>().rights_value(), write_and_grant);
    META_AUTH_CHECK_EQ(holder.delegate<read_write>().rights_value(), read_write);

    // Delegating cannot produce a set that is not a subset of the held one.
    for (std::uint32_t bits = 0; bits <= meta_auth::all_right_bits; ++bits) {
        const rights_set candidate{static_cast<right>(bits)};
        if (candidate.is_subset_of(delegable)) {
            META_AUTH_CHECK(candidate.is_subset_of(holder.rights_value()));
        }
    }
}
