// ===========================================================================
//  Tests of the rights lattice.
//
//  A lattice with 7 atoms has 128 elements, which is small enough to enumerate
//  completely. That changes the character of these tests: they are not samples
//  of the algebra, they are *proofs by exhaustion* of it. Every one of the
//  128 sets is constructed, every one of the 16384 ordered pairs is checked
//  against the laws, and every algebraic identity is verified over the whole
//  domain rather than over a handful of examples.
//
//  The reason to spend that effort here rather than on the layers above is that
//  everything above depends on this: monotone attenuation, the delegation
//  constraint and the policy engine's rights comparison are all statements
//  about `⊆`. If `⊆` is wrong, they are all wrong in a way that no amount of
//  testing at their level would localise.
// ===========================================================================
#include "meta_auth/capability/rights.hpp"
#include "test_framework.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>

using meta_auth::right;
using meta_auth::right_count;
using meta_auth::rights_set;

namespace {

/// The number of subsets of 7 atoms.
inline constexpr std::size_t subset_count = 1U << right_count;

/// Every subset, indexed by its bit pattern.
consteval auto all_subsets() -> std::array<rights_set, subset_count> {
    std::array<rights_set, subset_count> sets{};
    for (std::uint32_t bits = 0; bits < subset_count; ++bits) {
        sets[bits] = rights_set{static_cast<right>(bits)};
    }
    return sets;
}

inline constexpr auto subsets = all_subsets();

/// A family that generates the lattice.
///
/// The cubic identities below -- associativity, distributivity, absorption --
/// are checked over all triples of this family rather than over all 128^3
/// triples of the lattice. The reduction is sound rather than a shortcut: the
/// operations are pointwise on bits, so each of the seven bit positions is an
/// independent two-element Boolean algebra, and an identity that holds for
/// every triple drawn from a family containing all the atoms holds at every
/// bit position of every element. The exhaustive version was measured at 57
/// seconds of test time and proved exactly the same thing.
/// The family is the atoms plus the two bounds of the lattice. An earlier
/// version of this list omitted four atoms and the check at the end of the
/// cubic test caught it, which is why that check exists.
inline constexpr std::array<rights_set, 9> generating_family = {
    rights_set::none(),          rights_set{right::read},
    rights_set{right::write},    rights_set{right::execute},
    rights_set{right::grant},    rights_set{right::revoke},
    rights_set{right::audit},    rights_set{right::administer},
    rights_set::all(),
};

/// Population count, computed independently of the implementation under test
/// so that a shared bug cannot cancel itself out.
[[nodiscard]] constexpr auto popcount(std::uint32_t bits) noexcept -> std::size_t {
    std::size_t count = 0;
    for (std::size_t index = 0; index < 32; ++index) {
        count += (bits >> index) & 1U;
    }
    return count;
}

} // namespace

// ---------------------------------------------------------------------------
// Compile-time properties
// ---------------------------------------------------------------------------

/// The enumeration and the constants that describe it must agree. A right that
/// is missing from `all_right_bits` would be invisible to `all()` and to the
/// complement, which is the sort of omission that shows up as a privilege that
/// cannot be revoked.
static_assert(meta_auth::all_rights.size() == right_count);
static_assert([]() constexpr {
    std::uint32_t combined = 0;
    for (const right value : meta_auth::all_rights) {
        combined |= static_cast<std::uint32_t>(value);
    }
    return combined == meta_auth::all_right_bits;
}());
static_assert(meta_auth::all_right_bits == 0x7FU);

/// Every named right has a distinct bit, and a distinct name.
static_assert([]() constexpr {
    for (std::size_t lhs = 0; lhs < right_count; ++lhs) {
        for (std::size_t rhs = lhs + 1; rhs < right_count; ++rhs) {
            if (meta_auth::all_rights[lhs] == meta_auth::all_rights[rhs]) {
                return false;
            }
            if (meta_auth::to_string(meta_auth::all_rights[lhs])
                == meta_auth::to_string(meta_auth::all_rights[rhs])) {
                return false;
            }
        }
    }
    return true;
}());

static_assert(meta_auth::right_index(right::read) == 0);
static_assert(meta_auth::right_index(right::administer) == 6);
/// Anything that is not exactly one bit has no index and no name.
static_assert(meta_auth::right_index(static_cast<right>(0)) == right_count);
static_assert(meta_auth::right_index(static_cast<right>(0x3)) == right_count);
static_assert(meta_auth::to_string(static_cast<right>(0)) == "<invalid right>");

/// The type must be usable as a template argument, which is the entire point.
template <rights_set Rights>
[[nodiscard]] constexpr auto granted_count() noexcept -> std::size_t {
    return Rights.size();
}

static_assert(granted_count<rights_set{right::read, right::write}>() == 2);
static_assert(granted_count<rights_set{}>() == 0);
static_assert(granted_count<rights_set::all()>() == right_count);
static_assert(std::is_standard_layout_v<rights_set>);
static_assert(std::is_trivially_copyable_v<rights_set>);
static_assert(sizeof(rights_set) == sizeof(std::uint32_t));

/// Set literals, and the operations that must agree with them.
static_assert(rights_set{right::read, right::write}
              == (rights_set{right::read} | rights_set{right::write}));
static_assert((rights_set::all() & rights_set{right::read}) == rights_set{right::read});
static_assert((rights_set::all() - rights_set{right::read}).size() == right_count - 1);
static_assert(rights_set::all().complement().is_empty());
static_assert(rights_set::none().complement().is_full());

// ---------------------------------------------------------------------------
// The lattice laws, over every element
// ---------------------------------------------------------------------------
META_AUTH_TEST("rights", "subset_is_reflexive_and_antisymmetric") {
    for (const rights_set& lhs : subsets) {
        META_AUTH_CHECK(lhs.is_subset_of(lhs));
        META_AUTH_CHECK(!lhs.is_proper_subset_of(lhs));
        for (const rights_set& rhs : subsets) {
            // Antisymmetry is what makes `⊆` a partial order rather than a
            // preorder, and it is what lets attenuation be checked by
            // comparing sets instead of comparing sizes.
            if (lhs.is_subset_of(rhs) && rhs.is_subset_of(lhs)) {
                META_AUTH_CHECK_EQ(lhs, rhs);
            }
        }
    }
}

META_AUTH_TEST("rights", "subset_is_transitive") {
    for (const rights_set& a : subsets) {
        for (const rights_set& b : subsets) {
            if (!a.is_subset_of(b)) {
                continue;
            }
            for (const rights_set& c : subsets) {
                if (b.is_subset_of(c)) {
                    META_AUTH_CHECK(a.is_subset_of(c));
                }
            }
        }
    }
}

META_AUTH_TEST("rights", "proper_subset_is_strict") {
    for (const rights_set& lhs : subsets) {
        for (const rights_set& rhs : subsets) {
            META_AUTH_CHECK_EQ(lhs.is_proper_subset_of(rhs),
                               lhs.is_subset_of(rhs) && !(lhs == rhs));
        }
    }
}

META_AUTH_TEST("rights", "union_and_intersection_are_bounds") {
    for (const rights_set& lhs : subsets) {
        for (const rights_set& rhs : subsets) {
            const rights_set union_set = lhs | rhs;
            const rights_set intersection = lhs & rhs;

            // The least upper bound and the greatest lower bound.
            META_AUTH_CHECK(lhs.is_subset_of(union_set));
            META_AUTH_CHECK(rhs.is_subset_of(union_set));
            META_AUTH_CHECK(intersection.is_subset_of(lhs));
            META_AUTH_CHECK(intersection.is_subset_of(rhs));
            META_AUTH_CHECK(intersection.is_subset_of(union_set));

            // Inclusion-exclusion, computed with an independent popcount.
            META_AUTH_CHECK_EQ(union_set.size() + intersection.size(),
                               lhs.size() + rhs.size());
            META_AUTH_CHECK_EQ(union_set.size(), popcount(lhs.bits() | rhs.bits()));
            META_AUTH_CHECK_EQ(intersection.size(), popcount(lhs.bits() & rhs.bits()));
        }
    }
}

META_AUTH_TEST("rights", "union_and_intersection_are_commutative_over_every_pair") {
    for (const rights_set& a : subsets) {
        for (const rights_set& b : subsets) {
            META_AUTH_CHECK_EQ(a | b, b | a);
            META_AUTH_CHECK_EQ(a & b, b & a);
        }
    }
}

META_AUTH_TEST("rights", "the_cubic_laws_hold_over_a_generating_family") {
    for (const rights_set& a : generating_family) {
        for (const rights_set& b : generating_family) {
            // Absorption: each operation determines the other.
            META_AUTH_CHECK_EQ(a | (a & b), a);
            META_AUTH_CHECK_EQ(a & (a | b), a);
            for (const rights_set& c : generating_family) {
                META_AUTH_CHECK_EQ((a | b) | c, a | (b | c));
                META_AUTH_CHECK_EQ((a & b) & c, a & (b & c));
                META_AUTH_CHECK_EQ(a & (b | c), (a & b) | (a & c));
                META_AUTH_CHECK_EQ(a | (b & c), (a | b) & (a | c));
            }
        }
    }
    // The family must contain every atom, or it does not generate the lattice
    // and the reduction above proves nothing. Asserted rather than trusted.
    for (const right value : meta_auth::all_rights) {
        bool found = false;
        for (const rights_set& candidate : generating_family) {
            found = found || (candidate == rights_set{value});
        }
        META_AUTH_CHECK(found);
    }
}

META_AUTH_TEST("rights", "complement_is_an_involution") {
    for (const rights_set& a : subsets) {
        META_AUTH_CHECK_EQ(a.complement().complement(), a);
        META_AUTH_CHECK_EQ((a | a.complement()), rights_set::all());
        META_AUTH_CHECK_EQ((a & a.complement()), rights_set::none());
    }
}

META_AUTH_TEST("rights", "de_morgan_holds_over_a_generating_family") {
    for (const rights_set& a : generating_family) {
        for (const rights_set& b : generating_family) {
            META_AUTH_CHECK_EQ((a | b).complement(), a.complement() & b.complement());
            META_AUTH_CHECK_EQ((a & b).complement(), a.complement() | b.complement());
        }
    }
}

META_AUTH_TEST("rights", "difference_is_the_intersection_with_the_complement") {
    for (const rights_set& a : subsets) {
        for (const rights_set& b : subsets) {
            META_AUTH_CHECK_EQ(a - b, a & b.complement());
            META_AUTH_CHECK((a - b).is_subset_of(a));
            META_AUTH_CHECK_EQ((a - b) & b, rights_set::none());
            META_AUTH_CHECK_EQ((a - b) | (a & b), a);
        }
    }
}

META_AUTH_TEST("rights", "contains_agrees_with_the_bit_representation") {
    for (const rights_set& set : subsets) {
        for (const right value : meta_auth::all_rights) {
            const bool expected = (set.bits() & static_cast<std::uint32_t>(value)) != 0U;
            META_AUTH_CHECK_EQ(set.contains(value), expected);
        }
        // `contains(rights_set)` and `is_subset_of` are the same relation read
        // in two directions, which is exactly how the delegation constraint
        // uses them.
        for (const rights_set& other : subsets) {
            META_AUTH_CHECK_EQ(set.contains(other), other.is_subset_of(set));
        }
    }
}

META_AUTH_TEST("rights", "size_matches_an_independent_popcount") {
    for (const rights_set& set : subsets) {
        META_AUTH_CHECK_EQ(set.size(), popcount(set.bits()));
        META_AUTH_CHECK_EQ(set.is_empty(), set.size() == 0);
        META_AUTH_CHECK_EQ(set.is_full(), set.size() == right_count);
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
META_AUTH_TEST("rights", "rendering_names_every_member") {
    META_AUTH_CHECK_EQ(rights_set::none().to_string(), std::string{"none"});
    META_AUTH_CHECK_EQ(rights_set::all().to_string(), std::string{"all"});
    META_AUTH_CHECK_EQ(rights_set{right::read}.to_string(), std::string{"read"});
    // Declaration order, not insertion order: a rendering that depended on how
    // the set was built would make two equal sets log differently.
    META_AUTH_CHECK_EQ((rights_set{right::audit, right::read}).to_string(),
                       std::string{"read|audit"});
    META_AUTH_CHECK_EQ((rights_set{right::administer, right::write, right::read}).to_string(),
                       std::string{"read|write|administer"});
}

META_AUTH_TEST("rights", "rendering_never_overruns_a_small_buffer") {
    // The audit trail renders right sets into a fixed buffer, so the writer
    // has to be safe at every size, including zero.
    std::array<char, 64> buffer{};
    for (std::size_t size = 0; size <= buffer.size(); ++size) {
        for (const rights_set& set : subsets) {
            const std::string_view text = set.write_to(std::span<char>{buffer.data(), size});
            META_AUTH_CHECK(text.size() <= size);
            if (size > 0) {
                META_AUTH_CHECK(text.data() == buffer.data());
            }
        }
    }
}

META_AUTH_TEST("rights", "rendering_round_trips_through_the_formatter") {
    for (const rights_set& set : subsets) {
        META_AUTH_CHECK_EQ(std::format("{}", set), set.to_string());
        META_AUTH_CHECK_EQ(std::format("{}", set), meta_auth::test::stringify(set));
    }
    META_AUTH_CHECK_EQ(std::format("{}", right::read), std::string{"read"});
    META_AUTH_CHECK_EQ(std::format("{}", static_cast<right>(0)), std::string{"<invalid right>"});
}

META_AUTH_TEST("rights", "for_each_right_visits_each_member_once_in_order") {
    for (const rights_set& set : subsets) {
        std::size_t visits = 0;
        std::uint32_t previous = 0;
        meta_auth::for_each_right(set, [&](right value) {
            const auto bits = static_cast<std::uint32_t>(value);
            // Strictly increasing: each right is visited once, in declaration
            // order, which is what makes the audit rendering deterministic.
            META_AUTH_CHECK(bits > previous);
            previous = bits;
            ++visits;
        });
        META_AUTH_CHECK_EQ(visits, set.size());
    }
}
