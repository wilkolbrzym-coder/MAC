// ===========================================================================
//  Tests of revocation epochs.
//
//  Revocation is the one capability operation that happens *outside* the
//  holder's control, so its correctness is a property of the whole system
//  rather than of a call: after `revoke_all<Resource>()`, every capability
//  minted before it must be rejected, whether or not anyone told the holder.
//
//  The three claims tested here are:
//
//    * a capability minted before a revocation is stale and one minted after
//      it is live, with no other difference between them;
//    * epochs are per resource type, so revoking one resource does not disturb
//      another -- a global counter would be a denial of service waiting to
//      happen;
//    * concurrent revocations all take effect, which is what distinguishes an
//      atomic increment from a load-then-store, and is the reason this file
//      runs under ThreadSanitizer in CI.
// ===========================================================================
#include "meta_auth/capability/capability.hpp"
#include "test_framework.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace {

using meta_auth::authority;
using meta_auth::named_resource;
using meta_auth::revocation_epoch;
using meta_auth::right;
using meta_auth::rights_set;

/// Resource types used only by this file, so that epochs here cannot be
/// disturbed by another test binary or by another case in this one.
using alpha_resource = named_resource<"test-alpha">;
using beta_resource = named_resource<"test-beta">;
using gamma_resource = named_resource<"test-gamma">;

constexpr rights_set read_only{right::read};

} // namespace

// ---------------------------------------------------------------------------
// The epoch type itself
// ---------------------------------------------------------------------------
static_assert(revocation_epoch{}.is_initial());
static_assert(!revocation_epoch{1}.is_initial());
static_assert(revocation_epoch{1}.next() == revocation_epoch{2});
static_assert(revocation_epoch{1} < revocation_epoch{2});
static_assert(meta_auth::epoch_is_current(revocation_epoch{3}, revocation_epoch{3}));
static_assert(!meta_auth::epoch_is_current(revocation_epoch{2}, revocation_epoch{3}));
/// An epoch ahead of the current one is not "from the future to be trusted":
/// it did not come from this resource's counter, and honouring it would be a
/// way to bypass revocation by inventing a value.
static_assert(!meta_auth::epoch_is_current(revocation_epoch{4}, revocation_epoch{3}));
static_assert(meta_auth::epochs_behind(revocation_epoch{1}, revocation_epoch{4}) == 3);
static_assert(meta_auth::epochs_behind(revocation_epoch{4}, revocation_epoch{1}) == 0);

META_AUTH_TEST("revocation", "epoch_renders_with_its_number") {
    META_AUTH_CHECK_EQ(std::format("{}", revocation_epoch{7}), std::string{"epoch#7"});
}

// ---------------------------------------------------------------------------
// Revocation invalidates exactly what it should
// ---------------------------------------------------------------------------
META_AUTH_TEST("revocation", "revoking_makes_earlier_capabilities_stale") {
    authority<alpha_resource, read_only> root;

    const auto before = root.mint<read_only>();
    META_AUTH_CHECK(before.is_live());

    const revocation_epoch after_revocation = meta_auth::revoke_all<alpha_resource>();
    META_AUTH_CHECK_EQ(after_revocation, before.epoch().next());

    // The capability is unchanged and still usable as a value; what changed is
    // whether the resource considers it current. That distinction is what
    // allows the rejection to be reported and audited instead of the
    // capability simply vanishing.
    META_AUTH_CHECK(!before.is_live());
    META_AUTH_CHECK_EQ(before.rights_value(), read_only);
}

META_AUTH_TEST("revocation", "a_capability_minted_after_revocation_is_live") {
    static_cast<void>(meta_auth::revoke_all<alpha_resource>());

    authority<alpha_resource, read_only> root;
    const auto after = root.mint<read_only>();

    META_AUTH_CHECK(after.is_live());
    META_AUTH_CHECK(after.epoch() > revocation_epoch{});
}

META_AUTH_TEST("revocation", "attenuation_inherits_the_epoch_it_was_minted_in") {
    authority<alpha_resource, rights_set::all()> root;
    auto strong = root.mint<rights_set::all()>();
    const revocation_epoch epoch = strong.epoch();

    auto weak = std::move(strong).attenuate<read_only>();
    META_AUTH_CHECK_EQ(weak.epoch(), epoch);

    static_cast<void>(meta_auth::revoke_all<alpha_resource>());
    // Attenuation does not refresh a capability: a weaker capability derived
    // from a revoked one is revoked as well, or revocation would be a
    // formality anyone could undo by attenuating.
    META_AUTH_CHECK(!weak.is_live());
}

META_AUTH_TEST("revocation", "delegation_inherits_the_epoch") {
    authority<alpha_resource, rights_set::all()> root;
    const auto strong = root.mint<rights_set::all()>();
    const revocation_epoch epoch = strong.epoch();

    const auto delegated = strong.delegate<read_only>();
    META_AUTH_CHECK_EQ(delegated.epoch(), epoch);
}

// ---------------------------------------------------------------------------
// Epochs are per resource
// ---------------------------------------------------------------------------
META_AUTH_TEST("revocation", "epochs_are_scoped_to_the_resource_type") {
    authority<beta_resource, read_only> beta_root;
    authority<gamma_resource, read_only> gamma_root;

    const auto beta_capability = beta_root.mint<read_only>();
    const auto gamma_capability = gamma_root.mint<read_only>();
    // The epoch *change* is what is asserted, not an absolute value: this
    // binary runs its cases in a fixed order and other cases revoke gamma, so
    // an absolute expectation would be a test that depends on test order.
    const revocation_epoch gamma_before = meta_auth::current_epoch<gamma_resource>();
    const revocation_epoch beta_before = meta_auth::current_epoch<beta_resource>();

    static_cast<void>(meta_auth::revoke_all<beta_resource>());

    // Revoking one resource must not disturb another. A single global epoch
    // would make every revocation a denial of service for every resource.
    META_AUTH_CHECK(!beta_capability.is_live());
    META_AUTH_CHECK(gamma_capability.is_live());
    META_AUTH_CHECK_EQ(meta_auth::current_epoch<gamma_resource>(), gamma_before);
    META_AUTH_CHECK_EQ(meta_auth::current_epoch<beta_resource>(), beta_before.next());
}

META_AUTH_TEST("revocation", "repeated_revocations_advance_the_epoch_by_one_each") {
    const revocation_epoch start = meta_auth::current_epoch<beta_resource>();

    const auto first = meta_auth::revoke_all<beta_resource>();
    const auto second = meta_auth::revoke_all<beta_resource>();
    const auto third = meta_auth::revoke_all<beta_resource>();

    META_AUTH_CHECK_EQ(first, start.next());
    META_AUTH_CHECK_EQ(second, first.next());
    META_AUTH_CHECK_EQ(third, second.next());
    META_AUTH_CHECK_EQ(meta_auth::current_epoch<beta_resource>(), third);
}

META_AUTH_TEST("revocation", "a_capability_is_stale_by_the_number_of_generations_it_missed") {
    authority<gamma_resource, read_only> root;
    const auto capability = root.mint<read_only>();

    static_cast<void>(meta_auth::revoke_all<gamma_resource>());
    static_cast<void>(meta_auth::revoke_all<gamma_resource>());

    const revocation_epoch current = meta_auth::current_epoch<gamma_resource>();
    META_AUTH_CHECK_EQ(meta_auth::epochs_behind(capability.epoch(), current), std::uint64_t{2});
}

// ---------------------------------------------------------------------------
// Concurrency
//
// One atomic increment per revocation is the entire implementation, and the
// property that makes it correct is that concurrent increments all take
// effect. A load-then-store would lose them, and the failure would appear as
// an epoch that lags -- that is, as a capability that should have been revoked
// and was not. This suite runs under ThreadSanitizer in CI for exactly this
// case.
// ---------------------------------------------------------------------------
META_AUTH_TEST("revocation", "concurrent_revocations_all_take_effect") {
    using epoch_resource = named_resource<"test-concurrent">;

    constexpr int thread_count = 8;
    constexpr int revocations_per_thread = 250;

    const revocation_epoch start = meta_auth::current_epoch<epoch_resource>();

    std::atomic<int> ready{0};
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    for (int index = 0; index < thread_count; ++index) {
        workers.emplace_back([&ready] {
            ready.fetch_add(1, std::memory_order_release);
            while (ready.load(std::memory_order_acquire) < thread_count) {
                std::this_thread::yield();
            }
            for (int step = 0; step < revocations_per_thread; ++step) {
                static_cast<void>(meta_auth::revoke_all<epoch_resource>());
            }
        });
    }

    for (auto& worker : workers) {
        worker.join();
    }

    const revocation_epoch expected =
        revocation_epoch{start.value() + static_cast<std::uint64_t>(thread_count)
                                          * static_cast<std::uint64_t>(revocations_per_thread)};
    META_AUTH_CHECK_EQ(meta_auth::current_epoch<epoch_resource>(), expected);
}

META_AUTH_TEST("revocation", "reading_the_epoch_is_safe_while_another_thread_revokes") {
    using live_resource = named_resource<"test-live">;

    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> observed_min{0xFFFFFFFFFFFFFFFFULL};

    std::thread revoker{[&stop] {
        while (!stop.load(std::memory_order_acquire)) {
            static_cast<void>(meta_auth::revoke_all<live_resource>());
        }
    }};

    std::uint64_t previous = 0;
    for (int index = 0; index < 1000; ++index) {
        const std::uint64_t value = meta_auth::current_epoch<live_resource>().value();
        // A monotone counter read concurrently can only move forwards, so a
        // reader must never observe a smaller value than a previous read.
        META_AUTH_CHECK(value >= previous);
        previous = value;
    }

    stop.store(true, std::memory_order_release);
    revoker.join();

    observed_min.store(previous, std::memory_order_relaxed);
    META_AUTH_CHECK(meta_auth::current_epoch<live_resource>().value() >= previous);
}
