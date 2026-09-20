// ===========================================================================
//  meta-auth-core -- micro-benchmarks.
//
//  Three measurements, each answering a question the documentation makes a
//  claim about:
//
//    1. What does a mediated operation cost? A capability check that is
//       expensive is a capability check that gets bypassed, so the number has
//       to be small enough to be uninteresting.
//    2. What does recording cost? The audit trail is on the path an attacker
//       drives; if a denial is slower than a grant, denials become a lever.
//    3. **Does the constant-time comparison actually behave constant-time?**
//       This is the one that matters. Timing is not a property a unit test can
//       establish, and the honest way to support the claim is to measure the
//       comparison across every differing position and report the spread. A
//       comparison that returns at the first difference produces a spread that
//       grows with the position; a constant-time one does not. The check at the
//       end of `benchmark_constant_time` fails when the spread exceeds a stated
//       bound, so this is a measurement *and* a regression gate.
//
//  No benchmark framework: the project has no dependencies, and a benchmark
//  that needs one is a benchmark that runs in fewer places. The harness is the
//  twenty lines below, and it reports nanoseconds per operation with the
//  spread, because a mean without a spread cannot distinguish a constant-time
//  primitive from a branchy one.
// ===========================================================================
#include "meta_auth/auth/policy.hpp"
#include "meta_auth/auth/session.hpp"
#include "meta_auth/capability/capability.hpp"
#include "meta_auth/crypto/constant_time.hpp"
#include "meta_auth/crypto/hmac.hpp"
#include "meta_auth/sandbox/gate.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>

namespace {

using namespace meta_auth;

using device_resource = named_resource<"devices">;
using device_gate = gate<resource_kind::devices>;
using device_authority = authority<device_resource, rights_set::all()>;
using device_registry = protected_object<std::uint64_t, resource_kind::devices>;

using bench_policy = policy<
    allow<resource_kind::devices, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::devices, action::modify, exactly<admin_principal>>,
    allow<resource_kind::sessions, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::credentials, action::observe, exactly<admin_principal>>,
    allow<resource_kind::audit_log, action::audit, any_principal<principal_kind::user>>,
    allow<resource_kind::policy_store, action::modify, exactly<admin_principal>>>;

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------
struct measurement {
    double nanoseconds_per_operation = 0.0;
    double spread_nanoseconds = 0.0;
    std::size_t samples = 0;
};

/// Run `body` `iterations` times, `samples` times, and report the best and the
/// spread.
///
/// The best sample rather than the mean: a microbenchmark's mean is dominated
/// by whatever else the machine was doing, and the minimum is the closest
/// available estimate of the cost of the operation itself. The spread across
/// samples is reported because for the constant-time measurement it *is* the
/// result.
template <typename Body>
[[nodiscard]] auto measure(std::size_t iterations, std::size_t samples, Body&& body)
    -> measurement {
    std::vector<double> per_sample;
    per_sample.reserve(samples);

    for (std::size_t sample = 0; sample < samples; ++sample) {
        const auto started = std::chrono::steady_clock::now();
        for (std::size_t index = 0; index < iterations; ++index) {
            body(index);
        }
        const auto elapsed = std::chrono::steady_clock::now() - started;
        const double nanoseconds =
            static_cast<double>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count())
            / static_cast<double>(iterations);
        per_sample.push_back(nanoseconds);
    }

    const auto [smallest, largest] = std::minmax_element(per_sample.begin(), per_sample.end());
    return measurement{*smallest, *largest - *smallest, per_sample.size()};
}

void report(std::string_view name, const measurement& result) {
    std::printf("  %-46.*s %10.2f ns/op   spread %8.2f ns over %zu samples\n",
                static_cast<int>(name.size()), name.data(), result.nanoseconds_per_operation,
                result.spread_nanoseconds, result.samples);
}

// ---------------------------------------------------------------------------
// 1. A mediated operation
// ---------------------------------------------------------------------------
void benchmark_mediated_operation() {
    std::puts("\nmediated operation (gate + audit record)");

    audit_trail trail;
    device_gate mediator{trail};
    device_registry registry{0U};
    device_authority root;
    auto capability_value = root.mint<rights_set::all()>();

    const auto authorized = authorize<bench_policy, admin_principal, resource_kind::devices,
                                      action::modify>();
    (void)authorized;

    // Each iteration needs a fresh proof, because a proof is consumed. The
    // policy decision is compile-time, so the loop cost is the gate.
    const auto result = measure(200'000, 9, [&](std::size_t index) {
        static_cast<void>(index);
        auto proof = authorize<bench_policy, admin_principal, resource_kind::devices,
                               action::modify>();
        const auto outcome = registry.write<rights_set::all(), admin_principal>(
            capability_value, std::move(proof), mediator, 1U);
        if (!outcome.has_value()) {
            std::fputs("unexpected refusal in the benchmark\n", stderr);
            std::exit(EXIT_FAILURE);
        }
    });
    report("write through the gate", result);

    trail.clear();
    const auto denied = measure(200'000, 9, [&](std::size_t index) {
        static_cast<void>(index);
        auto weak = root.mint<rights_set{right::read}>();
        auto proof = authorize<bench_policy, admin_principal, resource_kind::devices,
                               action::modify>();
        const auto outcome = registry.write<rights_set{right::read}, admin_principal>(
            weak, std::move(proof), mediator, 1U);
        if (outcome.has_value()) {
            std::fputs("unexpected admission in the benchmark\n", stderr);
            std::exit(EXIT_FAILURE);
        }
    });
    report("refused write (capability too weak, recorded)", denied);
}

// ---------------------------------------------------------------------------
// 2. The audit trail on its own
// ---------------------------------------------------------------------------
void benchmark_audit_trail() {
    std::puts("\naudit trail");

    audit_trail trail;
    audit_event event{};
    event.principal_hash = 0x1234;
    event.resource_hash = 0x5678;
    event.rights_bits = 0x7F;
    event.outcome = audit_outcome::denied_insufficient_rights;

    const auto result = measure(1'000'000, 9, [&](std::size_t index) {
        event.capability_serial = index;
        trail.record(event);
    });
    report("record one event", result);
    std::printf("  %-46s %10llu\n", "records written", static_cast<unsigned long long>(trail.recorded()));
    std::printf("  %-46s %10llu\n", "records overwritten before being read",
                static_cast<unsigned long long>(trail.dropped()));
}

// ---------------------------------------------------------------------------
// 3. Constant time, measured rather than asserted
// ---------------------------------------------------------------------------
void benchmark_constant_time() {
    std::puts("\nconstant-time comparison, by position of the first difference");

    constexpr std::size_t length = 32;
    std::array<std::byte, length> reference{};
    for (std::size_t index = 0; index < length; ++index) {
        reference[index] = static_cast<std::byte>(index + 1);
    }
    std::array<std::byte, length> candidate = reference;

    std::vector<double> per_position;
    per_position.reserve(length + 1);

    // The last position differs: an implementation that returns at the first
    // difference does the most work here and the least at position zero, so the
    // spread across positions is the signal.
    for (std::size_t position = 0; position <= length; ++position) {
        candidate = reference;
        if (position < length) {
            candidate[position] = static_cast<std::byte>(
                std::to_integer<std::uint8_t>(candidate[position]) ^ 0xFFU);
        }

        const auto result = measure(200'000, 15, [&](std::size_t) {
            volatile bool equal = crypto::constant_time_equal(reference, candidate);
            static_cast<void>(equal);
        });
        per_position.push_back(result.nanoseconds_per_operation);
    }

    const auto [smallest, largest] =
        std::minmax_element(per_position.begin(), per_position.end());
    const double spread = *largest - *smallest;
    const double relative = spread / *smallest;

    std::printf("  %-46s %10.2f ns\n", "comparison, equal inputs", per_position.back());
    std::printf("  %-46s %10.2f ns\n", "comparison, difference at position 0", per_position[0]);
    std::printf("  %-46s %10.2f ns\n", "comparison, difference at the last position",
                per_position[length - 1]);
    std::printf("  %-46s %10.2f ns (%.1f%% of the fastest)\n", "spread across all positions",
                spread, relative * 100.0);

    // The gate. A branchy comparison shows a spread that tracks the position of
    // the first difference; 32 bytes is 32 opportunities to return early, and
    // on any realistic machine that is tens of percent, not a few. The bound is
    // deliberately loose -- this is a smoke test for "constant time", not a
    // side-channel analysis -- but it is a bound, and a change that turned the
    // comparison back into an early-exit loop would exceed it.
    constexpr double allowed_relative_spread = 0.25;
    if (relative > allowed_relative_spread) {
        std::printf("\nCONSTANT-TIME REGRESSION: the spread is %.1f%% of the fastest measurement, "
                    "above the %.0f%% bound.\n",
                    relative * 100.0, allowed_relative_spread * 100.0);
        std::exit(EXIT_FAILURE);
    }
    std::printf("  %-46s %10.0f%%\n", "bound on the relative spread",
                allowed_relative_spread * 100.0);
}

// ---------------------------------------------------------------------------
// 4. Hashing, for scale
// ---------------------------------------------------------------------------
void benchmark_hash() {
    std::puts("\nhashing");

    std::array<std::byte, 1024> block{};
    const auto result = measure(20'000, 9, [&](std::size_t) {
        volatile auto digest = crypto::sha256(block);
        static_cast<void>(digest);
    });
    report("sha256 of 1 KiB", result);

    std::array<std::byte, 32> key{};
    key.fill(std::byte{0x2A});
    std::array<std::byte, 64> message{};
    const auto mac_result = measure(20'000, 9, [&](std::size_t) {
        volatile auto tag = crypto::hmac_sha256(key, message);
        static_cast<void>(tag);
    });
    report("hmac-sha256 of 64 B", mac_result);
}

} // namespace

auto main() -> int {
    std::printf("meta-auth-core benchmarks (%s)\n", config::dialect_summary());
    std::printf("costs are the fastest of several samples; the spread is reported because for\n"
                "the constant-time measurement it is the result, not the noise\n");

    benchmark_mediated_operation();
    benchmark_audit_trail();
    benchmark_constant_time();
    benchmark_hash();

    std::puts("\ndone");
    return EXIT_SUCCESS;
}
