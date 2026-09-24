// ===========================================================================
//  meta-auth-core -- the audit trail.
//
//  Every authorisation decision this library makes is recorded before it is
//  acted on: the grant and the denial alike, because a log that only contains
//  failures cannot answer "what did this principal actually do".
//
//  The design constraints come from where the code runs:
//
//    * **It must not allocate.** A denial happens on the path an attacker
//      drives, and an allocation there is both a latency and a failure mode.
//      The trail is a fixed-size ring of atomic slots.
//    * **It must not throw or fail.** A full trail drops the oldest record and
//      counts the loss, because the alternative -- refusing to record and
//      therefore refusing to decide -- turns a full log into a denial of
//      service. The dropped counter is what keeps the loss visible.
//    * **It must be readable while being written.** An operator inspects the
//      trail of a running process. Each slot carries a stamp written before and
//      after its fields, so a reader detects a torn record and retries rather
//      than reporting a mixture of two events.
//
//      The stamp detects *a* writer's interruption, which is a different thing
//      from detecting two writers in one slot -- and the reader of this comment
//      should know which one is guaranteed. The protocol is a seqlock, and a
//      seqlock assumes a single writer per slot. Here the slot is chosen as
//      `sequence & (capacity - 1)`, so two writers share a slot exactly when
//      their sequence numbers differ by `capacity` -- 256.
//
//      That is *not* the same as requiring 256 writers in flight, which is what
//      this comment claimed before the ASan job disproved it. What it requires
//      is one writer to be *stalled* while 256 later appends take its slot: the
//      stalled writer returns, its stamp and fields land on top of a newer
//      record, and a reader then sees a stamp matching neither sequence and
//      skips that record. The record is not torn -- the seqlock holds and the
//      mixture is never returned -- but it is *missing*, and `dropped()` does
//      not count it, because the overflow that counter tracks happened when the
//      overwritten record was written, not when it was lost.
//
//      That mechanism is the one most consistent with the failure, not a
//      measured one: `sandbox.concurrent_records_all_land` failed in the first
//      ASan run (a gap where a retained record should have been -- sequences
//      1419 and 1421 adjacent, 1420 absent, out of 1600 appends from eight
//      writers on four cores), and twelve runs of that case under ASan on the
//      machine this was written on did not reproduce it. The bound is therefore
//      stated as the code actually behaves rather than as intended: **a reader
//      never returns a mixture of two records, and a record can be lost -- not
//      merely overwritten -- when a writer stalls by `capacity` appends.**
//      Closing that needs the slot to be claimed rather than inferred from the
//      sequence (a per-slot owner word taken with a compare-exchange), which
//      changes the write path; it is not done here.
//    * **A record must not dangle.** Names are stored as their 64-bit hashes
//      rather than as views, so a record stays valid after the string it came
//      from is gone. Rendering resolves a hash through the principal and
//      resource registries, which are compile-time values.
// ===========================================================================
#ifndef META_AUTH_SANDBOX_AUDIT_HPP
#define META_AUTH_SANDBOX_AUDIT_HPP

#include "meta_auth/config.hpp"
#include "meta_auth/core/fixed_string.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace meta_auth {

/// Why a decision came out the way it did.
///
/// A denial carries its reason, because "denied" alone cannot be acted on: an
/// operator needs to know whether to enroll a device, widen a policy or
/// investigate a forgery.
/// The outcome vocabulary is shared with the code that *calls* the gate: a
/// consumer that mediates sessions or presents its own resource can record
/// `denied_unauthenticated`, `denied_policy` or `denied_unavailable` in the
/// same trail, and an operator reading a mixed trail gets one vocabulary
/// instead of two. This library's own mediator produces five of the seven --
/// `granted`, `denied_insufficient_rights`, `denied_revoked`,
/// `denied_neutralised` and (from the revocation path) none -- which is why
/// the remaining three are documented here rather than left looking unused.
enum class audit_outcome : std::uint8_t {
    granted = 0,
    denied_insufficient_rights = 1,
    denied_revoked = 2,
    denied_policy = 3,
    denied_unauthenticated = 4,
    denied_unavailable = 5,
    denied_neutralised = 6,
};

[[nodiscard]] constexpr auto to_string(audit_outcome outcome) noexcept -> std::string_view {
    switch (outcome) {
    case audit_outcome::granted:
        return "granted";
    case audit_outcome::denied_insufficient_rights:
        return "denied:insufficient-rights";
    case audit_outcome::denied_revoked:
        return "denied:revoked";
    case audit_outcome::denied_policy:
        return "denied:policy";
    case audit_outcome::denied_unauthenticated:
        return "denied:unauthenticated";
    case audit_outcome::denied_unavailable:
        return "denied:unavailable";
    case audit_outcome::denied_neutralised:
        return "denied:neutralised";
    }
    return "unknown";
}

[[nodiscard]] constexpr auto is_denial(audit_outcome outcome) noexcept -> bool {
    return outcome != audit_outcome::granted;
}

/// What was asked, what was decided, and on whose authority.
///
/// A plain value, copied out of the ring; the ring itself holds atomics.
struct audit_event {
    std::uint64_t sequence = 0;      ///< 1-based order of recording
    std::int64_t timestamp_ns = 0;   ///< steady-clock nanoseconds
    std::uint64_t principal_hash = 0;///< who asked
    std::uint64_t resource_hash = 0; ///< what was asked for
    std::uint64_t capability_serial = 0; ///< which capability was presented
    std::uint64_t epoch = 0;         ///< the epoch the capability carried
    std::uint32_t rights_bits = 0;   ///< the rights the capability held
    audit_outcome outcome = audit_outcome::granted;
    std::uint8_t action_raw = 0;     ///< `action` as its underlying value
};

/// A fixed-capacity, lock-free, allocation-free ring of audit records.
///
/// One instance per process is typical, but nothing here is global: a test can
/// hold its own trail, which is what lets the audit tests assert on exactly the
/// records their own operations produced.
class audit_trail {
public:
    /// Number of records retained. A power of two so that the wrap is a mask,
    /// and large enough to cover the interesting part of an incident while
    /// staying small enough to dump.
    static constexpr std::size_t capacity = 256;

    static_assert((capacity & (capacity - 1)) == 0, "capacity must be a power of two");

    audit_trail() noexcept = default;

    audit_trail(const audit_trail&) = delete;
    auto operator=(const audit_trail&) -> audit_trail& = delete;
    audit_trail(audit_trail&&) = delete;
    auto operator=(audit_trail&&) -> audit_trail& = delete;
    ~audit_trail() = default;

    /// Append a record. Never fails: the oldest record is overwritten and the
    /// loss is counted.
    void record(const audit_event& event) noexcept {
        const std::uint64_t sequence = sequence_counter_.fetch_add(1, std::memory_order_relaxed);
        // `sequence` here is the *slot* index, monotone across wraps, so the
        // stamp below distinguishes a fresh record from a stale one.
        slot& target = slots_[sequence & (capacity - 1U)];

        // Odd stamp means "being written". A reader that sees an odd stamp, or
        // a stamp that changed under it, knows the record is torn.
        target.stamp.store((sequence * 2U) + 1U, std::memory_order_release);
        target.sequence.store(sequence + 1U, std::memory_order_relaxed);
        target.timestamp_ns.store(event.timestamp_ns, std::memory_order_relaxed);
        target.principal_hash.store(event.principal_hash, std::memory_order_relaxed);
        target.resource_hash.store(event.resource_hash, std::memory_order_relaxed);
        target.capability_serial.store(event.capability_serial, std::memory_order_relaxed);
        target.epoch.store(event.epoch, std::memory_order_relaxed);
        target.rights_bits.store(event.rights_bits, std::memory_order_relaxed);
        target.outcome_raw.store(static_cast<std::uint8_t>(event.outcome),
                                 std::memory_order_relaxed);
        target.action_raw.store(event.action_raw, std::memory_order_relaxed);
        target.stamp.store((sequence * 2U) + 2U, std::memory_order_release);

        if (sequence >= capacity) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    /// Number of records appended, including those overwritten.
    [[nodiscard]] auto recorded() const noexcept -> std::uint64_t {
        return sequence_counter_.load(std::memory_order_relaxed);
    }

    /// Number of records overwritten before being read.
    ///
    /// Exposed rather than hidden: a trail that silently lost records would
    /// make every later statement about it unsound.
    [[nodiscard]] auto dropped() const noexcept -> std::uint64_t {
        return dropped_.load(std::memory_order_relaxed);
    }

    /// Records currently retained, in oldest-first order.
    ///
    /// A torn record is retried a bounded number of times and then skipped, so
    /// a reader can never return a mixture of two events -- which would be
    /// worse than returning one fewer.
    [[nodiscard]] auto snapshot(std::span<audit_event> destination) const noexcept
        -> std::size_t {
        const std::uint64_t recorded_now = recorded();
        const std::uint64_t retained =
            recorded_now < capacity ? recorded_now : static_cast<std::uint64_t>(capacity);
        const std::uint64_t first = recorded_now - retained;

        std::size_t written = 0;
        for (std::uint64_t sequence = first; sequence < recorded_now; ++sequence) {
            if (written >= destination.size()) {
                break;
            }
            if (read_slot(sequence & (capacity - 1U), sequence, destination[written])) {
                ++written;
            }
        }
        return written;
    }

    /// The most recent record, if any.
    [[nodiscard]] auto last() const noexcept -> std::optional<audit_event> {
        const std::uint64_t recorded_now = recorded();
        if (recorded_now == 0) {
            return std::nullopt;
        }
        audit_event event{};
        if (!read_slot((recorded_now - 1U) & (capacity - 1U), recorded_now - 1U, event)) {
            return std::nullopt;
        }
        return event;
    }

    /// Forget everything. Only for tests: an application has no reason to
    /// destroy evidence.
    void clear() noexcept {
        for (slot& entry : slots_) {
            entry.stamp.store(0, std::memory_order_relaxed);
        }
        sequence_counter_.store(0, std::memory_order_relaxed);
        dropped_.store(0, std::memory_order_relaxed);
    }

    /// Nanoseconds from the steady clock, for stamping a record.
    [[nodiscard]] static auto now_ns() noexcept -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

private:
    /// One ring entry. Atomic fields rather than a plain struct: a seqlock over
    /// non-atomic memory is the classic lock-free reader protocol, and it is
    /// also a data race as far as the language and ThreadSanitizer are
    /// concerned. Relaxed atomics keep the protocol and remove the race; the
    /// stamp provides the consistency, not the memory order.
    struct slot {
        std::atomic<std::uint64_t> stamp{0};
        std::atomic<std::uint64_t> sequence{0};
        std::atomic<std::int64_t> timestamp_ns{0};
        std::atomic<std::uint64_t> principal_hash{0};
        std::atomic<std::uint64_t> resource_hash{0};
        std::atomic<std::uint64_t> capability_serial{0};
        std::atomic<std::uint64_t> epoch{0};
        std::atomic<std::uint32_t> rights_bits{0};
        std::atomic<std::uint8_t> outcome_raw{0};
        std::atomic<std::uint8_t> action_raw{0};
    };

    [[nodiscard]] auto read_slot(std::size_t index, std::uint64_t expected_sequence,
                                 audit_event& destination) const noexcept -> bool {
        constexpr int attempts = 4;
        for (int attempt = 0; attempt < attempts; ++attempt) {
            const std::uint64_t before = slots_[index].stamp.load(std::memory_order_acquire);
            if ((before & 1U) != 0U) {
                continue; // being written
            }
            if (before != (expected_sequence * 2U) + 2U) {
                return false; // the slot has been reused; the record is gone
            }

            audit_event candidate{};
            candidate.sequence = slots_[index].sequence.load(std::memory_order_relaxed);
            candidate.timestamp_ns = slots_[index].timestamp_ns.load(std::memory_order_relaxed);
            candidate.principal_hash =
                slots_[index].principal_hash.load(std::memory_order_relaxed);
            candidate.resource_hash = slots_[index].resource_hash.load(std::memory_order_relaxed);
            candidate.capability_serial =
                slots_[index].capability_serial.load(std::memory_order_relaxed);
            candidate.epoch = slots_[index].epoch.load(std::memory_order_relaxed);
            candidate.rights_bits = slots_[index].rights_bits.load(std::memory_order_relaxed);
            candidate.outcome = static_cast<audit_outcome>(
                slots_[index].outcome_raw.load(std::memory_order_relaxed));
            candidate.action_raw = slots_[index].action_raw.load(std::memory_order_relaxed);

            const std::uint64_t after = slots_[index].stamp.load(std::memory_order_acquire);
            if (before == after) {
                destination = candidate;
                return true;
            }
        }
        return false;
    }

    mutable std::array<slot, capacity> slots_{};
    std::atomic<std::uint64_t> sequence_counter_{0};
    std::atomic<std::uint64_t> dropped_{0};
};

} // namespace meta_auth

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
template <>
struct std::formatter<meta_auth::audit_outcome, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(meta_auth::audit_outcome outcome, std::format_context& context) const {
        return std::format_to(context.out(), "{}", meta_auth::to_string(outcome));
    }
};

template <>
struct std::formatter<meta_auth::audit_event, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    /// Hashes are rendered as hex rather than resolved to names: the trail is
    /// self-contained and the resolution belongs to the registry, which is a
    /// compile-time value the formatter does not have.
    auto format(const meta_auth::audit_event& event, std::format_context& context) const {
        return std::format_to(context.out(),
                              "#{} t={}ns principal={:016x} resource={:016x} "
                              "capability={} epoch={} rights={:02x} action={} -> {}",
                              event.sequence, event.timestamp_ns, event.principal_hash,
                              event.resource_hash, event.capability_serial, event.epoch,
                              event.rights_bits, event.action_raw,
                              meta_auth::to_string(event.outcome));
    }
};

#endif // META_AUTH_SANDBOX_AUDIT_HPP
