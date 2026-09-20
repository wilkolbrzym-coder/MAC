// ===========================================================================
//  Tests of the audit trail, the mediation gate and protected objects.
//
//  The three claims worth testing here are the ones that make the sandbox a
//  sandbox rather than a naming convention:
//
//    * every decision is recorded, grants and denials alike, and a denial is
//      recorded *before* the caller learns the outcome;
//    * a capability that is too weak, or that has been revoked, is refused by
//      the gate even though it is a perfectly valid value;
//    * the data of a protected object cannot be reached without passing through
//      the gate -- which is asserted by the compile-failure suite from the
//      other side, by trying to reach it directly.
//
//  The audit trail is also the only concurrently written component in the
//  library, so it gets a concurrency case that runs under ThreadSanitizer in CI.
// ===========================================================================
#include "meta_auth/sandbox/gate.hpp"
#include "test_framework.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using meta_auth::action;
using meta_auth::admin_principal;
using meta_auth::allow;
using meta_auth::any_principal;
using meta_auth::audit_event;
using meta_auth::audit_outcome;
using meta_auth::audit_trail;
using meta_auth::authority;
using meta_auth::authorization;
using meta_auth::capability;
using meta_auth::decision;
using meta_auth::exactly;
using meta_auth::gate;
using meta_auth::operator_principal;
using meta_auth::policy;
using meta_auth::principal_kind;
using meta_auth::protected_object;
using meta_auth::resource_kind;
using meta_auth::right;
using meta_auth::rights_set;

namespace {

constexpr rights_set read_only{right::read};
constexpr rights_set read_write{right::read, right::write};

/// The policy the sandbox tests run under. Small and explicit, so that a
/// failure here points at the gate rather than at a policy the reader has to
/// reconstruct.
using sandbox_policy = policy<
    allow<resource_kind::devices, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::devices, action::modify, exactly<admin_principal>>,
    allow<resource_kind::sessions, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::credentials, action::observe, exactly<admin_principal>>,
    allow<resource_kind::audit_log, action::audit, any_principal<principal_kind::user>>,
    allow<resource_kind::policy_store, action::modify, exactly<admin_principal>>>;

using device_gate = gate<resource_kind::devices>;

/// The authority the test uses to hand out capabilities. Declared per test
/// rather than shared, so that serial numbers do not leak between cases.
[[nodiscard]] auto device_authority() -> authority<meta_auth::resource_for_t<resource_kind::devices>,
                                                   rights_set::all()> {
    return {};
}

/// A proof that the policy allows an operation. A free function because the
/// `consteval` call has to happen in a constant expression.
[[nodiscard]] consteval auto proof_for_observe() noexcept
    -> authorization<resource_kind::devices, action::observe> {
    return meta_auth::authorize<sandbox_policy, admin_principal, resource_kind::devices,
                                action::observe>();
}

[[nodiscard]] consteval auto proof_for_modify() noexcept
    -> authorization<resource_kind::devices, action::modify> {
    return meta_auth::authorize<sandbox_policy, admin_principal, resource_kind::devices,
                                action::modify>();
}

} // namespace

// ---------------------------------------------------------------------------
// Compile-time properties
// ---------------------------------------------------------------------------

/// The policy's resource kinds and the capability layer's resources are the
/// same resources. If they drifted, a gate would mediate one resource while the
/// policy authorised another, and nothing at run time would notice.
static_assert(meta_auth::to_string(resource_kind::devices)
              == meta_auth::resource_name<meta_auth::resource_for_t<resource_kind::devices>>());
static_assert(meta_auth::to_string(resource_kind::sessions)
              == meta_auth::resource_name<meta_auth::resource_for_t<resource_kind::sessions>>());
static_assert(meta_auth::to_string(resource_kind::credentials)
              == meta_auth::resource_name<meta_auth::resource_for_t<resource_kind::credentials>>());
static_assert(meta_auth::to_string(resource_kind::audit_log)
              == meta_auth::resource_name<meta_auth::resource_for_t<resource_kind::audit_log>>());
static_assert(meta_auth::to_string(resource_kind::policy_store)
              == meta_auth::resource_name<meta_auth::resource_for_t<resource_kind::policy_store>>());

/// A proof carries the request it proves, so a gate can be handed one for a
/// different resource and reject it at compile time.
static_assert(authorization<resource_kind::devices, action::observe>::resource
              == resource_kind::devices);
static_assert(authorization<resource_kind::devices, action::observe>::action_value
              == action::observe);

// ---------------------------------------------------------------------------
// The audit trail
// ---------------------------------------------------------------------------
META_AUTH_TEST("audit", "records_are_readable_in_order") {
    audit_trail trail;
    for (int index = 0; index < 5; ++index) {
        audit_event event{};
        event.timestamp_ns = index;
        event.capability_serial = static_cast<std::uint64_t>(index) + 1U;
        event.outcome = index % 2 == 0 ? audit_outcome::granted
                                       : audit_outcome::denied_insufficient_rights;
        trail.record(event);
    }

    META_AUTH_CHECK_EQ(trail.recorded(), std::uint64_t{5});
    META_AUTH_CHECK_EQ(trail.dropped(), std::uint64_t{0});

    std::array<audit_event, 8> buffer{};
    const std::size_t count = trail.snapshot(buffer);
    META_AUTH_REQUIRE_EQ(count, std::size_t{5});

    for (std::size_t index = 0; index < count; ++index) {
        META_AUTH_CHECK_EQ(buffer[index].sequence, index + 1U);
        META_AUTH_CHECK_EQ(buffer[index].timestamp_ns, static_cast<std::int64_t>(index));
        META_AUTH_CHECK_EQ(buffer[index].capability_serial, index + 1U);
    }
    META_AUTH_CHECK_EQ(buffer[0].outcome, audit_outcome::granted);
    META_AUTH_CHECK_EQ(buffer[1].outcome, audit_outcome::denied_insufficient_rights);
}

META_AUTH_TEST("audit", "a_full_trail_overwrites_and_counts_the_loss") {
    // A ring that silently dropped records would make every later statement
    // about the trail unsound, so the loss is a first-class number.
    audit_trail trail;
    const std::size_t overflow = audit_trail::capacity + 10;

    for (std::size_t index = 0; index < overflow; ++index) {
        audit_event event{};
        event.capability_serial = index + 1U;
        trail.record(event);
    }

    META_AUTH_CHECK_EQ(trail.recorded(), static_cast<std::uint64_t>(overflow));
    META_AUTH_CHECK_EQ(trail.dropped(), static_cast<std::uint64_t>(10));

    std::array<audit_event, audit_trail::capacity> buffer{};
    const std::size_t count = trail.snapshot(buffer);
    META_AUTH_CHECK_EQ(count, audit_trail::capacity);
    // The oldest retained record is the 11th, and the newest is the last.
    META_AUTH_CHECK_EQ(buffer[0].capability_serial, std::uint64_t{11});
    META_AUTH_CHECK_EQ(buffer[count - 1].capability_serial,
                       static_cast<std::uint64_t>(overflow));
}

META_AUTH_TEST("audit", "a_snapshot_shorter_than_the_trail_truncates_from_the_oldest") {
    audit_trail trail;
    for (int index = 0; index < 6; ++index) {
        audit_event event{};
        event.capability_serial = static_cast<std::uint64_t>(index) + 1U;
        trail.record(event);
    }

    std::array<audit_event, 3> buffer{};
    META_AUTH_CHECK_EQ(trail.snapshot(buffer), std::size_t{3});
    META_AUTH_CHECK_EQ(buffer[0].capability_serial, std::uint64_t{1});
    META_AUTH_CHECK_EQ(buffer[2].capability_serial, std::uint64_t{3});
}

META_AUTH_TEST("audit", "last_returns_the_newest_record") {
    audit_trail trail;
    META_AUTH_CHECK(!trail.last().has_value());

    for (int index = 0; index < 3; ++index) {
        audit_event event{};
        event.capability_serial = static_cast<std::uint64_t>(index) + 1U;
        trail.record(event);
    }

    const auto newest = trail.last();
    META_AUTH_REQUIRE(newest.has_value());
    META_AUTH_CHECK_EQ(newest->capability_serial, std::uint64_t{3});
    META_AUTH_CHECK_EQ(newest->sequence, std::uint64_t{3});
}

META_AUTH_TEST("audit", "a_record_renders_its_decision") {
    audit_event event{};
    event.sequence = 7;
    event.principal_hash = 0xABCD;
    event.outcome = audit_outcome::denied_revoked;
    const std::string rendered = std::format("{}", event);

    META_AUTH_CHECK(rendered.find("#7") != std::string::npos);
    META_AUTH_CHECK(rendered.find("denied:revoked") != std::string::npos);
    META_AUTH_CHECK(rendered.find("000000000000abcd") != std::string::npos);
}

META_AUTH_TEST("audit", "concurrent_records_all_land") {
    // The trail is the one component in the library that is written from
    // several threads. Every record must be counted, and every snapshot must
    // contain whole records -- which is what the stamp protocol is for.
    audit_trail trail;

    constexpr int thread_count = 8;
    constexpr int per_thread = 200;

    std::atomic<int> ready{0};
    std::vector<std::thread> workers;
    workers.reserve(thread_count);
    for (int index = 0; index < thread_count; ++index) {
        workers.emplace_back([&trail, &ready, index] {
            ready.fetch_add(1, std::memory_order_release);
            while (ready.load(std::memory_order_acquire) < thread_count) {
                std::this_thread::yield();
            }
            for (int step = 0; step < per_thread; ++step) {
                audit_event event{};
                event.timestamp_ns = audit_trail::now_ns();
                event.principal_hash = static_cast<std::uint64_t>(index);
                event.capability_serial = static_cast<std::uint64_t>(step);
                trail.record(event);
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }

    META_AUTH_CHECK_EQ(trail.recorded(),
                       static_cast<std::uint64_t>(thread_count * per_thread));
    META_AUTH_CHECK_EQ(trail.dropped(),
                       static_cast<std::uint64_t>(thread_count * per_thread)
                           - audit_trail::capacity);

    std::array<audit_event, audit_trail::capacity> buffer{};
    const std::size_t count = trail.snapshot(buffer);
    for (std::size_t index = 0; index < count; ++index) {
        // A torn record would mix two writers: the principal of one and the
        // serial of another. Each writer used a fixed principal, so a record
        // whose serial is per_thread-1 must be from that principal's last
        // write -- and every serial must be in range for some writer.
        META_AUTH_CHECK(buffer[index].capability_serial < per_thread);
        if (index > 0) {
            META_AUTH_CHECK_EQ(buffer[index].sequence, buffer[index - 1].sequence + 1U);
        }
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------
META_AUTH_TEST("gate", "a_sufficient_capability_is_admitted_and_recorded") {
    audit_trail trail;
    device_gate mediator{trail};
    auto capability_value = device_authority().mint<read_write>();

    const auto outcome = mediator.admit<action::observe, read_write, admin_principal>(
        capability_value, proof_for_observe());
    META_AUTH_CHECK(outcome.has_value());

    const auto record = trail.last();
    META_AUTH_REQUIRE(record.has_value());
    META_AUTH_CHECK_EQ(record->outcome, audit_outcome::granted);
    META_AUTH_CHECK_EQ(record->capability_serial, capability_value.serial());
    META_AUTH_CHECK_EQ(record->resource_hash,
                       meta_auth::resource_for_t<resource_kind::devices>::identifier());
    META_AUTH_CHECK_EQ(record->rights_bits, read_write.bits());
}

META_AUTH_TEST("gate", "a_capability_without_the_right_is_refused_and_recorded") {
    audit_trail trail;
    device_gate mediator{trail};
    auto read_capability = device_authority().mint<read_only>();

    // The proof says the policy allows `modify`; the capability says this
    // holder does not hold `write`. Both are required, so the gate refuses --
    // and the refusal is what makes the distinction between "authorised" and
    // "permitted here" visible.
    const auto outcome = mediator.admit<action::modify, read_only, admin_principal>(
        read_capability, proof_for_modify());
    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::insufficient_rights);

    const auto record = trail.last();
    META_AUTH_REQUIRE(record.has_value());
    META_AUTH_CHECK_EQ(record->outcome, audit_outcome::denied_insufficient_rights);
    META_AUTH_CHECK_EQ(record->capability_serial, read_capability.serial());
}

META_AUTH_TEST("gate", "a_revoked_capability_is_refused_and_recorded") {
    audit_trail trail;
    device_gate mediator{trail};
    auto capability_value = device_authority().mint<read_write>();

    // Bound to a local before the macro: the template argument list contains
    // commas, and a macro argument list does not know about angle brackets.
    const meta_auth::status first_admission = mediator.admit<action::observe, read_write,
                                                             admin_principal>(capability_value,
                                                                               proof_for_observe());
    META_AUTH_CHECK(first_admission.has_value());

    static_cast<void>(meta_auth::revoke_all<meta_auth::resource_for_t<resource_kind::devices>>());

    // The capability is still a valid value with the right rights; it is simply
    // no longer current, and the gate says so with a distinct error -- which is
    // what lets an operator distinguish a revocation from a permissions bug.
    const auto outcome = mediator.admit<action::observe, read_write, admin_principal>(
        capability_value, proof_for_observe());
    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::capability_revoked);

    const auto record = trail.last();
    META_AUTH_REQUIRE(record.has_value());
    META_AUTH_CHECK_EQ(record->outcome, audit_outcome::denied_revoked);
}

META_AUTH_TEST("gate", "every_decision_produces_exactly_one_record") {
    audit_trail trail;
    device_gate mediator{trail};
    auto strong = device_authority().mint<read_write>();
    auto weak = device_authority().mint<read_only>();

    static_cast<void>(mediator.admit<action::observe, read_write, admin_principal>(
        strong, proof_for_observe()));
    static_cast<void>(mediator.admit<action::modify, read_only, admin_principal>(
        weak, proof_for_modify()));
    static_cast<void>(mediator.admit<action::modify, read_write, admin_principal>(
        strong, proof_for_modify()));

    META_AUTH_CHECK_EQ(trail.recorded(), std::uint64_t{3});
    std::array<audit_event, 8> buffer{};
    const std::size_t count = trail.snapshot(buffer);
    META_AUTH_REQUIRE_EQ(count, std::size_t{3});
    META_AUTH_CHECK_EQ(buffer[0].outcome, audit_outcome::granted);
    META_AUTH_CHECK_EQ(buffer[1].outcome, audit_outcome::denied_insufficient_rights);
    META_AUTH_CHECK_EQ(buffer[2].outcome, audit_outcome::granted);
}

// ---------------------------------------------------------------------------
// Protected objects
// ---------------------------------------------------------------------------
META_AUTH_TEST("protected_object", "reading_requires_observe_and_the_read_right") {
    audit_trail trail;
    device_gate mediator{trail};
    protected_object<std::uint32_t, resource_kind::devices> registry{0x1234U};

    auto reader = device_authority().mint<read_only>();
    const auto value = registry.read<read_only, admin_principal>(reader, proof_for_observe(),
                                                                 mediator);
    META_AUTH_REQUIRE(value.has_value());
    META_AUTH_CHECK_EQ(*value, 0x1234U);
    META_AUTH_CHECK_EQ(trail.last()->outcome, audit_outcome::granted);
}

META_AUTH_TEST("protected_object", "writing_requires_modify_and_the_write_right") {
    audit_trail trail;
    device_gate mediator{trail};
    protected_object<std::uint32_t, resource_kind::devices> registry{1U};

    auto writer = device_authority().mint<read_write>();
    const auto write_outcome =
        registry.write<read_write, admin_principal>(writer, proof_for_modify(), mediator, 2U);
    META_AUTH_CHECK(write_outcome.has_value());

    const auto read_back =
        registry.read<read_write, admin_principal>(writer, proof_for_observe(), mediator);
    META_AUTH_REQUIRE(read_back.has_value());
    META_AUTH_CHECK_EQ(*read_back, 2U);
}

META_AUTH_TEST("protected_object", "a_read_only_capability_cannot_write") {
    audit_trail trail;
    device_gate mediator{trail};
    protected_object<std::uint32_t, resource_kind::devices> registry{1U};

    auto reader = device_authority().mint<read_only>();
    const auto outcome =
        registry.write<read_only, admin_principal>(reader, proof_for_modify(), mediator, 2U);

    META_AUTH_REQUIRE(!outcome.has_value());
    META_AUTH_CHECK_EQ(outcome.error(), meta_auth::auth_error::insufficient_rights);

    // The value is unchanged. A refused write that had already modified the
    // object would be the worst of both worlds: no authority and an effect.
    auto strong = device_authority().mint<read_write>();
    const auto unchanged =
        registry.read<read_write, admin_principal>(strong, proof_for_observe(), mediator);
    META_AUTH_REQUIRE(unchanged.has_value());
    META_AUTH_CHECK_EQ(*unchanged, 1U);
    META_AUTH_CHECK_EQ(trail.last()->outcome, audit_outcome::granted);
}

META_AUTH_TEST("protected_object", "the_confused_deputy_has_nothing_to_be_confused_about") {
    // A deputy is a component that acts for a caller. In a system with ambient
    // authority it holds authority of its own and can be tricked into using it
    // for a caller who lacks it. Here it holds nothing: the capability is a
    // parameter, and a caller that does not have one cannot supply one, because
    // capabilities cannot be constructed.
    //
    // What this case asserts at run time is the weaker, still useful half: the
    // deputy performs exactly the operation it was handed authority for, and a
    // capability that is too weak is refused -- with the refusal recorded
    // against the *capability*, not against the deputy.
    struct deputy {
        [[nodiscard]] static auto act_for(const capability<
                                              meta_auth::resource_for_t<resource_kind::devices>,
                                              read_only>& presented,
                                          device_gate& mediator)
            -> meta_auth::result<std::uint32_t> {
            protected_object<std::uint32_t, resource_kind::devices> registry{7U};
            return registry.read<read_only, admin_principal>(presented, proof_for_observe(),
                                                             mediator);
        }
    };

    audit_trail trail;
    device_gate mediator{trail};
    auto caller_capability = device_authority().mint<read_only>();

    const auto outcome = deputy::act_for(caller_capability, mediator);
    META_AUTH_REQUIRE(outcome.has_value());
    META_AUTH_CHECK_EQ(*outcome, 7U);

    // The deputy could not have done more: `act_for` takes a read-only
    // capability, and there is no overload that takes a write proof. The
    // compile-failure suite asserts that the write variant does not exist.
    META_AUTH_CHECK_EQ(trail.recorded(), std::uint64_t{1});
}
