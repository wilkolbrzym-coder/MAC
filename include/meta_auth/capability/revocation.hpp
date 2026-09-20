// ===========================================================================
//  meta-auth-core -- revocation epochs.
//
//  Revocation is the hard half of a capability system. Capabilities are
//  unforgeable and uncopyable, which is what makes them safe to hand out, and
//  it is also what makes them impossible to take back: there is no list to
//  remove an entry from, because the holder's copy is the only record.
//
//  The mechanism here is an epoch. Every capability records the epoch it was
//  minted in; every resource has one current epoch. Advancing the epoch makes
//  every capability minted before it stale, in one operation, without touching
//  any holder. A gate compares the two before honouring a capability, and the
//  comparison is a single 64-bit equality.
//
//  Two properties make this work rather than merely sound:
//
//    * the epoch is per *resource type*, stored in a function-local static, so
//      a lookup is a load and there is no table to size, scan or lock;
//    * the comparison happens at the gate, which is the only path to the
//      resource, so a stale capability cannot be used by any route that this
//      library mediates. A capability held across a revocation is not
//      invalidated -- it is *rejected*, which is what allows the rejection to
//      be audited and reported rather than being a silent no-op.
//
//  The unmediated route -- a caller that ignores the API -- is out of scope
//  and is listed as such in docs/threat-model.md.
// ===========================================================================
#ifndef META_AUTH_CAPABILITY_REVOCATION_HPP
#define META_AUTH_CAPABILITY_REVOCATION_HPP

#include "meta_auth/config.hpp"

#include <atomic>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace meta_auth {

/// A generation counter for a resource type.
///
/// A distinct type rather than a bare integer so that an epoch cannot be
/// compared with, or assigned from, a serial number or a length.
class revocation_epoch {
public:
    /// The first generation. Every capability minted before any revocation
    /// carries this value.
    static constexpr std::uint64_t initial_value = 0;

    constexpr revocation_epoch() noexcept = default;

    explicit constexpr revocation_epoch(std::uint64_t value) noexcept : value_(value) {}

    [[nodiscard]] constexpr auto value() const noexcept -> std::uint64_t { return value_; }

    /// True when this epoch is the initial one, i.e. nothing has been revoked.
    [[nodiscard]] constexpr auto is_initial() const noexcept -> bool {
        return value_ == initial_value;
    }

    /// The next generation.
    [[nodiscard]] constexpr auto next() const noexcept -> revocation_epoch {
        return revocation_epoch{value_ + 1U};
    }

    friend constexpr auto operator==(revocation_epoch, revocation_epoch) noexcept
        -> bool = default;

    /// Ordering exists so that a gate can report *how far* behind a stale
    /// capability is, which is useful when the answer is "revoked four
    /// generations ago".
    friend constexpr auto operator<=>(revocation_epoch, revocation_epoch) noexcept
        -> std::strong_ordering = default;

private:
    std::uint64_t value_ = initial_value;
};

namespace detail {

/// The epoch slot for a resource type.
///
/// A function-local static rather than a global table: one slot per resource
/// type, initialised on first use, thread-safe by the language's guarantee for
/// block-scope statics. Revocation therefore costs one atomic load at the gate
/// and needs no registry to be sized, scanned or locked.
template <typename Resource>
[[nodiscard]] auto epoch_slot() noexcept -> std::atomic<std::uint64_t>& {
    static std::atomic<std::uint64_t> slot{revocation_epoch::initial_value};
    return slot;
}

} // namespace detail

/// The current epoch of a resource type.
template <typename Resource>
[[nodiscard]] auto current_epoch() noexcept -> revocation_epoch {
    return revocation_epoch{detail::epoch_slot<Resource>().load(std::memory_order_acquire)};
}

/// Advance the epoch of a resource type, invalidating every capability minted
/// before this call.
///
/// Returns the new epoch. The operation is a single atomic increment, so
/// concurrent revocations all take effect and the resulting epoch is the
/// number of revocations that happened -- which the concurrency test asserts,
/// because an implementation using a load-then-store would lose them.
template <typename Resource>
[[nodiscard]] auto revoke_all() noexcept -> revocation_epoch {
    const std::uint64_t previous =
        detail::epoch_slot<Resource>().fetch_add(1, std::memory_order_acq_rel);
    return revocation_epoch{previous + 1U};
}

/// True when a capability minted in `minted_in` may still be honoured.
///
/// Equality rather than "greater than or equal": an epoch that is *ahead* of
/// the current one is not a capability from the future to be trusted, it is a
/// value that did not come from this resource's counter, and treating it as
/// valid would be a way to bypass revocation by inventing an epoch.
[[nodiscard]] constexpr auto epoch_is_current(revocation_epoch minted_in,
                                              revocation_epoch current) noexcept -> bool {
    return minted_in == current;
}

/// Describe the age of a stale capability, for the audit record.
[[nodiscard]] constexpr auto epochs_behind(revocation_epoch minted_in,
                                           revocation_epoch current) noexcept -> std::uint64_t {
    return minted_in < current ? (current.value() - minted_in.value()) : 0U;
}

} // namespace meta_auth

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
template <>
struct std::formatter<meta_auth::revocation_epoch, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(meta_auth::revocation_epoch epoch, std::format_context& context) const {
        return std::format_to(context.out(), "epoch#{}", epoch.value());
    }
};

#endif // META_AUTH_CAPABILITY_REVOCATION_HPP
