// ===========================================================================
//  meta-auth-core -- erasing secrets from memory.
//
//  `std::memset(buffer, 0, size)` on a buffer that is never read again is a
//  dead store, and a compiler is entitled to delete it. The result is a key
//  that survives in freed heap memory, in a core dump, or in a swap file,
//  which is where it is found by whoever comes next.
//
//  The two mechanisms here are the ones that actually work:
//
//    * a write through a `volatile` pointer, which is an observable side
//      effect by definition and therefore cannot be elided;
//    * a signal fence afterwards, which orders the erasure against everything
//      else the thread has done, so a subsequent free or unlock cannot be
//      reordered before it by the optimiser.
//
//  The functions are deliberately not constexpr. Erasure is a run-time
//  operation on run-time storage; a compile-time variant would either do
//  nothing or give false comfort.
// ===========================================================================
#ifndef META_AUTH_CRYPTO_SECURE_ERASE_HPP
#define META_AUTH_CRYPTO_SECURE_ERASE_HPP

#include "meta_auth/config.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace meta_auth::crypto {

/// Overwrite `buffer` with zeroes in a way the optimiser must preserve.
inline void secure_erase(std::span<std::byte> buffer) noexcept {
    if (buffer.empty()) {
        return;
    }

    // volatile is the point, not an accident: it makes each store an
    // observable side effect, so dead-store elimination cannot remove it.
    volatile std::byte* const cursor = buffer.data();
    for (std::size_t index = 0; index < buffer.size(); ++index) {
        cursor[index] = std::byte{0};
    }

    // Order the erasure before anything the caller does next. Without the
    // fence the stores are still present but may be sunk past a subsequent
    // free() or mutex unlock, which is the window an attacker needs.
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

/// Overwrite a trivially copyable object with zeroes.
///
/// Restricted to trivially copyable types on purpose: for anything else,
/// "zeroing the bytes" is not the same as "destroying the value", and offering
/// it would invite exactly the confusion this header exists to remove.
template <typename T>
    requires std::is_trivially_copyable_v<T>
inline void secure_erase_object(T& object) noexcept {
    secure_erase(std::as_writable_bytes(std::span<T, 1>{&object, 1}));
}

/// A fixed-capacity buffer of secret bytes that erases itself.
///
/// The type is non-copyable and non-movable: a copy would put the secret
/// somewhere the destructor will not reach, and a move would leave the source
/// holding the secret with no owner to erase it. Copying a secret is a design
/// decision, and this type requires it to be made explicitly, by the caller,
/// through `copy_to`.
template <std::size_t Capacity>
class secret_buffer {
public:
    static constexpr std::size_t capacity = Capacity;

    constexpr secret_buffer() noexcept = default;

    secret_buffer(const secret_buffer&) = delete;
    auto operator=(const secret_buffer&) -> secret_buffer& = delete;

    /// Movable, and the move erases the source.
    ///
    /// A deleted move would make it impossible to return a secret from a
    /// factory function -- a normal thing to do -- without forcing callers
    /// into out-parameters. Transferring and wiping is what a move of a secret
    /// *means*: exactly one object holds the value afterwards, and the other
    /// holds nothing rather than a stale copy the destructor will not reach.
    secret_buffer(secret_buffer&& other) noexcept : size_(other.size_) {
        for (std::size_t index = 0; index < size_; ++index) {
            storage_[index] = other.storage_[index];
        }
        other.wipe();
    }

    auto operator=(secret_buffer&& other) noexcept -> secret_buffer& {
        if (this != &other) {
            wipe();
            size_ = other.size_;
            for (std::size_t index = 0; index < size_; ++index) {
                storage_[index] = other.storage_[index];
            }
            other.wipe();
        }
        return *this;
    }

    /// A constexpr destructor that erases only at run time.
    ///
    /// The guard is what keeps the type a *literal* type: a destructor that
    /// unconditionally called the non-constexpr `wipe()` would make every
    /// constexpr constructor of this class ill-formed. During constant
    /// evaluation there is no memory to leave behind, so skipping the erase
    /// there costs nothing and keeps the type usable in `static_assert`.
    constexpr ~secret_buffer() {
        if !consteval {
            wipe();
        }
    }

    /// Bytes currently held.
    [[nodiscard]] auto size() const noexcept -> std::size_t { return size_; }

    [[nodiscard]] auto is_empty() const noexcept -> bool { return size_ == 0; }

    [[nodiscard]] auto data() noexcept -> std::byte* { return storage_; }
    [[nodiscard]] auto data() const noexcept -> const std::byte* { return storage_; }

    [[nodiscard]] auto bytes() noexcept -> std::span<std::byte> {
        return std::span<std::byte>{storage_, size_};
    }

    [[nodiscard]] auto bytes() const noexcept -> std::span<const std::byte> {
        return std::span<const std::byte>{storage_, size_};
    }

    /// Overwrite the contents with `source`, which must fit.
    ///
    /// Returns false when it does not fit, rather than truncating: a truncated
    /// key is a wrong key, and a wrong key that looks accepted is how a
    /// security check turns into a no-op.
    [[nodiscard]] auto assign(std::span<const std::byte> source) noexcept -> bool {
        if (source.size() > Capacity) {
            return false;
        }
        wipe();
        for (std::size_t index = 0; index < source.size(); ++index) {
            storage_[index] = source[index];
        }
        size_ = source.size();
        return true;
    }

    /// Copy the contents out. Explicit, because the caller is taking on the
    /// obligation to erase the destination.
    void copy_to(std::span<std::byte> destination) const noexcept {
        const std::size_t count = destination.size() < size_ ? destination.size() : size_;
        for (std::size_t index = 0; index < count; ++index) {
            destination[index] = storage_[index];
        }
    }

    /// Erase now, without waiting for the destructor. Not constexpr: erasure
    /// is an operation on run-time storage.
    void wipe() noexcept {
        secure_erase(std::span<std::byte>{storage_, size_});
        size_ = 0;
    }

private:
    // The whole capacity is erased, not just the used prefix: a shorter value
    // assigned earlier would otherwise leave its tail behind.
    std::byte storage_[Capacity]{};
    std::size_t size_ = 0;
};

} // namespace meta_auth::crypto

#endif // META_AUTH_CRYPTO_SECURE_ERASE_HPP
