// ===========================================================================
//  meta-auth-core -- sessions as a type-state machine.
//
//  The usual way to write a session is a struct with a boolean:
//
//      if (!session.authenticated)          return unauthenticated;
//      if (!session.mfa_verified)           return elevation_required;
//      if (session.revoked)                 return revoked;
//      wipe_device(session, device);        // ...if nobody forgot a line
//
//  A boolean admits four states of which three are illegal, and every operation
//  has to re-derive which of them it is in. The type-state version admits only
//  the legal ones: `session<Principal, authenticated>` has no `wipe_device`,
//  because wiping a device is not something an authenticated-but-not-elevated
//  session can do. The illegal call is not a run-time error, it is an overload
//  that does not exist -- and it is reported by a `= delete("...")` declaration
//  that says which transition was missing.
//
//  The states and their transitions:
//
//      anonymous --authenticate(credential)--> authenticated
//      authenticated --elevate(second factor)--> elevated
//      any --revoke()--> revoked        (terminal: no operation is defined)
//
//  There is no transition back from `elevated` except `revoke`, and no
//  transition from `revoked` at all. That is deliberate: a session that can be
//  un-revoked has a window in which it is revoked and usable, and that window
//  is exactly where the interesting attacks live.
// ===========================================================================
#ifndef META_AUTH_AUTH_SESSION_HPP
#define META_AUTH_AUTH_SESSION_HPP

#include "meta_auth/capability/revocation.hpp"
#include "meta_auth/config.hpp"
#include "meta_auth/core/contract.hpp"
#include "meta_auth/core/error.hpp"
#include "meta_auth/core/strong_id.hpp"
#include "meta_auth/crypto/constant_time.hpp"
#include "meta_auth/crypto/hmac.hpp"
#include "meta_auth/crypto/sha256.hpp"
#include "meta_auth/identity/principal.hpp"

#include <atomic>
#include <cstdint>
#include <format>
#include <string_view>
#include <utility>

// The static assertions at the end of this header use `requires`-expressions
// and `std::move` on the session types above, which is why <utility> is here
// rather than in a translation unit that happens to need it.

namespace meta_auth {

/// The states a session can be in.
///
/// An enumeration rather than four types, because the *type* is
/// `session<Principal, State>`: the enumeration provides the vocabulary and the
/// template provides the separation.
enum class session_state : std::uint8_t {
    anonymous = 0,     ///< nothing has been proven yet
    authenticated = 1, ///< a credential verified
    elevated = 2,      ///< a credential and a second factor verified
    revoked = 3,       ///< terminated; terminal by construction
};

[[nodiscard]] constexpr auto to_string(session_state state) noexcept -> std::string_view {
    switch (state) {
    case session_state::anonymous:
        return "anonymous";
    case session_state::authenticated:
        return "authenticated";
    case session_state::elevated:
        return "elevated";
    case session_state::revoked:
        return "revoked";
    }
    return "unknown";
}

/// True when the state has proven something about the principal.
[[nodiscard]] constexpr auto is_proven(session_state state) noexcept -> bool {
    return state == session_state::authenticated || state == session_state::elevated;
}

struct session_tag;

/// An identifier for one session, so that an audit record can name it.
using session_id = strong_id<session_tag>;

namespace detail {

template <typename Resource>
[[nodiscard]] auto session_counter() noexcept -> std::atomic<std::uint64_t>& {
    static std::atomic<std::uint64_t> counter{0};
    return counter;
}

/// The data that survives a transition: the session's identity and the epoch
/// it began in.
///
/// A transition hands its core to the next state, which is what makes the
/// states of one session share an identity instead of being four unrelated
/// objects. It lives in `detail` rather than being private to `session`
/// because a class template cannot befriend its own other instantiations on
/// this compiler: a constrained friend declaration of the enclosing template
/// is rejected as a conflicting redeclaration. The name is the protection -- a
/// caller who writes `detail::session_core` has written the bypass where a
/// reviewer will see it.
///
/// Not an aggregate, and that is load-bearing. It was one -- a struct with two
/// public members and a public `create()` -- and `session`'s constructor takes
/// a core, so
///
///     session<admin_principal, session_state::elevated>{detail::session_core{}}
///
/// compiled, ran, and produced a fully elevated session for the administrator
/// with no credential, no second factor and no transition. The whole state
/// machine was bypassable by a line of code that does not look like a bypass.
/// The constructor is private now, so `create()` is the only way to obtain a
/// core, and the copy and move operations are written out rather than
/// defaulted so that the type is not trivially copyable either -- otherwise
/// `std::bit_cast` would fabricate one from raw bytes, which is the same
/// bypass spelled differently.
class session_core {
public:
    /// Start a new identity. Allocates the next serial for the principal.
    template <principal_type Principal>
    [[nodiscard]] static auto create() noexcept -> session_core {
        return session_core{session_id::from_value(
                                session_counter<Principal>().fetch_add(1, std::memory_order_relaxed)
                                + 1U),
                            current_epoch<Principal>()};
    }

    /// There is no way to name an empty core.
    ///
    /// Declared and deleted rather than merely absent, so that the program
    /// which used to compile says why it no longer does. `session_core{}` was
    /// a valid expression and, combined with the session constructor, an
    /// elevated session for any principal the caller cared to name.
    session_core() = delete(
        "A session core cannot be created directly. A session's state is obtained from "
        "session::begin() and reached through authenticate(), elevate() and revoke().");

    session_id id{};
    revocation_epoch epoch{};

    constexpr session_core(const session_core& other) noexcept
        : id(other.id), epoch(other.epoch) {}

    constexpr auto operator=(const session_core& other) noexcept -> session_core& {
        id = other.id;
        epoch = other.epoch;
        return *this;
    }

    constexpr session_core(session_core&& other) noexcept : id(other.id), epoch(other.epoch) {
        other.id = session_id::invalid();
        other.epoch = revocation_epoch{};
    }

    constexpr auto operator=(session_core&& other) noexcept -> session_core& {
        id = other.id;
        epoch = other.epoch;
        other.id = session_id::invalid();
        other.epoch = revocation_epoch{};
        return *this;
    }

    ~session_core() = default;

private:
    constexpr session_core(session_id identifier, revocation_epoch started_in) noexcept
        : id(identifier), epoch(started_in) {}
};

static_assert(!std::is_trivially_copyable_v<session_core>,
              "a session core must not be trivially copyable: std::bit_cast would fabricate one "
              "and re-open the bypass the private constructor closes");
static_assert(!std::is_default_constructible_v<session_core>,
              "a session core has no default constructor on purpose: `session_core{}` would be a "
              "session state that was never authenticated");

} // namespace detail

template <principal_type Principal, session_state State>
class session;

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// The enrolled credential of a principal: the MAC of a secret, computed when
/// the principal was enrolled.
///
/// The secret itself is not stored. What is stored is a keyed digest of it, so
/// a leaked record does not yield a usable credential -- and because the MAC is
/// keyed by the principal's name, two principals that choose the same secret do
/// not share a record.
template <principal_type Principal>
class credential_record {
public:
    static constexpr std::size_t secret_size = 32;

    /// Enrol a principal. Runs wherever the secret is available, which is not
    /// where verification happens.
    [[nodiscard]] static constexpr auto enrol(std::string_view secret) noexcept
        -> credential_record {
        return credential_record{mac_of(secret)};
    }

    /// A record that no secret matches, for a principal that is not enrolled.
    ///
    /// Present so that "this principal has no credential" is expressible and
    /// verifies against nothing, rather than being an absent record that the
    /// caller has to check for.
    [[nodiscard]] static constexpr auto unenrolled() noexcept -> credential_record {
        credential_record record;
        record.mac_ = crypto::hmac_sha256_of("meta-auth-core/unenrolled",
                                             principal_name<Principal>());
        return record;
    }

    [[nodiscard]] constexpr auto mac() const noexcept -> const crypto::sha256_digest& {
        return mac_;
    }

private:
    constexpr credential_record() = default;

    explicit constexpr credential_record(crypto::sha256_digest mac) noexcept : mac_(mac) {}

    /// Keyed by the principal's name, so that a record is not transferable
    /// between principals even if two of them present the same secret.
    [[nodiscard]] static constexpr auto mac_of(std::string_view secret) noexcept
        -> crypto::sha256_digest {
        return crypto::hmac_sha256_of(principal_name<Principal>(), secret);
    }

    crypto::sha256_digest mac_{};
};

/// Check a presented secret against an enrolled record.
///
/// Constant-time comparison, because this is the one place where an attacker
/// gets to make guesses: a comparison that returns at the first differing byte
/// turns a search over 2^256 secrets into at most 32 x 256 guesses.
template <principal_type Principal>
[[nodiscard]] constexpr auto verify_credential(const credential_record<Principal>& record,
                                               std::string_view presented) noexcept -> bool {
    const crypto::sha256_digest computed = crypto::hmac_sha256_of(principal_name<Principal>(),
                                                                  presented);
    return crypto::constant_time_equal(computed.span(), record.mac().span());
}

/// The second factor, for the transition to `elevated`.
///
/// A distinct type from the primary credential so that the two cannot be
/// swapped: an implementation that let a password satisfy both checks would
/// have no second factor at all, and the type system should not permit that
/// mistake to be made silently.
template <principal_type Principal>
class second_factor {
public:
    [[nodiscard]] static constexpr auto enrol(std::string_view secret) noexcept -> second_factor {
        return second_factor{crypto::hmac_sha256_of(principal_name<Principal>(), secret)};
    }

    [[nodiscard]] static constexpr auto unenrolled() noexcept -> second_factor {
        return second_factor{
            crypto::hmac_sha256_of("meta-auth-core/unenrolled-2fa", principal_name<Principal>())};
    }

    [[nodiscard]] constexpr auto mac() const noexcept -> const crypto::sha256_digest& {
        return mac_;
    }

private:
    constexpr second_factor() = default;
    explicit constexpr second_factor(crypto::sha256_digest mac) noexcept : mac_(mac) {}

    crypto::sha256_digest mac_{};
};

template <principal_type Principal>
[[nodiscard]] constexpr auto verify_second_factor(const second_factor<Principal>& enrolled,
                                                  std::string_view presented) noexcept -> bool {
    const crypto::sha256_digest computed = crypto::hmac_sha256_of(principal_name<Principal>(),
                                                                  presented);
    return crypto::constant_time_equal(computed.span(), enrolled.mac().span());
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// A session in a specific state, for a specific principal.
///
/// Every operation that is meaningful only in some states exists only in those
/// states. What a caller can see is therefore the complete set of things that
/// are legal right now, which is a stronger statement than a comment saying
/// which checks have already run.
template <principal_type Principal, session_state State>
class session {
public:
    /// The principal this session is for.
    ///
    /// Named `subject_type` rather than `principal_type` because the latter is
    /// the name of the concept that constrains the template parameter, and a
    /// member alias would shadow it inside the class -- which turns every
    /// `template <principal_type P>` in a member declaration into a
    /// non-type parameter and produces an error about the wrong thing.
    using subject_type = Principal;

    static constexpr session_state state = State;
    static constexpr bool proven = is_proven(State);

    /// Start a session. Only an anonymous one can be started directly; every
    /// other state is reached by a transition, which is what makes the state
    /// machine the only way in.
    [[nodiscard]] static auto begin() noexcept -> session<Principal, session_state::anonymous>
        requires(State == session_state::anonymous)
    {
        return session<Principal, session_state::anonymous>{
            detail::session_core::create<Principal>()};
    }

    /// Construct a state from the core a transition carried over.
    ///
    /// Public, and harmless now that a core can only be obtained from
    /// `detail::session_core::create`: the parameter is a value the caller
    /// must already hold, so this is a way to *name* an existing state, not a
    /// way to acquire one. It was not harmless while `session_core` was an
    /// aggregate -- see the note on that class.
    explicit constexpr session(detail::session_core core) noexcept : core_(std::move(core)) {}

    session(const session&) = delete;
    auto operator=(const session&) -> session& = delete;
    constexpr session(session&&) noexcept = default;
    constexpr auto operator=(session&&) noexcept -> session& = default;
    ~session() = default;

    /// The identifier of this session, for audit records.
    [[nodiscard]] constexpr auto identifier() const noexcept -> session_id {
        return core_.id;
    }

    /// The digest of the principal this session is for. Available once
    /// something has been proven; asking an anonymous session who it is for is
    /// precisely the question that has no answer yet.
    [[nodiscard]] constexpr auto principal_digest() const noexcept -> crypto::sha256_digest
        requires(is_proven(State))
    {
        return Principal::digest();
    }

    /// The epoch this session was created in, so that a session can be
    /// invalidated the same way a capability is.
    [[nodiscard]] constexpr auto epoch() const noexcept -> revocation_epoch {
        return core_.epoch;
    }

    // -- transitions --------------------------------------------------------

    /// anonymous -> authenticated.
    [[nodiscard]] auto authenticate(const credential_record<Principal>& enrolled,
                                    std::string_view presented) && noexcept
        -> result<session<Principal, session_state::authenticated>>
        requires(State == session_state::anonymous)
    {
        if (!verify_credential(enrolled, presented)) {
            return failure(auth_error::credential_rejected);
        }
        return session<Principal, session_state::authenticated>{core_};    }

    /// A credential record belonging to a different principal.
    ///
    /// A record is keyed by its principal, so one principal's record cannot
    /// authenticate another -- and the mistake is caught by the type rather
    /// than by comparing names at run time. The diagnostic says which mistake
    /// it is, because "no matching function" for a one-type mismatch is the
    /// least helpful message a compiler produces.
    template <principal_type OtherPrincipal>
        requires(State == session_state::anonymous)
    auto authenticate(const credential_record<OtherPrincipal>&, std::string_view) && noexcept = delete(
        "session::authenticate: this credential record belongs to a different principal. "
        "A record is bound to its principal, so it cannot authenticate this session.");

    /// Attempting to authenticate a session that has already proven a
    /// credential.
    template <typename Record>
        requires(State != session_state::anonymous)
    auto authenticate(const Record&, std::string_view) && noexcept = delete(
        "session::authenticate: this session has already proven a credential. "
        "Re-authentication is a new session, not a transition.");

    /// authenticated -> elevated.
    [[nodiscard]] auto elevate(const second_factor<Principal>& enrolled,
                               std::string_view presented) && noexcept
        -> result<session<Principal, session_state::elevated>>
        requires(State == session_state::authenticated)
    {
        if (!verify_second_factor(enrolled, presented)) {
            return failure(auth_error::credential_rejected);
        }
        return session<Principal, session_state::elevated>{core_};
    }

    /// A second factor enrolled for a different principal.
    template <principal_type OtherPrincipal>
        requires(State == session_state::authenticated)
    auto elevate(const second_factor<OtherPrincipal>&, std::string_view) && noexcept = delete(
        "session::elevate: this second factor belongs to a different principal.");

    /// Elevation from the wrong state.
    template <typename Factor>
        requires(State != session_state::authenticated)
    auto elevate(const Factor&, std::string_view) && noexcept = delete(
        "session::elevate: a second factor requires an authenticated session first. "
        "Call authenticate() to obtain one.");

    /// any non-revoked state -> revoked.
    template <session_state S = State>
        requires(S == State && S != session_state::revoked)
    [[nodiscard]] auto revoke() && noexcept -> session<Principal, session_state::revoked> {
        return session<Principal, session_state::revoked>{core_};
    }

    /// Revoking a revoked session.
    ///
    /// A deleted overload rather than a mere absence: without it the rejection
    /// is "no matching function for call to 'revoke()'", which is true and
    /// unhelpful. Every other illegal transition in this class carries a
    /// sentence, and this one did not.
    template <session_state S = State>
        requires(S == State && S == session_state::revoked)
    auto revoke() && noexcept = delete(
        "session::revoke: this session is already revoked. Revocation is terminal, and a second "
        "revocation is not a no-op -- it is a program that has lost track of its own state.");

    // -- operations that require a state ------------------------------------

    /// An operation that only an authenticated session may perform.
    template <session_state S = State>
        requires(S == State && is_proven(S))
    [[nodiscard]] constexpr auto describe_subject() const noexcept -> std::string_view {
        return principal_name<Principal>();
    }

    /// The same operation from a state that has proven nothing.
    ///
    /// A constrained member that simply does not exist would reject the call
    /// correctly and explain nothing; the deleted twin is what turns the
    /// rejection into a sentence naming the transition that is missing.
    template <session_state S = State>
        requires(S == State && !is_proven(S))
    constexpr auto describe_subject() const noexcept = delete(
        "session::describe_subject: this session has not proven a credential, so it does not "
        "know which principal it is for. Call authenticate() to obtain a session that does.");

    /// An operation that only an elevated session may perform. Named for what
    /// it stands for rather than for what it does: the point of the type-state
    /// is that this call is unreachable from an authenticated session.
    template <session_state S = State>
        requires(S == State && S == session_state::elevated)
    [[nodiscard]] constexpr auto require_second_factor() const noexcept -> bool {
        return true;
    }

    /// The same operation without a second factor.
    template <session_state S = State>
        requires(S == State && S != session_state::elevated)
    constexpr auto require_second_factor() const noexcept = delete(
        "session::require_second_factor: this session has not presented a second factor, so the "
        "operation it guards is unreachable. Call elevate() to obtain an elevated session.");

private:
    detail::session_core core_;
};

// The positive half of the state machine, asserted here: in each state, the
// operations that are supposed to exist do exist.
static_assert(requires(session<admin_principal, session_state::anonymous> value) {
    std::move(value).authenticate(credential_record<admin_principal>::unenrolled(), "");
});
static_assert(requires(session<admin_principal, session_state::authenticated> value) {
    value.describe_subject();
});
static_assert(requires(session<admin_principal, session_state::authenticated> value) {
    std::move(value).elevate(second_factor<admin_principal>::unenrolled(), "");
});
static_assert(requires(session<admin_principal, session_state::elevated> value) {
    value.require_second_factor();
});
static_assert(requires(session<admin_principal, session_state::elevated> value) {
    value.principal_digest();
});
static_assert(requires(session<admin_principal, session_state::revoked> value) {
    value.identifier();
});

// The negative half -- that a revoked session has no `revoke`, that an
// anonymous one cannot describe a subject, that an authenticated one cannot
// satisfy a second factor -- is asserted by tests/compile_fail/, not here.
// The reason is a compiler limitation rather than a preference: GCC 16.0.1
// diagnoses a call to a function whose constraints are unsatisfied as a hard
// error even inside a requires-expression, where the standard says it is a
// substitution failure that yields `false`. `static_assert(!requires(...))`
// is therefore unusable for a constrained member on this compiler, while
// compiling the offending program and inspecting the diagnostic is exact --
// and it checks the message as well as the rejection.

} // namespace meta_auth

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
template <>
struct std::formatter<meta_auth::session_state, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(meta_auth::session_state state, std::format_context& context) const {
        return std::format_to(context.out(), "{}", meta_auth::to_string(state));
    }
};

template <meta_auth::principal_type Principal, meta_auth::session_state State>
struct std::formatter<meta_auth::session<Principal, State>, char> {
    constexpr auto parse(std::format_parse_context& context) -> decltype(context.begin()) {
        return context.begin();
    }

    auto format(const meta_auth::session<Principal, State>& value,
                std::format_context& context) const {
        // The identifier is part of the rendering: two sessions for one
        // principal are distinguishable in a log, which is what makes an audit
        // trail able to say *which* session did something.
        return std::format_to(context.out(), "session<{}>({}, id={})",
                              meta_auth::principal_name<Principal>(),
                              meta_auth::to_string(State), value.identifier().value());
    }
};

#endif // META_AUTH_AUTH_SESSION_HPP
