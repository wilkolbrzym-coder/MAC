// ===========================================================================
//  meta-auth-core -- contract assertions and the fail-stop path.
//
//  Contracts are how this library states the things that are *not* the
//  caller's business: an invariant that must hold, a precondition a caller
//  violated, a postcondition the implementation failed to meet. They are not
//  error handling. A domain error is a value (core/error.hpp); a broken
//  invariant terminates the process, because a security component that
//  continues after its invariants are broken is the definition of a
//  vulnerability (docs/DESIGN-PRINCIPLES.md, P7).
//
//  Two forms, and both are needed
//  ------------------------------
//    * Declarator contracts -- `META_AUTH_PRE(...)`, `META_AUTH_POST(...)` --
//      appear in the function's declarator, where they document the interface
//      and are enforced by the compiler under P2900. They expand to nothing
//      on a compiler without contract support.
//    * Statement contracts -- `META_AUTH_EXPECTS`, `META_AUTH_ENSURES`,
//      `META_AUTH_ASSERT` -- expand to `contract_assert` where contracts
//      exist, and to a portable check with the *same report and the same
//      abort* where they do not.
//
//  The pairing rule: a function that declares `META_AUTH_PRE(x)` writes
//  `META_AUTH_PRE_FALLBACK(x)` as the first statement of its body. The
//  fallback expands to nothing exactly when the declarator contract was
//  emitted, so the fact is checked once in either build, and the portable
//  build is not a weaker build. `ctest --preset portable` runs the same
//  fail-stop tests as `ctest --preset dev`, which is what makes that claim
//  checkable rather than rhetorical.
//
//  Reports, not just aborts
//  ------------------------
//  The library installs its own `handle_contract_violation`, the hook P2900
//  leaves to the program. It produces a structured report, offers the record
//  to an observer (so an application can route a violation into its audit
//  trail before dying) and then aborts. The portable fallback goes through the
//  same function, so a violation reads identically whichever dialect features
//  the build has. The report is formatted into a caller-provided buffer: the
//  path that ends the process must not be able to fail on an allocation.
//
//  A known limitation of the reference compiler
//  --------------------------------------------
//  GCC 16.0.1 rejects the initialisation of a scalar `constexpr` variable from
//  a call to a function that declares a *named-result* postcondition, with
//  "contract condition is not constant". `static_assert`, aggregate
//  initialisation and run-time calls are all accepted. The rule this project
//  follows as a result: named-result postconditions are used on functions that
//  are verified by `static_assert`, and in-body `META_AUTH_ENSURES` is used
//  where a `constexpr` variable initialiser has to work. The reproduction and
//  the rule are recorded in docs/contracts.md and pinned by
//  tests/core/test_contract.cpp.
// ===========================================================================
#ifndef META_AUTH_CORE_CONTRACT_HPP
#define META_AUTH_CORE_CONTRACT_HPP

#include "meta_auth/config.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <span>
#include <string_view>

#if META_AUTH_HAS_CONTRACTS
#include <contracts>
#include <source_location>
#endif

namespace meta_auth::diag {

// ---------------------------------------------------------------------------
// What a violation is made of
// ---------------------------------------------------------------------------

/// Which kind of contract was violated. Mirrors P2900's `assertion_kind`,
/// restated here so that the portable path can produce the same report without
/// the `<contracts>` header.
enum class violation_kind : std::uint8_t {
    precondition = 1, ///< a `pre` contract
    postcondition = 2,///< a `post` contract
    assertion = 3,    ///< a `contract_assert` in a body
};

/// How the violation is handled. Mirrors P2900's `evaluation_semantic`.
enum class violation_semantic : std::uint8_t {
    ignore = 1,
    observe = 2,     ///< the program is permitted to continue
    enforce = 3,     ///< the program must stop
    quick_enforce = 4,
};

/// How the violation was detected. Mirrors P2900's `detection_mode`.
enum class violation_detection : std::uint8_t {
    predicate_false = 1,     ///< the condition evaluated to false
    evaluation_exception = 2,///< evaluating the condition threw
};

[[nodiscard]] constexpr auto to_string(violation_kind kind) noexcept -> std::string_view {
    switch (kind) {
    case violation_kind::precondition:
        return "precondition";
    case violation_kind::postcondition:
        return "postcondition";
    case violation_kind::assertion:
        return "assertion";
    }
    return "unknown";
}

[[nodiscard]] constexpr auto to_string(violation_semantic semantic) noexcept -> std::string_view {
    switch (semantic) {
    case violation_semantic::ignore:
        return "ignore";
    case violation_semantic::observe:
        return "observe";
    case violation_semantic::enforce:
        return "enforce";
    case violation_semantic::quick_enforce:
        return "quick_enforce";
    }
    return "unknown";
}

[[nodiscard]] constexpr auto to_string(violation_detection detection) noexcept -> std::string_view {
    switch (detection) {
    case violation_detection::predicate_false:
        return "predicate_false";
    case violation_detection::evaluation_exception:
        return "evaluation_exception";
    }
    return "unknown";
}

/// True when the violation must terminate the process.
///
/// This library aborts on every violation, including one reported with
/// `observe` semantics: there is no state in which continuing past a broken
/// invariant has been shown to be safe here. The function exists so that the
/// decision is written down once instead of being implied by the handler body.
[[nodiscard]] constexpr auto must_terminate(violation_semantic semantic) noexcept -> bool {
    return semantic != violation_semantic::observe && semantic != violation_semantic::ignore;
}

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

/// A violation, as the library records it.
///
/// The string members are non-owning and must outlive the record. Every
/// producer in this library passes literals (`__FILE__`, `__func__`, the
/// stringised condition), all of which have static storage duration; the
/// constraint is stated because an observer may keep the record and read it
/// later.
struct violation_record {
    std::string_view expression; ///< the stringised condition
    std::string_view file;       ///< where it was written
    std::string_view function;   ///< the enclosing function, when known
    std::uint32_t line = 0;      ///< line within `file`
    std::uint64_t sequence = 0;  ///< 1-based order of reporting in this process
    violation_kind kind = violation_kind::assertion;
    violation_semantic semantic = violation_semantic::enforce;
    violation_detection detection = violation_detection::predicate_false;
};

/// Size of the buffer a violation report is formatted into. Large enough for a
/// file path, a function name and a full condition; small enough to live on
/// the stack of a function that is about to terminate the process.
inline constexpr std::size_t violation_report_capacity = 1024;

/// Format a report into `buffer` and return the view of what was written.
///
/// Allocation-free by construction, and truncation is explicit: a report that
/// silently loses its second half is worse than one that says it was cut. The
/// result is NUL-terminated when there is room, so it can also be handed to a
/// C API without a copy.
[[nodiscard]] inline auto format_violation(const violation_record& record,
                                           std::span<char> buffer) noexcept -> std::string_view {
    if (buffer.empty()) {
        return {};
    }

    const std::string_view function =
        record.function.empty() ? std::string_view{"<unknown>"} : record.function;
    const std::string_view expression =
        record.expression.empty() ? std::string_view{"<no condition>"} : record.expression;
    const std::string_view file =
        record.file.empty() ? std::string_view{"<no file>"} : record.file;

    // format_to_n takes a signed difference type; the cast is explicit
    // because the conversion is the kind this project compiles with
    // -Wsign-conversion to catch, and it is safe here only because the
    // buffer size is bounded by violation_report_capacity.
    const auto capacity = static_cast<std::ptrdiff_t>(buffer.size());
    const auto result = std::format_to_n(
        buffer.data(), capacity,
        "meta-auth: contract violation\n"
        "  what      : {} ({})\n"
        "  where     : {}:{} in {}\n"
        "  detected  : {}; semantics {}, terminating {}\n"
        "  sequence  : {}\n",
        expression, to_string(record.kind), file, record.line, function,
        to_string(record.detection), to_string(record.semantic),
        must_terminate(record.semantic) ? "yes" : "no", record.sequence);

    std::size_t written = static_cast<std::size_t>(result.out - buffer.data());
    // result.size is the number of characters the report *would* have used.
    const bool truncated = static_cast<std::size_t>(result.size) > buffer.size();

    if (truncated) {
        // Replace the tail with a marker rather than leaving a half-written
        // line: the reader has to know the report is incomplete.
        constexpr std::string_view marker = "...[truncated]";
        const std::size_t keep = buffer.size() > marker.size() ? buffer.size() - marker.size() : 0;
        for (std::size_t index = 0; index < marker.size() && keep + index < buffer.size(); ++index) {
            buffer[keep + index] = marker[index];
        }
        written = keep + marker.size() < buffer.size() ? keep + marker.size() : buffer.size();
    } else {
        buffer[written] = '\0';
    }

    return std::string_view{buffer.data(), written};
}

namespace detail {

/// Violation bookkeeping. Function-local statics rather than namespace-scope
/// objects, so that a translation unit which merely includes the header does
/// not pay for them unless a violation actually happens.
[[nodiscard]] inline auto sequence_counter() noexcept -> std::atomic<std::uint64_t>& {
    static std::atomic<std::uint64_t> counter{0};
    return counter;
}

} // namespace detail

// ---------------------------------------------------------------------------
// Observation hook
// ---------------------------------------------------------------------------

/// Called with the record before the process terminates.
///
/// "Fail stop" and "leave a record" are two requirements, not one: an
/// application routes this into its audit trail so that a violation is visible
/// after the process is gone. Tests use it to assert what was reported without
/// parsing stderr.
using violation_observer = void (*)(void* user, const violation_record& record);

/// Install (or clear, with nullptr) the observer.
///
/// Expected to be called once during start-up, before threads that could
/// violate a contract exist; the slot is atomic so that a violation on another
/// thread sees a consistent observer-or-nullptr.
void set_violation_observer(violation_observer observer, void* user) noexcept;

/// The installed observer, or nullptr.
[[nodiscard]] auto violation_observer_instance() noexcept -> violation_observer;

/// The user pointer that was installed with the observer.
[[nodiscard]] auto violation_observer_user() noexcept -> void*;

/// Number of violations reported by this process: zero means none.
[[nodiscard]] auto violation_count() noexcept -> std::uint64_t;

/// Stream the report is written to. `stderr` unless changed.
///
/// The stream is redirectable because a component that runs under a supervisor
/// usually has somewhere better to put a violation than the process's own
/// standard error, and because a test can capture the report by pointing this
/// at a temporary file instead of parsing the output of a process that dies.
void set_violation_stream(std::FILE* stream) noexcept;

/// The stream reports are currently written to. Never null.
[[nodiscard]] auto violation_stream() noexcept -> std::FILE*;

/// Report a violation: assign a sequence number, write the report to stderr,
/// notify the observer, and return the record with its sequence assigned.
///
/// Returns rather than terminates so that the reporting path is testable;
/// every caller in this library terminates immediately afterwards.
[[nodiscard]] auto report_violation(violation_record record) noexcept -> violation_record;

/// Everything the library does on a violation, up to and including stopping.
/// One function, so that "what happens on a violation" has a single answer.
[[noreturn]] inline void fail_stop(violation_record record) noexcept {
    static_cast<void>(report_violation(record));
    std::abort();
}

} // namespace meta_auth::diag

// ---------------------------------------------------------------------------
// Out-of-line definitions
//
// `inline` because the library is header-only: a program that includes this
// header in ten translation units gets one copy of each, and no ODR problem.
// ---------------------------------------------------------------------------
namespace meta_auth::diag {

namespace detail {

[[nodiscard]] inline auto observer_slot() noexcept -> std::atomic<violation_observer>& {
    static std::atomic<violation_observer> slot{nullptr};
    return slot;
}

[[nodiscard]] inline auto observer_user_slot() noexcept -> std::atomic<void*>& {
    static std::atomic<void*> slot{nullptr};
    return slot;
}

[[nodiscard]] inline auto stream_slot() noexcept -> std::atomic<std::FILE*>& {
    static std::atomic<std::FILE*> slot{stderr};
    return slot;
}

} // namespace detail

inline void set_violation_observer(violation_observer observer, void* user) noexcept {
    detail::observer_user_slot().store(user, std::memory_order_relaxed);
    detail::observer_slot().store(observer, std::memory_order_release);
}

[[nodiscard]] inline auto violation_observer_instance() noexcept -> violation_observer {
    return detail::observer_slot().load(std::memory_order_acquire);
}

[[nodiscard]] inline auto violation_observer_user() noexcept -> void* {
    return detail::observer_user_slot().load(std::memory_order_relaxed);
}

[[nodiscard]] inline auto violation_count() noexcept -> std::uint64_t {
    return detail::sequence_counter().load(std::memory_order_relaxed);
}

inline void set_violation_stream(std::FILE* stream) noexcept {
    detail::stream_slot().store(stream == nullptr ? stderr : stream, std::memory_order_release);
}

[[nodiscard]] inline auto violation_stream() noexcept -> std::FILE* {
    std::FILE* stream = detail::stream_slot().load(std::memory_order_acquire);
    return stream == nullptr ? stderr : stream;
}

[[nodiscard]] inline auto report_violation(violation_record record) noexcept -> violation_record {
    record.sequence = detail::sequence_counter().fetch_add(1, std::memory_order_relaxed) + 1;

    std::array<char, violation_report_capacity> buffer{};
    const std::string_view text = format_violation(record, buffer);
    if (!text.empty()) {
        std::FILE* const stream = violation_stream();
        static_cast<void>(std::fwrite(text.data(), 1, text.size(), stream));
        static_cast<void>(std::fflush(stream));
    }

    if (const violation_observer observer = violation_observer_instance(); observer != nullptr) {
        observer(violation_observer_user(), record);
    }
    return record;
}

} // namespace meta_auth::diag

// ---------------------------------------------------------------------------
// The P2900 hook
//
// P2900 leaves `handle_contract_violation` to the program: the compiler emits
// calls to it and the program must define it. Defining it here has three
// consequences, all deliberate:
//
//   * a consumer of this header-only library gets a working handler without
//     writing one, and without the link error a missing definition produces;
//   * library code and application code report a violation the same way;
//   * the observer hook becomes reachable, which is what lets an application
//     record the violation before it dies.
//
// A program that wants its own handler defines
// META_AUTH_CONFIG_INSTALL_VIOLATION_HANDLER=0 and provides one.
//
// Why the definition is weak, and not `inline`
// --------------------------------------------
// Both alternatives were tried against GCC 16.0.1 and both fail, for different
// reasons that are worth recording because neither is obvious:
//
//   * `inline` -- the compiler emits an *undefined* reference to
//     `handle_contract_violation` for its contract-lowering code and never
//     emits the inline definition, because nothing in the translation unit
//     odr-uses it. The program links, and the standard library's default
//     handler runs instead, silently replacing the library's reporting and
//     observer hook. This was caught by a test asserting the report text, not
//     by a link error.
//   * a plain (strong) definition -- correct for one translation unit and a
//     duplicate-symbol error for two, which makes it unusable in a header.
//
// A weak definition has the three properties the design needs: it is emitted,
// definitions from several translation units merge into one, and a program
// that supplies its own strong definition overrides it.
// ---------------------------------------------------------------------------
#if !defined(META_AUTH_CONFIG_INSTALL_VIOLATION_HANDLER)
#define META_AUTH_CONFIG_INSTALL_VIOLATION_HANDLER 1
#endif

#if defined(__GNUC__) || defined(__clang__)
#define META_AUTH_WEAK_SYMBOL __attribute__((weak))
#else
/// The handler is installed with a non-weak definition on toolchains without a
/// weak-symbol attribute. That is correct for a single translation unit and a
/// duplicate-definition error for several, which is why the header states the
/// constraint rather than discovering it at link time.
#define META_AUTH_WEAK_SYMBOL
#endif

#if META_AUTH_HAS_CONTRACTS && META_AUTH_CONFIG_INSTALL_VIOLATION_HANDLER

namespace meta_auth::diag::detail {

/// Translations from P2900's enumerations to this library's. Each switch
/// covers every enumerator and still ends with a return, because P2900 allows
/// implementations to add values above 1000.
[[nodiscard]] inline auto translate(std::contracts::assertion_kind kind) noexcept
    -> violation_kind {
    switch (kind) {
    case std::contracts::assertion_kind::pre:
        return violation_kind::precondition;
    case std::contracts::assertion_kind::post:
        return violation_kind::postcondition;
    case std::contracts::assertion_kind::assert:
        return violation_kind::assertion;
    }
    return violation_kind::assertion;
}

[[nodiscard]] inline auto translate(std::contracts::evaluation_semantic semantic) noexcept
    -> violation_semantic {
    switch (semantic) {
    case std::contracts::evaluation_semantic::ignore:
        return violation_semantic::ignore;
    case std::contracts::evaluation_semantic::observe:
        return violation_semantic::observe;
    case std::contracts::evaluation_semantic::enforce:
        return violation_semantic::enforce;
    case std::contracts::evaluation_semantic::quick_enforce:
        return violation_semantic::quick_enforce;
    }
    return violation_semantic::enforce;
}

[[nodiscard]] inline auto translate(std::contracts::detection_mode mode) noexcept
    -> violation_detection {
    switch (mode) {
    case std::contracts::detection_mode::predicate_false:
        return violation_detection::predicate_false;
    case std::contracts::detection_mode::evaluation_exception:
        return violation_detection::evaluation_exception;
    }
    return violation_detection::predicate_false;
}

/// `source_location` hands out `const char*` that may be null on some
/// implementations; a report is not the place to discover that.
[[nodiscard]] inline auto or_placeholder(const char* text, std::string_view placeholder) noexcept
    -> std::string_view {
    return text == nullptr ? placeholder : std::string_view{text};
}

} // namespace meta_auth::diag::detail

/// Declaration first, definition after: a definition without a preceding
/// declaration is what -Wmissing-declarations exists to catch, and the
/// declaration also documents the exact signature P2900 requires.
void handle_contract_violation(const std::contracts::contract_violation& violation);

META_AUTH_WEAK_SYMBOL void handle_contract_violation(
    const std::contracts::contract_violation& violation) {
    const std::source_location location = violation.location();

    meta_auth::diag::fail_stop(meta_auth::diag::violation_record{
        .expression = meta_auth::diag::detail::or_placeholder(violation.comment(),
                                                              "<no condition>"),
        .file = meta_auth::diag::detail::or_placeholder(location.file_name(), "<no file>"),
        .function = meta_auth::diag::detail::or_placeholder(location.function_name(),
                                                            "<no function>"),
        .line = location.line(),
        .kind = meta_auth::diag::detail::translate(violation.kind()),
        .semantic = meta_auth::diag::detail::translate(violation.semantic()),
        .detection = meta_auth::diag::detail::translate(violation.mode()),
    });
}

#endif // META_AUTH_HAS_CONTRACTS && META_AUTH_CONFIG_INSTALL_VIOLATION_HANDLER

// ---------------------------------------------------------------------------
// Contract macros
// ---------------------------------------------------------------------------

#if META_AUTH_HAS_CONTRACTS

/// Declarator precondition. Empty on a compiler without contract support; pair
/// it with META_AUTH_PRE_FALLBACK as the first statement of the body.
#define META_AUTH_PRE(condition) pre(condition)

/// Declarator postcondition.
#define META_AUTH_POST(condition) post(condition)

/// Declarator postcondition that names the return value:
/// `META_AUTH_POST_EQ(result, result <= limit)`.
#define META_AUTH_POST_EQ(name, condition) post(name : (condition))

/// Body-level assertion, always active.
#define META_AUTH_ASSERT(condition) contract_assert(condition)

/// Body-level precondition, always active.
#define META_AUTH_EXPECTS(condition) contract_assert(condition)

/// Body-level postcondition, always active.
#define META_AUTH_ENSURES(condition) contract_assert(condition)

/// The portable twin of a declarator contract: empty here, because the
/// declarator already carries the check and asserting it twice would double
/// the cost of every call for no additional guarantee.
#define META_AUTH_PRE_FALLBACK(condition) ((void)0)
#define META_AUTH_POST_FALLBACK(condition) ((void)0)

#else // !META_AUTH_HAS_CONTRACTS

#define META_AUTH_PRE(condition)
#define META_AUTH_POST(condition)
#define META_AUTH_POST_EQ(name, condition)

/// Portable fail-stop assertion. Reports through the same path as a native
/// contract violation, so the diagnostic does not depend on the dialect.
#define META_AUTH_ASSERT(condition)                                                          \
    do {                                                                                     \
        if (!(condition)) {                                                                  \
            ::meta_auth::diag::fail_stop(::meta_auth::diag::violation_record{                \
                .expression = #condition,                                                    \
                .file = __FILE__,                                                            \
                .function = __func__,                                                        \
                .line = static_cast<std::uint32_t>(__LINE__),                                \
                .kind = ::meta_auth::diag::violation_kind::assertion,                        \
                .semantic = ::meta_auth::diag::violation_semantic::enforce,                  \
                .detection = ::meta_auth::diag::violation_detection::predicate_false,        \
            });                                                                              \
        }                                                                                    \
    } while (false)

#define META_AUTH_EXPECTS(condition) META_AUTH_ASSERT(condition)
#define META_AUTH_ENSURES(condition) META_AUTH_ASSERT(condition)

/// The portable twin of a declarator contract: this is where the check lives
/// when the compiler cannot put it in the declarator.
#define META_AUTH_PRE_FALLBACK(condition) META_AUTH_ASSERT(condition)
#define META_AUTH_POST_FALLBACK(condition) META_AUTH_ASSERT(condition)

#endif // META_AUTH_HAS_CONTRACTS

/// Mark a branch that the design says cannot be reached. Reported through the
/// same path as any other violation, so an unreachable branch that turns out
/// to be reachable is not silent.
#define META_AUTH_UNREACHABLE(message)                                                       \
    ::meta_auth::diag::fail_stop(::meta_auth::diag::violation_record{                        \
        .expression = message,                                                               \
        .file = __FILE__,                                                                    \
        .function = __func__,                                                                \
        .line = static_cast<std::uint32_t>(__LINE__),                                        \
        .kind = ::meta_auth::diag::violation_kind::assertion,                                \
        .semantic = ::meta_auth::diag::violation_semantic::enforce,                          \
        .detection = ::meta_auth::diag::violation_detection::predicate_false,                \
    })

#endif // META_AUTH_CORE_CONTRACT_HPP
