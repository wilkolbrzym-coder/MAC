// ===========================================================================
//  meta-auth-core -- test framework.
//
//  A dependency-free xUnit-style harness, for three reasons:
//
//    1. The library has no third-party dependencies, and a test suite that
//       pulls in a framework would make that claim false at the level where it
//       matters most (CI, and anyone building this repository).
//    2. The suite needs to test things a general-purpose framework makes
//       awkward: whether the *framework's own* failure path is fatal, whether
//       the process dies the way the design says it must, and whether programs
//       that must not compile stay uncompilable.
//    3. The harness is small enough to be read in one sitting, which is the
//       standard this repository holds its own code to.
//
//  Structure
//  ---------
//    * `stringify`   -- best-effort rendering of a value for a failure report,
//                       using std::format when available, `operator<<` as a
//                       fallback, and reflection to name the type when
//                       neither exists.
//    * `context`     -- the mutable state of a run (counters, current case)
//                       with an injectable failure sink, so the framework's
//                       own behaviour is unit-testable rather than assumed.
//    * `registry`    -- self-registering test cases, discoverable and
//                       filterable from the command line.
//    * macros        -- META_AUTH_TEST, CHECK / REQUIRE and their typed
//                       variants.
// ===========================================================================
#ifndef META_AUTH_TEST_FRAMEWORK_HPP
#define META_AUTH_TEST_FRAMEWORK_HPP

#include "meta_auth/config.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <expected>
#include <format>
#include <source_location>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#if META_AUTH_HAS_REFLECTION
#include <meta>
#endif

namespace meta_auth::test {

// ---------------------------------------------------------------------------
// Rendering values into failure reports
// ---------------------------------------------------------------------------

/// Name of a type, for diagnostics. Uses reflection when the build has it: a
/// failure report that says "capability<DeviceResource, rights{read}>" instead
/// of "<unprintable>" is the difference between a five-second fix and a
/// debugging session.
#if META_AUTH_HAS_REFLECTION
template <typename T>
inline constexpr std::string_view type_name = std::meta::display_string_of(^^T);
#else
template <typename T>
inline constexpr std::string_view type_name = "<unknown type>";
#endif

/// True when a `std::formatter` specialization for `T` is usable.
///
/// Detected directly rather than through `std::formattable<T, char>`, and the
/// difference is not academic. An atomic constraint whose arguments do not
/// depend on a template parameter is evaluated where it is written, so a
/// non-dependent `std::formattable<Concrete, char>` is answered before a
/// specialization declared later in the translation unit is visible -- while
/// `std::format("{}", Concrete{})` at the same point would work. This concept
/// depends on `T` and is therefore evaluated at instantiation, where the
/// specialization is visible.
///
/// The probe is the standard way a disabled primary template is detected: the
/// library's `std::formatter` primary is not default-constructible, so a valid
/// specialization is exactly one that can be built and asked to format.
template <typename T>
concept has_formatter =
    requires(const std::remove_cvref_t<T>& value, std::format_context& context) {
        std::formatter<std::remove_cvref_t<T>, char>{}.format(value, context);
    };

/// Render a value for a failure report.
///
/// Preference order: std::format (which library types opt into by providing a
/// formatter, and which is the only option that renders a std::expected
/// usefully), then `operator<<`, then a placeholder that at least names the
/// type.
template <typename T>
[[nodiscard]] auto stringify(const T& value) -> std::string {
    if constexpr (has_formatter<T>) {
        return std::format("{}", value);
    } else if constexpr (requires(std::ostream& stream, const T& candidate) {
                             stream << candidate;
                         }) {
        std::ostringstream stream;
        stream << value;
        return stream.str();
    } else {
        return std::format("<unprintable {}>", type_name<T>);
    }
}

/// Strings are quoted in reports so that a leading or trailing space is
/// visible; that defect class is otherwise invisible in CI output.
[[nodiscard]] inline auto stringify(const std::string& value) -> std::string {
    return std::format("\"{}\"", value);
}

[[nodiscard]] inline auto stringify(std::string_view value) -> std::string {
    return std::format("\"{}\"", value);
}

[[nodiscard]] inline auto stringify(const char* value) -> std::string {
    return value == nullptr ? std::string{"<null>"} : std::format("\"{}\"", value);
}

[[nodiscard]] inline auto stringify(bool value) -> std::string {
    return value ? "true" : "false";
}

// ---------------------------------------------------------------------------
// std::expected is rendered by the harness rather than by std::format.
//
// GCC 16's standard library does not provide a `std::formatter` for
// `std::expected`: the specialization is absent, so `std::format("{}", value)`
// is a compile error and `has_formatter` correctly reports false. That leaves
// the most interesting values in this library -- the ones a test just failed
// to unwrap -- unprintable, which is the opposite of what a failure report is
// for. The overloads below therefore render both halves explicitly.
// ---------------------------------------------------------------------------
template <typename T, typename E>
[[nodiscard]] auto stringify(const std::expected<T, E>& value) -> std::string {
    if (!value.has_value()) {
        return std::format("error({})", stringify(value.error()));
    }
    if constexpr (std::is_void_v<T>) {
        return std::string{"success()"};
    } else {
        return std::format("success({})", stringify(*value));
    }
}

template <typename E>
[[nodiscard]] auto stringify(const std::unexpected<E>& value) -> std::string {
    return std::format("unexpected({})", stringify(value.error()));
}

// ---------------------------------------------------------------------------
// Failure records
// ---------------------------------------------------------------------------

/// One failed check. Deliberately a value: the framework's job is to describe
/// the failure completely enough that the report needs no follow-up question.
struct check_failure {
    std::string_view suite;
    std::string_view test_name;
    std::string_view expression;
    std::string detail;
    std::source_location where;
    bool fatal;
};

/// Where failures go. The indirection exists so that tests of the framework
/// can capture records instead of printing them.
using failure_sink = void (*)(void* user, const check_failure& failure);

// ---------------------------------------------------------------------------
// Run statistics
// ---------------------------------------------------------------------------
struct statistics {
    std::size_t cases_run = 0;
    std::size_t cases_failed = 0;
    std::size_t cases_skipped = 0;
    std::size_t checks = 0;
    std::size_t failures = 0;
};

// ---------------------------------------------------------------------------
// Run context
//
// A single process-wide instance: the harness runs cases sequentially, and a
// per-thread context would only be needed for a parallel runner, which this
// deliberately is not (a shared audit trail is one of the things under test,
// so test execution order has to be controlled).
// ---------------------------------------------------------------------------
class context {
public:
    /// Thrown by REQUIRE to abandon the current case without abandoning the
    /// run. Exceptions are confined to the harness: the library never throws.
    struct case_aborted {};

    /// Thrown by META_AUTH_SKIP. A skip is recorded and reported, never
    /// silent: a suite whose cases quietly stop running is a suite that
    /// stopped being evidence. The reason is owned rather than a view,
    /// because callers compose it at run time.
    struct case_skipped {
        std::string reason;
    };

    [[nodiscard]] static auto instance() noexcept -> context& {
        static context ctx;
        return ctx;
    }

    context(const context&) = delete;
    auto operator=(const context&) -> context& = delete;
    context(context&&) = delete;
    auto operator=(context&&) -> context& = delete;

    /// Install a sink. Passing nullptr restores the default stderr sink.
    void set_sink(failure_sink sink, void* user) noexcept {
        sink_ = sink;
        sink_user_ = user;
    }

    void begin_case(std::string_view suite, std::string_view name) noexcept {
        suite_ = suite;
        test_name_ = name;
        case_failed_ = false;
        ++stats_.cases_run;
    }

    void end_case() noexcept {
        if (case_failed_) {
            ++stats_.cases_failed;
        }
    }

    void note_skip() noexcept { ++stats_.cases_skipped; }

    /// Record one check outcome. Returns the condition so that call sites can
    /// be expressions.
    auto record_check(bool passed, std::string_view expression, std::string detail,
                      const std::source_location& where, bool fatal) -> bool {
        ++stats_.checks;
        if (passed) {
            return true;
        }
        ++stats_.failures;
        if (case_tracking_) {
            case_failed_ = true;
        }
        check_failure failure{suite_,     test_name_, expression,
                              std::move(detail), where,      fatal};
        if (sink_ != nullptr) {
            sink_(sink_user_, failure);
        } else {
            default_sink(nullptr, failure);
        }
        return false;
    }

    [[nodiscard]] auto stats() const noexcept -> const statistics& { return stats_; }
    [[nodiscard]] auto case_failed() const noexcept -> bool { return case_failed_; }

    /// Mutable access for `isolation_guard`, which has to be able to roll the
    /// counters back after a test that deliberately records failures.
    [[nodiscard]] auto stats_mutable() noexcept -> statistics& { return stats_; }

    /// While disabled, a recorded failure is reported but does not mark the
    /// current case as failed. Only the tests of this harness use it.
    void set_case_tracking(bool enabled) noexcept { case_tracking_ = enabled; }
    [[nodiscard]] auto case_tracking() const noexcept -> bool { return case_tracking_; }

    static void default_sink(void* /*user*/, const check_failure& failure) {
        const auto& where = failure.where;
        std::fprintf(stderr, "\nFAIL %.*s.%.*s\n  at %s:%u\n  %.*s\n",
                     static_cast<int>(failure.suite.size()), failure.suite.data(),
                     static_cast<int>(failure.test_name.size()), failure.test_name.data(),
                     where.file_name(), where.line(),
                     static_cast<int>(failure.expression.size()), failure.expression.data());
        if (!failure.detail.empty()) {
            std::fprintf(stderr, "  %s\n", failure.detail.c_str());
        }
        std::fflush(stderr);
    }

private:
    context() = default;

    failure_sink sink_ = nullptr;
    void* sink_user_ = nullptr;
    std::string_view suite_{};
    std::string_view test_name_{};
    statistics stats_{};
    bool case_failed_ = false;
    bool case_tracking_ = true;
};

/// Test-only device: while alive, failures recorded through the framework are
/// reported to the sink but do not mark the current case as failed and do not
/// count towards the run totals, which are restored on destruction.
///
/// This exists so that the harness's own failure path can be tested by a case
/// that is expected to pass. Without it, the test of "a failed check is
/// recorded" would itself fail.
class isolation_guard {
public:
    isolation_guard() noexcept
        : context_(context::instance()), saved_statistics_(context_.stats()) {
        context_.set_case_tracking(false);
    }

    ~isolation_guard() {
        context_.set_case_tracking(true);
        context_.stats_mutable() = saved_statistics_;
    }

    isolation_guard(const isolation_guard&) = delete;
    auto operator=(const isolation_guard&) -> isolation_guard& = delete;
    isolation_guard(isolation_guard&&) = delete;
    auto operator=(isolation_guard&&) -> isolation_guard& = delete;

    /// The sink is part of the isolated state as well: a test that installs a
    /// capturing sink must not leave it installed for the next case.
    void use_sink(failure_sink sink, void* user) noexcept { context_.set_sink(sink, user); }
    void clear_sink() noexcept { context_.set_sink(nullptr, nullptr); }

private:
    context& context_;
    statistics saved_statistics_;
};

// ---------------------------------------------------------------------------
// Check primitives
// ---------------------------------------------------------------------------
namespace detail {

/// The check primitives are deliberately not `[[nodiscard]]`: the macros below
/// discard their result, and a failed check is already recorded in the run
/// context by the time they return. Callers that need the boolean (the
/// framework's own tests) can still use it.
inline auto check(bool passed, std::string_view expression, const std::source_location& where)
    -> bool {
    return context::instance().record_check(passed, expression, {}, where, false);
}

inline auto require(bool passed, std::string_view expression, const std::source_location& where)
    -> bool {
    const bool outcome = context::instance().record_check(passed, expression, {}, where, true);
    if (!outcome) {
        throw context::case_aborted{};
    }
    return true;
}

inline auto check_binary(bool passed, std::string_view expression, std::string left,
                         std::string right, const std::source_location& where, bool fatal) -> bool {
    std::string detail = std::format("left  = {}\n  right = {}", left, right);
    const bool outcome =
        context::instance().record_check(passed, expression, std::move(detail), where, fatal);
    if (!outcome && fatal) {
        throw context::case_aborted{};
    }
    return outcome;
}

inline auto check_comparison(bool passed, std::string_view expression, std::string detail,
                             const std::source_location& where, bool fatal) -> bool {
    const bool outcome =
        context::instance().record_check(passed, expression, std::move(detail), where, fatal);
    if (!outcome && fatal) {
        throw context::case_aborted{};
    }
    return outcome;
}

} // namespace detail

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------
struct test_case_entry {
    std::string_view suite;
    std::string_view name;
    void (*run)();
};

class registry {
public:
    [[nodiscard]] static auto instance() noexcept -> registry& {
        static registry reg;
        return reg;
    }

    registry(const registry&) = delete;
    auto operator=(const registry&) -> registry& = delete;
    registry(registry&&) = delete;
    auto operator=(registry&&) -> registry& = delete;

    void add(test_case_entry entry) { cases_.push_back(entry); }

    /// Cases in a deterministic order. Registration order depends on the link
    /// order of translation units, which is stable for one binary but not
    /// across toolchains; sorting by (suite, name) makes CI output comparable
    /// between compilers, which is the point of running the matrix at all.
    [[nodiscard]] auto cases() const -> std::vector<test_case_entry> {
        auto sorted = cases_;
        std::sort(sorted.begin(), sorted.end(), [](const auto& lhs, const auto& rhs) {
            if (lhs.suite != rhs.suite) {
                return lhs.suite < rhs.suite;
            }
            return lhs.name < rhs.name;
        });
        return sorted;
    }

private:
    registry() = default;
    std::vector<test_case_entry> cases_{};
};

/// Static-initialisation registrar. Declared `[[maybe_unused]]` at every use
/// site so that a translation unit containing only registrations does not warn
/// about an unused variable.
struct registrar {
    registrar(std::string_view suite, std::string_view name, void (*run)()) {
        registry::instance().add({suite, name, run});
    }
};

// ---------------------------------------------------------------------------
// Named test cases
//
// `__COUNTER__` is captured once, in the argument list of the helper, and the
// resulting number is substituted into all three generated names. That is what
// makes two cases with the same name in one translation unit a duplicate
// *runtime* entry, which the runner reports, rather than a redefinition error.
// ---------------------------------------------------------------------------
#define META_AUTH_TEST_CONCAT_IMPL(a, b) a##b
#define META_AUTH_TEST_CONCAT(a, b) META_AUTH_TEST_CONCAT_IMPL(a, b)

#define META_AUTH_TEST(suite_name, case_name) META_AUTH_TEST_IMPL(suite_name, case_name, __COUNTER__)

#define META_AUTH_TEST_IMPL(suite_name, case_name, id)                                 \
    static void META_AUTH_TEST_CONCAT(meta_auth_case_, id)();                          \
    [[maybe_unused]] static const ::meta_auth::test::registrar                         \
        META_AUTH_TEST_CONCAT(meta_auth_registrar_, id){                               \
            suite_name, case_name, &META_AUTH_TEST_CONCAT(meta_auth_case_, id)};       \
    static void META_AUTH_TEST_CONCAT(meta_auth_case_, id)()

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

/// A failed CHECK records the failure and continues: the rest of the case
/// still runs, which is what makes a failing run informative. The expression
/// is converted to bool by the callee, so pointers, integers and types with a
/// non-explicit `operator bool` all work and no cast is needed here (a cast
/// would trip -Wuseless-cast on the common case of an expression that is
/// already bool).
#define META_AUTH_CHECK(expression)                                                  \
    ::meta_auth::test::detail::check(expression, #expression, std::source_location::current())

/// A failed REQUIRE records the failure and abandons the case, because every
/// later assertion in it would be reporting a consequence rather than a cause.
#define META_AUTH_REQUIRE(expression)                                                \
    ::meta_auth::test::detail::require(expression, #expression, std::source_location::current())

#define META_AUTH_CHECK_FALSE(expression)                                            \
    ::meta_auth::test::detail::check(!(expression), "!(" #expression ")",            \
                                     std::source_location::current())

/// Equality with both operands rendered. The lambda evaluates each operand
/// once and *copies* it, so the report shows the value the check was made
/// against even if the operand is later mutated. The consequence is that
/// CHECK_EQ requires copy-constructible operands; a move-only or expensive
/// value is compared with CHECK instead.
///
/// The copy is not a style choice. Binding `const auto&` to the result of a
/// call whose function declares a named-result postcondition makes GCC 16.0.1
/// reject the contract condition as non-constant ("contract condition is not
/// constant"), which would make this macro unusable with any function in the
/// library that documents its result that way.
#define META_AUTH_CHECK_EQ(lhs, rhs)                                                 \
    ([&]() -> bool {                                                                 \
        const auto meta_auth_lhs = (lhs);                                            \
        const auto meta_auth_rhs = (rhs);                                            \
        return ::meta_auth::test::detail::check_binary(                              \
            meta_auth_lhs == meta_auth_rhs, #lhs " == " #rhs,                        \
            ::meta_auth::test::stringify(meta_auth_lhs),                             \
            ::meta_auth::test::stringify(meta_auth_rhs), std::source_location::current(), \
            false);                                                                   \
    }())

#define META_AUTH_REQUIRE_EQ(lhs, rhs)                                               \
    ([&]() -> bool {                                                                 \
        const auto meta_auth_lhs = (lhs);                                            \
        const auto meta_auth_rhs = (rhs);                                            \
        return ::meta_auth::test::detail::check_binary(                              \
            meta_auth_lhs == meta_auth_rhs, #lhs " == " #rhs,                        \
            ::meta_auth::test::stringify(meta_auth_lhs),                             \
            ::meta_auth::test::stringify(meta_auth_rhs), std::source_location::current(), \
            true);                                                                    \
    }())

#define META_AUTH_CHECK_NE(lhs, rhs)                                                 \
    ([&]() -> bool {                                                                 \
        const auto meta_auth_lhs = (lhs);                                            \
        const auto meta_auth_rhs = (rhs);                                            \
        return ::meta_auth::test::detail::check_binary(                              \
            !(meta_auth_lhs == meta_auth_rhs), #lhs " != " #rhs,                     \
            ::meta_auth::test::stringify(meta_auth_lhs),                             \
            ::meta_auth::test::stringify(meta_auth_rhs), std::source_location::current(), \
            false);                                                                   \
    }())

/// Ordering comparison, rendered as a relation so the report shows both the
/// operands and which way the comparison was expected to go.
#define META_AUTH_CHECK_RELATION(lhs, op, rhs)                                       \
    ([&]() -> bool {                                                                 \
        const auto meta_auth_lhs = (lhs);                                            \
        const auto meta_auth_rhs = (rhs);                                            \
        const bool meta_auth_passed = (meta_auth_lhs op meta_auth_rhs);              \
        return ::meta_auth::test::detail::check_comparison(                          \
            meta_auth_passed, #lhs " " #op " " #rhs,                                 \
            ::meta_auth::test::stringify(meta_auth_lhs) + " " #op " "                \
                + ::meta_auth::test::stringify(meta_auth_rhs),                       \
            std::source_location::current(), false);                                 \
    }())

#define META_AUTH_CHECK_LT(lhs, rhs) META_AUTH_CHECK_RELATION(lhs, <, rhs)
#define META_AUTH_CHECK_LE(lhs, rhs) META_AUTH_CHECK_RELATION(lhs, <=, rhs)
#define META_AUTH_CHECK_GT(lhs, rhs) META_AUTH_CHECK_RELATION(lhs, >, rhs)
#define META_AUTH_CHECK_GE(lhs, rhs) META_AUTH_CHECK_RELATION(lhs, >=, rhs)

/// Abandon the current case without failing it. Used where a test needs a
/// resource the environment may not provide (a second thread, a writable
/// temporary directory); the skip is printed and counted.
#define META_AUTH_SKIP(reason) \
    throw ::meta_auth::test::context::case_skipped{std::string{reason}}

// ---------------------------------------------------------------------------
// Command-line handling, exposed so that it can be tested
// ---------------------------------------------------------------------------
struct options {
    std::string_view filter{};
    bool list = false;
    bool verbose = false;
    bool help = false;
};

/// `const char* const*` rather than `char**`: the runner never modifies the
/// arguments, and the const-correct signature lets tests pass a literal array
/// without casting away constness.
[[nodiscard]] auto parse_options(int argc, const char* const* argv) -> options;

/// A case matches when the filter is empty or is a substring of
/// "suite.name". Substring rather than prefix so that `--filter=revocation`
/// selects every case about revocation regardless of the suite it lives in.
[[nodiscard]] auto matches_filter(const test_case_entry& entry, std::string_view filter) -> bool;

/// Run every registered case that matches, and return a process exit code.
auto run_all(const options& opts) -> int;

} // namespace meta_auth::test

#endif // META_AUTH_TEST_FRAMEWORK_HPP
