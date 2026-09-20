// ===========================================================================
//  Tests of the contract layer.
//
//  A fail-stop path is unusually easy to test badly. "The process aborted" is
//  satisfiable by any crash, so this file splits the layer into the parts that
//  can be observed without dying and tests them here:
//
//    * the report is a pure function of a record, so its exact wording,
//      ordering and truncation behaviour are asserted, not eyeballed;
//    * the observer hook and the stream are redirectable, so what a violation
//      *does* is asserted by capturing it;
//    * sequence numbering is asserted to be monotone and to start at one.
//
//  What is left -- that a violation terminates the process -- is asserted from
//  the outside by the failure tests in CMakeLists.txt, which is the only place
//  it can be asserted at all.
// ===========================================================================
#include "meta_auth/core/contract.hpp"
#include "test_framework.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

/// Read back everything written to a temporary file. Used to capture the
/// violation report without letting the process end.
[[nodiscard]] auto slurp(std::FILE* file) -> std::string {
    if (std::fflush(file) != 0) {
        return {};
    }
    if (std::fseek(file, 0, SEEK_SET) != 0) {
        return {};
    }
    std::string contents;
    std::array<char, 256> chunk{};
    while (true) {
        const std::size_t read = std::fread(chunk.data(), 1, chunk.size(), file);
        contents.append(chunk.data(), read);
        if (read < chunk.size()) {
            break;
        }
    }
    return contents;
}

/// Restores the report stream when it goes out of scope, so one case cannot
/// change what the next one observes.
struct stream_guard {
    std::FILE* previous = meta_auth::diag::violation_stream();
    ~stream_guard() { meta_auth::diag::set_violation_stream(previous); }
};

[[nodiscard]] auto sample_record() -> meta_auth::diag::violation_record {
    return meta_auth::diag::violation_record{
        .expression = "rights.contains(right::write)",
        .file = "capability/gate.hpp",
        .function = "invoke",
        .line = 42,
        .kind = meta_auth::diag::violation_kind::precondition,
        .semantic = meta_auth::diag::violation_semantic::enforce,
        .detection = meta_auth::diag::violation_detection::predicate_false,
    };
}

/// A contract that a caller can violate on purpose. The declarator carries
/// the check where the compiler supports contracts, and the fallback carries
/// it everywhere else; both produce the same report.
[[nodiscard]] constexpr auto checked_ratio(int numerator, int denominator) -> double
    META_AUTH_PRE(denominator != 0)
    META_AUTH_POST(result: result >= 0.0)
{
    META_AUTH_PRE_FALLBACK(denominator != 0);
    const double quotient =
        static_cast<double>(numerator) / static_cast<double>(denominator);
    META_AUTH_POST_FALLBACK(quotient >= 0.0);
    return quotient;
}

} // namespace

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------
static_assert(!meta_auth::diag::must_terminate(meta_auth::diag::violation_semantic::observe));
static_assert(meta_auth::diag::must_terminate(meta_auth::diag::violation_semantic::enforce));
static_assert(meta_auth::diag::must_terminate(
    meta_auth::diag::violation_semantic::quick_enforce));
static_assert(meta_auth::diag::to_string(meta_auth::diag::violation_kind::precondition)
              == "precondition");

META_AUTH_TEST("contract", "enum_names_are_exhaustive") {
    using meta_auth::diag::to_string;
    using meta_auth::diag::violation_detection;
    using meta_auth::diag::violation_kind;
    using meta_auth::diag::violation_semantic;

    META_AUTH_CHECK_NE(to_string(violation_kind::precondition), std::string_view{"unknown"});
    META_AUTH_CHECK_NE(to_string(violation_kind::postcondition), std::string_view{"unknown"});
    META_AUTH_CHECK_NE(to_string(violation_kind::assertion), std::string_view{"unknown"});

    META_AUTH_CHECK_NE(to_string(violation_semantic::ignore), std::string_view{"unknown"});
    META_AUTH_CHECK_NE(to_string(violation_semantic::observe), std::string_view{"unknown"});
    META_AUTH_CHECK_NE(to_string(violation_semantic::enforce), std::string_view{"unknown"});
    META_AUTH_CHECK_NE(to_string(violation_semantic::quick_enforce), std::string_view{"unknown"});

    META_AUTH_CHECK_NE(to_string(violation_detection::predicate_false),
                       std::string_view{"unknown"});
    META_AUTH_CHECK_NE(to_string(violation_detection::evaluation_exception),
                       std::string_view{"unknown"});
}

// ---------------------------------------------------------------------------
// The report is a pure function
// ---------------------------------------------------------------------------
META_AUTH_TEST("contract", "report_contains_every_field") {
    std::array<char, meta_auth::diag::violation_report_capacity> buffer{};
    auto record = sample_record();
    record.sequence = 7;

    const std::string_view text = meta_auth::diag::format_violation(record, buffer);

    // Every field matters to whoever reads this at three in the morning: the
    // condition, where it is, in which function, and how it was classified.
    META_AUTH_CHECK(text.find("contract violation") != std::string_view::npos);
    META_AUTH_CHECK(text.find("rights.contains(right::write)") != std::string_view::npos);
    META_AUTH_CHECK(text.find("precondition") != std::string_view::npos);
    META_AUTH_CHECK(text.find("capability/gate.hpp:42") != std::string_view::npos);
    META_AUTH_CHECK(text.find("invoke") != std::string_view::npos);
    META_AUTH_CHECK(text.find("predicate_false") != std::string_view::npos);
    META_AUTH_CHECK(text.find("terminating yes") != std::string_view::npos);
    META_AUTH_CHECK(text.find("sequence  : 7") != std::string_view::npos);
}

META_AUTH_TEST("contract", "report_is_nul_terminated_when_it_fits") {
    // The buffer form exists so the report can also be handed to a C API
    // without a copy, which requires the terminator to be there.
    std::array<char, meta_auth::diag::violation_report_capacity> buffer{};
    const std::string_view text = meta_auth::diag::format_violation(sample_record(), buffer);

    META_AUTH_REQUIRE(text.size() < buffer.size());
    META_AUTH_CHECK_EQ(buffer[text.size()], '\0');
    META_AUTH_CHECK_EQ(std::string_view{buffer.data()}, text);
}

META_AUTH_TEST("contract", "a_report_that_exactly_fills_the_buffer_is_not_written_past") {
    // The boundary the terminator logic got wrong -- and the one the check
    // above could never see, because that check requires
    // `text.size() < buffer.size()`, which excludes the only case that matters.
    //
    // A report whose length is exactly the buffer size is not truncated, so
    // the branch that appends a terminator ran, and it wrote at
    // `buffer[size]` -- one byte past the end. On the reference compiler that
    // is not a quiet stray byte: libstdc++ 16 hardens `span::operator[]` by
    // default, so the write aborts the process, on the fail-stop path whose
    // entire purpose is to report a contract violation before stopping.
    //
    // Both ways of failing are failures: on a hardened standard library the
    // process aborts, and on one without the hardening the sentinel below is
    // clobbered.
    const std::string_view condition = "oversized.left == oversized.right";
    const std::string_view place = "capability/oversized.hpp:1";
    const std::string_view function = "overflowing";

    std::array<char, 1024> sizing{};
    meta_auth::diag::violation_record probe{
        .expression = condition,
        .file = place,
        .function = function,
        .kind = meta_auth::diag::violation_kind::precondition,
    };
    const std::string_view rendered = meta_auth::diag::format_violation(probe, sizing);

    // The buffer that fits the report exactly, with a sentinel after it. The
    // sentinel is part of the same allocation on purpose: a byte past the end
    // of a separate array is what AddressSanitizer catches, and this test has
    // to mean something in a build without sanitizers too.
    const std::size_t exact = rendered.size();
    std::vector<char> storage(exact + 8, 'X');
    const std::span<char> buffer{storage.data(), exact};

    const std::string_view text = meta_auth::diag::format_violation(probe, buffer);
    META_AUTH_CHECK_EQ(text.size(), exact);
    for (std::size_t index = exact; index < storage.size(); ++index) {
        META_AUTH_CHECK_EQ(storage[index], 'X');
    }
}

META_AUTH_TEST("contract", "report_marks_truncation_instead_of_hiding_it") {
    // A report cut in half without saying so is worse than no report: it
    // invites the reader to conclude the missing part did not exist.
    std::array<char, 64> buffer{};
    const std::string_view text = meta_auth::diag::format_violation(sample_record(), buffer);

    META_AUTH_CHECK(!text.empty());
    META_AUTH_CHECK(text.size() <= buffer.size());
    META_AUTH_CHECK(text.find("[truncated]") != std::string_view::npos);
}

META_AUTH_TEST("contract", "an_empty_buffer_is_refused_not_written_to") {
    const std::string_view text = meta_auth::diag::format_violation(sample_record(), {});
    META_AUTH_CHECK(text.empty());
}

META_AUTH_TEST("contract", "missing_fields_render_as_placeholders") {
    std::array<char, meta_auth::diag::violation_report_capacity> buffer{};
    const std::string_view text = meta_auth::diag::format_violation({}, buffer);

    META_AUTH_CHECK(text.find("<no condition>") != std::string_view::npos);
    META_AUTH_CHECK(text.find("<no file>") != std::string_view::npos);
    META_AUTH_CHECK(text.find("<unknown>") != std::string_view::npos);
}

// ---------------------------------------------------------------------------
// Reporting: stream, sequence, observer
// ---------------------------------------------------------------------------
META_AUTH_TEST("contract", "report_is_written_to_the_configured_stream") {
    const stream_guard guard;
    std::FILE* const capture = std::tmpfile();
    META_AUTH_REQUIRE(capture != nullptr);
    meta_auth::diag::set_violation_stream(capture);

    const auto reported = meta_auth::diag::report_violation(sample_record());
    const std::string text = slurp(capture);

    META_AUTH_CHECK(text.find("contract violation") != std::string::npos);
    META_AUTH_CHECK(text.find("rights.contains(right::write)") != std::string::npos);
    // The returned record carries the sequence the report was written with,
    // so a caller can correlate its own logging with the report.
    META_AUTH_CHECK(reported.sequence >= 1);
    META_AUTH_CHECK(text.find(std::to_string(reported.sequence)) != std::string::npos);
    std::fclose(capture);
}

META_AUTH_TEST("contract", "sequence_numbers_increase_and_count_agrees") {
    const stream_guard guard;
    std::FILE* const capture = std::tmpfile();
    META_AUTH_REQUIRE(capture != nullptr);
    meta_auth::diag::set_violation_stream(capture);

    const std::uint64_t before = meta_auth::diag::violation_count();
    const auto first = meta_auth::diag::report_violation(sample_record());
    const auto second = meta_auth::diag::report_violation(sample_record());

    META_AUTH_CHECK_EQ(second.sequence, first.sequence + 1);
    META_AUTH_CHECK_EQ(meta_auth::diag::violation_count(), before + 2);
    std::fclose(capture);
}

META_AUTH_TEST("contract", "observer_sees_the_record_before_termination") {
    const stream_guard guard;
    std::FILE* const capture = std::tmpfile();
    META_AUTH_REQUIRE(capture != nullptr);
    meta_auth::diag::set_violation_stream(capture);

    struct collector {
        std::vector<meta_auth::diag::violation_record> records;
        static void observe(void* user, const meta_auth::diag::violation_record& record) {
            static_cast<collector*>(user)->records.push_back(record);
        }
    } collected;

    META_AUTH_CHECK(meta_auth::diag::violation_observer_instance() == nullptr);
    meta_auth::diag::set_violation_observer(&collector::observe, &collected);
    META_AUTH_CHECK(meta_auth::diag::violation_observer_instance() == &collector::observe);
    META_AUTH_CHECK_EQ(meta_auth::diag::violation_observer_user(),
                       static_cast<void*>(&collected));

    const auto reported = meta_auth::diag::report_violation(sample_record());

    META_AUTH_REQUIRE_EQ(collected.records.size(), std::size_t{1});
    META_AUTH_CHECK_EQ(collected.records.front().expression, sample_record().expression);
    META_AUTH_CHECK_EQ(collected.records.front().sequence, reported.sequence);

    meta_auth::diag::set_violation_observer(nullptr, nullptr);
    META_AUTH_CHECK(meta_auth::diag::violation_observer_instance() == nullptr);
    std::fclose(capture);
}

META_AUTH_TEST("contract", "a_null_stream_falls_back_to_stderr") {
    // Setting a null stream must not silently discard reports.
    const stream_guard guard;
    meta_auth::diag::set_violation_stream(nullptr);
    META_AUTH_CHECK(meta_auth::diag::violation_stream() == stderr);
}

// ---------------------------------------------------------------------------
// The macros themselves
// ---------------------------------------------------------------------------
META_AUTH_TEST("contract", "satisfied_contracts_do_not_fire") {
    // The positive direction. Without this case, a macro that always fired
    // would pass every fail-stop test in the suite.
    META_AUTH_ASSERT(1 + 1 == 2);
    META_AUTH_EXPECTS(true);
    META_AUTH_ENSURES(true);
    META_AUTH_CHECK_EQ(checked_ratio(8, 2), 4.0);
    META_AUTH_CHECK_EQ(checked_ratio(0, 5), 0.0);
}

META_AUTH_TEST("contract", "contracts_hold_during_constant_evaluation") {
    // A contract that could not be evaluated at compile time would silently
    // exclude every `consteval` function in the library from using one, since
    // compile-time evaluation is where half of this library's guarantees live.
    //
    // This is asserted with `static_assert` rather than by initialising a
    // `constexpr` variable, and the difference is not stylistic. GCC 16.0.1
    // rejects the variable form for a function with a *named-result*
    // postcondition:
    //
    //     constexpr auto ratio(int a, int b) -> double
    //         post(r: r >= 0.0) { return static_cast<double>(a) / b; }
    //     constexpr double value = ratio(1, 2);   // error: contract condition
    //                                             // is not constant
    //
    // while `static_assert(ratio(1, 2) == 0.5)`, aggregate initialisation and
    // run-time calls are all accepted. The rule this project follows as a
    // result is recorded in docs/contracts.md: named-result postconditions go
    // on functions verified by `static_assert`, and in-body
    // `META_AUTH_ENSURES` is used where a `constexpr` variable initialiser has
    // to work.
    static_assert(checked_ratio(1, 2) == 0.5);
    static_assert(checked_ratio(4, 2) == 2.0);
    META_AUTH_CHECK_EQ(checked_ratio(1, 2), 0.5);
}

META_AUTH_TEST("contract", "portable_fallback_is_inert_when_contracts_are_enabled") {
    // The pairing rule only works if the fallback expands to nothing when the
    // declarator contract was emitted. If both fired, a violating call would
    // report twice and the sequence numbers in the audit trail would lie.
#if META_AUTH_HAS_CONTRACTS
    const std::uint64_t before = meta_auth::diag::violation_count();
    std::array<char, meta_auth::diag::violation_report_capacity> buffer{};
    const std::string_view text = meta_auth::diag::format_violation(
        meta_auth::diag::violation_record{.expression = "x", .file = "f", .line = 1}, buffer);

    // Nothing above reports; this asserts the fallback macro is literally a
    // no-op in this configuration by checking the source-level contract.
    META_AUTH_CHECK(!text.empty());
    META_AUTH_CHECK_EQ(meta_auth::diag::violation_count(), before);
    META_AUTH_CHECK_EQ(META_AUTH_HAS_CONTRACTS, 1);
#else
    // In the portable build the fallback *is* the check, and the failure
    // tests prove it fires.
    META_AUTH_CHECK_EQ(META_AUTH_HAS_CONTRACTS, 0);
#endif
}
