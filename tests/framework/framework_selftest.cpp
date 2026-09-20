// ===========================================================================
//  Tests of the test framework.
//
//  Everything else in this suite is only as trustworthy as the harness that
//  reports it, so the harness is tested like any other component:
//
//    * `stringify` renders the values that appear in failure reports;
//    * the recording path counts checks and failures and routes them to an
//      injected sink, so the framework's behaviour is observed rather than
//      assumed;
//    * REQUIRE abandons the case, CHECK does not;
//    * option parsing and filtering behave as documented.
//
//  The two cases under "self_report" are the ones exercised by the failure
//  tests in CMakeLists.txt: they are skipped unless the environment asks for
//  them, and they fail on purpose when it does.
// ===========================================================================
#include "test_framework.hpp"

#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace {

/// Environment switch used by the failure tests. Naming the mode rather than
/// using a boolean keeps the two deliberate failures independent: setting one
/// mode does not make the other case fail as a side effect.
[[nodiscard]] auto selftest_mode() -> std::string_view {
    const char* value = std::getenv("META_AUTH_FRAMEWORK_SELFTEST");
    return value == nullptr ? std::string_view{} : std::string_view{value};
}

/// Skip the calling case unless the environment selected `mode`.
void require_mode(std::string_view mode) {
    if (selftest_mode() != mode) {
        META_AUTH_SKIP("set META_AUTH_FRAMEWORK_SELFTEST=" + std::string{mode}
                       + " to run this case");
    }
}

/// Captures failure records instead of printing them, so the framework's
/// recording path can be asserted on.
struct capture {
    std::vector<meta_auth::test::check_failure> records{};

    static void sink(void* user, const meta_auth::test::check_failure& failure) {
        static_cast<capture*>(user)->records.push_back(failure);
    }
};

/// A type the framework has to fall back on reflection to describe.
struct opaque {
    int payload;
};

/// A type that opts into std::format, which is how the library's own types
/// are rendered in reports.
///
/// The name is deliberately not `formattable`: inside the member declarations
/// of a `std::formatter` specialization, unqualified lookup reaches namespace
/// `std` before the global namespace, so a type named `formattable` would
/// collide with the `std::formattable` concept and the specialization would
/// fail to compile for a reason that has nothing to do with formatting.
struct renderable {
    int value;
};

} // namespace

template <>
struct std::formatter<renderable, char> {
    constexpr auto parse(std::format_parse_context& ctx) -> decltype(ctx.begin()) {
        return ctx.begin();
    }

    auto format(const renderable& item, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "renderable({})", item.value);
    }
};

// ---------------------------------------------------------------------------
// stringify
// ---------------------------------------------------------------------------
META_AUTH_TEST("stringify", "integers_and_booleans") {
    META_AUTH_CHECK_EQ(meta_auth::test::stringify(42), std::string{"42"});
    META_AUTH_CHECK_EQ(meta_auth::test::stringify(-7), std::string{"-7"});
    META_AUTH_CHECK_EQ(meta_auth::test::stringify(true), std::string{"true"});
    META_AUTH_CHECK_EQ(meta_auth::test::stringify(false), std::string{"false"});
}

META_AUTH_TEST("stringify", "strings_are_quoted") {
    // Quoting is what makes a stray leading or trailing space visible in a
    // failure report; without it the report is ambiguous exactly when it
    // matters.
    META_AUTH_CHECK_EQ(meta_auth::test::stringify(std::string_view{" spaced "}),
                       std::string{"\" spaced \""});
    META_AUTH_CHECK_EQ(meta_auth::test::stringify(std::string{"text"}), std::string{"\"text\""});

    // A string literal reaches the `const char*` overload, so it is quoted
    // like any other string. Asserting it here pins the overload set: if the
    // generic template ever started winning this call, literals would silently
    // render unquoted.
    META_AUTH_CHECK_EQ(meta_auth::test::stringify("literal"), std::string{"\"literal\""});
}

META_AUTH_TEST("stringify", "null_pointer_is_named") {
    const char* null_pointer = nullptr;
    META_AUTH_CHECK_EQ(meta_auth::test::stringify(null_pointer), std::string{"<null>"});
}

META_AUTH_TEST("stringify", "types_with_a_formatter_use_it") {
    META_AUTH_CHECK_EQ(meta_auth::test::stringify(renderable{5}), std::string{"renderable(5)"});
}

META_AUTH_TEST("stringify", "unprintable_types_still_name_themselves") {
    const std::string rendered = meta_auth::test::stringify(opaque{1});
    META_AUTH_CHECK(rendered.find("unprintable") != std::string::npos);
#if META_AUTH_HAS_REFLECTION
    // With reflection the placeholder names the type, which is the difference
    // between a report that says "<unprintable opaque>" and one that says
    // "<unprintable T>".
    META_AUTH_CHECK(rendered.find("opaque") != std::string::npos);
#endif
}

// ---------------------------------------------------------------------------
// Recording path
//
// These cases deliberately make the framework record failures, so they run
// inside an `isolation_guard`: the records are real, but they do not mark the
// case as failed and do not leak into the run totals. A harness that cannot be
// tested without failing is a harness whose failure path is untested.
// ---------------------------------------------------------------------------
META_AUTH_TEST("context", "counts_checks_and_failures") {
    using meta_auth::test::isolation_guard;
    auto& ctx = meta_auth::test::context::instance();
    const auto before = ctx.stats();
    capture captured;
    meta_auth::test::statistics observed{};
    meta_auth::test::statistics restored{};

    {
        const isolation_guard isolated;
        ctx.set_sink(&capture::sink, &captured);
        META_AUTH_CHECK(true);
        META_AUTH_CHECK(1 + 1 == 2);
        observed = ctx.stats();
        ctx.set_sink(nullptr, nullptr);
    }
    // Read straight after the guard closes and before any further check runs:
    // a check that reads the counters also increments them, so an assertion
    // about counter values has to be fed from a snapshot taken beforehand.
    restored = ctx.stats();

    META_AUTH_CHECK_EQ(observed.checks, before.checks + 2);
    META_AUTH_CHECK_EQ(observed.failures, before.failures);
    META_AUTH_CHECK(captured.records.empty());

    META_AUTH_CHECK_EQ(restored.checks, before.checks);
    META_AUTH_CHECK_EQ(restored.failures, before.failures);
}

META_AUTH_TEST("context", "a_failed_check_is_recorded_and_returns_false") {
    using meta_auth::test::isolation_guard;
    auto& ctx = meta_auth::test::context::instance();
    const auto before = ctx.stats();
    capture captured;
    bool outcome = true;
    meta_auth::test::statistics observed{};
    meta_auth::test::statistics restored{};

    {
        const isolation_guard isolated;
        ctx.set_sink(&capture::sink, &captured);
        outcome =
            meta_auth::test::detail::check(false, "false", std::source_location::current());
        observed = ctx.stats();
        ctx.set_sink(nullptr, nullptr);
    }
    restored = ctx.stats();

    // The failure was counted while the guard was alive, and rolled back after
    // it: that is what keeps this case green while still testing the path.
    META_AUTH_CHECK_EQ(observed.failures, before.failures + 1);
    META_AUTH_CHECK_EQ(restored.failures, before.failures);
    META_AUTH_CHECK(!outcome);
    META_AUTH_REQUIRE_EQ(captured.records.size(), std::size_t{1});

    const auto& record = captured.records.front();
    META_AUTH_CHECK_EQ(record.expression, std::string_view{"false"});
    META_AUTH_CHECK(!record.fatal);
    META_AUTH_CHECK_EQ(std::string_view{record.where.file_name()}.find("framework_selftest.cpp")
                           != std::string_view::npos,
                       true);
}

META_AUTH_TEST("context", "a_failed_require_is_marked_fatal") {
    using meta_auth::test::isolation_guard;
    capture captured;
    bool threw = false;

    {
        const isolation_guard isolated;
        meta_auth::test::context::instance().set_sink(&capture::sink, &captured);
        try {
            static_cast<void>(meta_auth::test::detail::require(false, "requirement",
                                                               std::source_location::current()));
        } catch (const meta_auth::test::context::case_aborted&) {
            threw = true;
        }
        meta_auth::test::context::instance().set_sink(nullptr, nullptr);
    }

    META_AUTH_CHECK(threw);
    META_AUTH_REQUIRE_EQ(captured.records.size(), std::size_t{1});
    META_AUTH_CHECK(captured.records.front().fatal);
}

META_AUTH_TEST("context", "a_passing_require_does_not_throw") {
    using meta_auth::test::isolation_guard;
    capture captured;
    bool outcome = false;

    {
        const isolation_guard isolated;
        meta_auth::test::context::instance().set_sink(&capture::sink, &captured);
        outcome = meta_auth::test::detail::require(true, "requirement",
                                                   std::source_location::current());
        meta_auth::test::context::instance().set_sink(nullptr, nullptr);
    }

    META_AUTH_CHECK(outcome);
    META_AUTH_CHECK(captured.records.empty());
}

META_AUTH_TEST("context", "binary_checks_render_both_operands") {
    using meta_auth::test::isolation_guard;
    capture captured;
    bool outcome = true;

    {
        const isolation_guard isolated;
        meta_auth::test::context::instance().set_sink(&capture::sink, &captured);
        outcome = meta_auth::test::detail::check_binary(false, "lhs == rhs", std::string{"1"},
                                                        std::string{"2"},
                                                        std::source_location::current(), false);
        meta_auth::test::context::instance().set_sink(nullptr, nullptr);
    }

    META_AUTH_CHECK(!outcome);
    META_AUTH_REQUIRE_EQ(captured.records.size(), std::size_t{1});
    const auto& detail = captured.records.front().detail;
    META_AUTH_CHECK(detail.find("left  = 1") != std::string::npos);
    META_AUTH_CHECK(detail.find("right = 2") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Registry and selection
// ---------------------------------------------------------------------------
META_AUTH_TEST("registry", "cases_are_unique_and_sorted") {
    const auto cases = meta_auth::test::registry::instance().cases();
    META_AUTH_CHECK(!cases.empty());

    for (std::size_t index = 1; index < cases.size(); ++index) {
        const auto& previous = cases[index - 1];
        const auto& current = cases[index];
        const bool ordered = previous.suite < current.suite
                             || (previous.suite == current.suite && previous.name < current.name);
        META_AUTH_CHECK(ordered);
        META_AUTH_CHECK(!(previous.suite == current.suite && previous.name == current.name));
    }
}

META_AUTH_TEST("registry", "every_case_has_a_body") {
    for (const auto& entry : meta_auth::test::registry::instance().cases()) {
        META_AUTH_CHECK(entry.run != nullptr);
        META_AUTH_CHECK(!entry.suite.empty());
        META_AUTH_CHECK(!entry.name.empty());
    }
}

META_AUTH_TEST("options", "filter_is_a_substring_match") {
    using meta_auth::test::matches_filter;
    const meta_auth::test::test_case_entry entry{"capability", "attenuation_is_monotone", nullptr};

    META_AUTH_CHECK(matches_filter(entry, ""));
    META_AUTH_CHECK(matches_filter(entry, "capability"));
    META_AUTH_CHECK(matches_filter(entry, "attenuation"));
    META_AUTH_CHECK(matches_filter(entry, "is_mono"));
    META_AUTH_CHECK(!matches_filter(entry, "revocation"));
    // A filter is a substring, not a glob: this is documented behaviour, and
    // asserting the negative keeps it from drifting into pattern matching.
    META_AUTH_CHECK(!matches_filter(entry, "capab*"));

    // The qualified spelling: what `--list` prints and what a reader copies
    // into `--filter=`. Searching the suite and the name separately -- which is
    // what this did -- means a filter containing the separator matches
    // nothing, so the most obvious way to run one case selected none.
    META_AUTH_CHECK(matches_filter(entry, "capability.attenuation_is_monotone"));
}

META_AUTH_TEST("context", "the_guard_restores_the_sink_it_found") {
    // The sink is part of the state a guarded scope may change, and the guard
    // did not put it back: it restored the counters only. That was latent,
    // because every case cleaned up after itself -- and the first case that did
    // not would have left a dangling user pointer installed for every case that
    // followed, in the harness whose job is to make failures visible.
    using meta_auth::test::isolation_guard;
    auto& ctx = meta_auth::test::context::instance();
    capture outer_captured;
    capture inner_captured;

    ctx.set_sink(&capture::sink, &outer_captured);
    {
        const isolation_guard isolated;
        // A scope that installs its own sink and forgets to remove it: the
        // guard is what has to undo this.
        isolated.use_sink(&capture::sink, &inner_captured);
        META_AUTH_CHECK_EQ(ctx.current_sink_user(), static_cast<void*>(&inner_captured));
    }
    META_AUTH_CHECK_EQ(ctx.current_sink(), &capture::sink);
    META_AUTH_CHECK_EQ(ctx.current_sink_user(), static_cast<void*>(&outer_captured));

    // And the counters came back too, which is the other half of the same
    // promise.
    META_AUTH_CHECK_EQ(ctx.stats().cases_failed, std::size_t{0});
    ctx.set_sink(nullptr, nullptr);
}

META_AUTH_TEST("options", "command_line_is_parsed") {
    const char* argv[] = {"binary", "--verbose", "--filter=capability", nullptr};
    const auto opts = meta_auth::test::parse_options(3, argv);

    META_AUTH_CHECK(opts.verbose);
    META_AUTH_CHECK(!opts.list);
    META_AUTH_CHECK(!opts.help);
    META_AUTH_CHECK_EQ(opts.filter, std::string_view{"capability"});
}

META_AUTH_TEST("options", "an_unknown_argument_is_an_error") {
    // An unrecognised flag must not be ignored, and it must not be taken for
    // a request for help either. A CI job that passes `--filtr=...` and gets a
    // full green run is a job that tested nothing -- and "asks for help" was
    // exactly that green run, because help exits 0.
    const char* argv[] = {"binary", "--nonsense", nullptr};
    const auto opts = meta_auth::test::parse_options(2, argv);
    META_AUTH_CHECK(opts.bad_argument);
    META_AUTH_CHECK(!opts.help);
}

META_AUTH_TEST("options", "a_typo_in_a_filter_selects_nothing") {
    // The concrete keystroke. The exit status is asserted by
    // tests/framework/CMakeLists.txt, which can observe the process; what is
    // asserted here is that the typo does not leave a filter behind, because
    // an empty filter means "run everything".
    const char* argv[] = {"binary", "--filtr=stringify", nullptr};
    const auto opts = meta_auth::test::parse_options(2, argv);
    META_AUTH_CHECK(opts.bad_argument);
    META_AUTH_CHECK(opts.filter.empty());
}

META_AUTH_TEST("options", "help_and_list_are_recognised") {
    {
        const char* argv[] = {"binary", "--help", nullptr};
        META_AUTH_CHECK(meta_auth::test::parse_options(2, argv).help);
    }
    {
        const char* argv[] = {"binary", "-h", nullptr};
        META_AUTH_CHECK(meta_auth::test::parse_options(2, argv).help);
    }
    {
        const char* argv[] = {"binary", "--list", nullptr};
        META_AUTH_CHECK(meta_auth::test::parse_options(2, argv).list);
    }
}

// ---------------------------------------------------------------------------
// Deliberate failures, driven by the failure tests in CMakeLists.txt.
//
// These are the only cases in the suite that are allowed to fail, and they
// fail only when the environment asks them to. Everything they touch is
// already covered positively above; what they add is evidence that the
// harness reports a failure and stops a case at REQUIRE.
// ---------------------------------------------------------------------------
META_AUTH_TEST("self_report", "deliberate_check_failure") {
    require_mode("check");
    META_AUTH_CHECK_EQ(1, 2);
    META_AUTH_CHECK(false);
}

META_AUTH_TEST("self_report", "deliberate_require_failure") {
    require_mode("require");
    META_AUTH_REQUIRE_EQ(1, 2);
    // Unreachable: the failure test asserts that exactly one check ran, which
    // is only true if REQUIRE abandoned the case here.
    META_AUTH_CHECK(false);
}
