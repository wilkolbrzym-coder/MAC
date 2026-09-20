// ===========================================================================
//  meta-auth-core -- test runner.
//
//  Compiled into every test binary by `meta_auth_add_test` (see
//  cmake/MetaAuthTestHelpers.cmake), so a test source file contains only test
//  cases and no `main`.
//
//  Exit codes are part of the CI contract:
//      0  every selected case passed
//      1  at least one case failed
//      2  the selection was empty (a filter that matches nothing is a typo,
//         not a green run)
//      3  an argument was not recognised (also a typo, and one that used to
//         exit 0 with the usage text -- see `options::bad_argument`)
// ===========================================================================
#include "test_framework.hpp"

#include <chrono>
#include <cstring>
#include <string>
#include <vector>

namespace meta_auth::test {
namespace {

constexpr std::string_view usage_text = R"(meta-auth-core test runner

usage: <test-binary> [options]

options:
  --filter=<substring>   run only cases whose "suite.name" contains the text
  --list                 print the selected cases and exit
  --verbose, -v          print a line for every case, not only for failures
  --help, -h             print this message

exit codes: 0 all selected cases passed, 1 a case failed,
            2 the selection was empty, 3 an argument was not recognised
)";

/// A case name that appears twice in the registry means one of the two
/// implementations never runs -- a defect in the suite itself, and one that
/// would otherwise be invisible because the binary is still green.
auto find_duplicate(const std::vector<test_case_entry>& cases) -> const test_case_entry* {
    for (std::size_t i = 0; i < cases.size(); ++i) {
        for (std::size_t j = i + 1; j < cases.size(); ++j) {
            if (cases[i].suite == cases[j].suite && cases[i].name == cases[j].name) {
                return &cases[i];
            }
        }
    }
    return nullptr;
}

} // namespace

auto parse_options(int argc, const char* const* argv) -> options {
    options opts;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--help" || argument == "-h") {
            opts.help = true;
        } else if (argument == "--list") {
            opts.list = true;
        } else if (argument == "--verbose" || argument == "-v") {
            opts.verbose = true;
        } else if (argument.starts_with("--filter=")) {
            opts.filter = argument.substr(std::strlen("--filter="));
        } else {
            std::fprintf(stderr, "unrecognised argument: %.*s\n\n", static_cast<int>(argument.size()),
                         argument.data());
            opts.bad_argument = true;
        }
    }
    return opts;
}

auto matches_filter(const test_case_entry& entry, std::string_view filter) -> bool {
    if (filter.empty()) {
        return true;
    }
    if (entry.suite.find(filter) != std::string_view::npos) {
        return true;
    }
    if (entry.name.find(filter) != std::string_view::npos) {
        return true;
    }
    // The qualified spelling, which is what the documentation promises and
    // what the two checks above do not deliver: they search the suite and the
    // name separately, so `--filter=options.command_line` -- the spelling
    // `--list` prints and a reader copies -- matched nothing and selected an
    // empty set.
    std::string qualified;
    qualified.reserve(entry.suite.size() + 1U + entry.name.size());
    qualified.append(entry.suite).append(".").append(entry.name);
    return qualified.find(filter) != std::string::npos;
}

auto run_all(const options& opts) -> int {
    if (opts.help) {
        std::fputs(usage_text.data(), stdout);
        return 0;
    }

    // An unrecognised argument fails the run rather than printing the usage
    // and succeeding. The distinction matters most where nobody is reading
    // the output: a script that passes the wrong flag must not be able to
    // report a pass, and the usage text is printed either way so the reader
    // still sees what the flag should have been.
    if (opts.bad_argument) {
        std::fputs(usage_text.data(), stdout);
        return 3;
    }

    auto cases = registry::instance().cases();

    std::vector<test_case_entry> selected;
    for (const auto& entry : cases) {
        if (matches_filter(entry, opts.filter)) {
            selected.push_back(entry);
        }
    }

    if (opts.list) {
        for (const auto& entry : selected) {
            std::printf("%.*s.%.*s\n", static_cast<int>(entry.suite.size()), entry.suite.data(),
                        static_cast<int>(entry.name.size()), entry.name.data());
        }
        return 0;
    }

    if (selected.empty()) {
        std::fprintf(stderr, "no test cases matched filter '%.*s' among %zu registered cases\n",
                     static_cast<int>(opts.filter.size()), opts.filter.data(), cases.size());
        return 2;
    }

    if (const test_case_entry* duplicate = find_duplicate(cases); duplicate != nullptr) {
        std::fprintf(stderr,
                     "duplicate test case '%.*s.%.*s': one of the two definitions never runs\n",
                     static_cast<int>(duplicate->suite.size()), duplicate->suite.data(),
                     static_cast<int>(duplicate->name.size()), duplicate->name.data());
        return 1;
    }

    std::fputs("\nmeta-auth-core test run\n", stdout);
    std::printf("  dialect  : %s\n", ::meta_auth::config::dialect_summary());
    std::printf("  cases    : %zu selected of %zu registered\n", selected.size(), cases.size());
    if (!opts.filter.empty()) {
        std::printf("  filter   : %.*s\n", static_cast<int>(opts.filter.size()), opts.filter.data());
    }

    auto& ctx = context::instance();
    const auto started = std::chrono::steady_clock::now();
    std::vector<std::string> failed_cases;
    std::vector<std::string> skipped_cases;

    for (const auto& entry : selected) {
        ctx.begin_case(entry.suite, entry.name);

        if (opts.verbose) {
            std::printf("  [ RUN      ] %.*s.%.*s\n", static_cast<int>(entry.suite.size()),
                        entry.suite.data(), static_cast<int>(entry.name.size()), entry.name.data());
            std::fflush(stdout);
        }

        try {
            entry.run();
        } catch (const context::case_skipped& skipped) {
            ctx.note_skip();
            skipped_cases.emplace_back(std::string{entry.suite} + "." + std::string{entry.name}
                                       + ": " + skipped.reason);
            if (opts.verbose) {
                std::printf("  [     SKIP ] %s\n", skipped.reason.c_str());
            }
        } catch (const context::case_aborted&) {
            // REQUIRE already recorded the failure that caused the abort.
        } catch (const std::exception& error) {
            // An escaping exception is a harness-level failure: the case threw
            // something that is not part of the framework's protocol.
            ctx.record_check(false, "no exception escapes a test case",
                             std::string{"unexpected exception: "} + error.what(),
                             std::source_location::current(), false);
        } catch (...) {
            ctx.record_check(false, "no exception escapes a test case",
                             "unexpected exception of unknown type",
                             std::source_location::current(), false);
        }

        if (ctx.case_failed()) {
            failed_cases.emplace_back(std::string{entry.suite} + "." + std::string{entry.name});
        } else if (opts.verbose) {
            std::printf("  [       OK ] %.*s.%.*s\n", static_cast<int>(entry.suite.size()),
                        entry.suite.data(), static_cast<int>(entry.name.size()), entry.name.data());
        }

        ctx.end_case();
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    const auto& stats = ctx.stats();

    std::printf("\n  checks   : %zu\n", stats.checks);
    std::printf("  failures : %zu in %zu case(s)\n", stats.failures, stats.cases_failed);
    if (stats.cases_skipped != 0) {
        std::printf("  skipped  : %zu\n", stats.cases_skipped);
    }
    std::printf("  duration : %lld ms\n", static_cast<long long>(elapsed.count()));

    if (!failed_cases.empty()) {
        std::fputs("\n  FAILED\n", stdout);
        for (const auto& name : failed_cases) {
            std::printf("    %s\n", name.c_str());
        }
    }
    if (!skipped_cases.empty() && !opts.verbose) {
        std::fputs("\n  SKIPPED\n", stdout);
        for (const auto& name : skipped_cases) {
            std::printf("    %s\n", name.c_str());
        }
    }

    std::printf("\n%s\n", failed_cases.empty() ? "PASSED" : "FAILED");
    return failed_cases.empty() ? 0 : 1;
}

} // namespace meta_auth::test

auto main(int argc, char** argv) -> int {
    return meta_auth::test::run_all(meta_auth::test::parse_options(argc, argv));
}
