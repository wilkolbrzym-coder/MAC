// ===========================================================================
//  Contract violation probe.
//
//  A process that is supposed to die cannot assert its own death, so this
//  program exists to be run *by* the failure tests in CMakeLists.txt: each
//  mode violates one kind of contract and is expected to be reported and then
//  terminated.
//
//  Two properties are being probed, and the second is the interesting one:
//
//    1. a violation terminates the process (rather than throwing, returning or
//       continuing in a degraded mode);
//    2. the *same* fact is enforced with the same report in a build without
//       contract support, where the check comes from the portable fallback.
//       Only the classification differs -- `pre`/`post` become `assertion`,
//       because `contract_assert` is the only statement form P2900 offers --
//       and the expected diagnostics in CMakeLists.txt record that.
// ===========================================================================
#include "meta_auth/core/contract.hpp"

#include <cstdio>
#include <cstring>
#include <string_view>

namespace {

/// Deliberately violable. The declarator carries the check where the compiler
/// supports contracts; `META_AUTH_PRE_FALLBACK` / `META_AUTH_POST_FALLBACK`
/// carry it everywhere else. The local is named `result` so that the stringised
/// condition is identical in both configurations, which lets one expected
/// diagnostic cover both.
[[nodiscard]] auto checked_ratio(int numerator, int denominator) -> double
    META_AUTH_PRE(denominator != 0)
    META_AUTH_POST(result: result >= 0.0)
{
    META_AUTH_PRE_FALLBACK(denominator != 0);
    const double result = static_cast<double>(numerator) / static_cast<double>(denominator);
    META_AUTH_POST_FALLBACK(result >= 0.0);
    return result;
}

struct observer_state {
    int calls = 0;
};

void observe_violation(void* user, const meta_auth::diag::violation_record& record) {
    auto* state = static_cast<observer_state*>(user);
    ++state->calls;
    std::printf("observer: call=%d kind=%s sequence=%llu\n", state->calls,
                std::string_view{meta_auth::diag::to_string(record.kind)}.data(),
                static_cast<unsigned long long>(record.sequence));
    std::fflush(stdout);
}

void report_usage(const char* program) {
    std::fprintf(stderr,
                 "usage: %s <mode>\n"
                 "  pre          violate a precondition\n"
                 "  post         violate a postcondition\n"
                 "  assert       violate a body assertion\n"
                 "  unreachable  reach a branch declared unreachable\n"
                 "  observer     report a violation with an observer installed\n",
                 program);
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc != 2) {
        report_usage(argv[0]);
        return 2;
    }

    const std::string_view mode{argv[1]};
    std::printf("probe: mode=%s contracts=%d\n", mode.data(), META_AUTH_HAS_CONTRACTS);
    std::fflush(stdout);

    // `volatile` keeps the compiler from evaluating the violation at compile
    // time: the probe has to fail at run time, in the process CTest inspects.
    volatile int zero = 0;
    volatile int negative = -4;

    if (mode == "pre") {
        static_cast<void>(checked_ratio(1, zero));
    } else if (mode == "post") {
        static_cast<void>(checked_ratio(negative, 2));
    } else if (mode == "assert") {
        META_AUTH_ASSERT(zero != 0);
    } else if (mode == "unreachable") {
        META_AUTH_UNREACHABLE("this branch is unreachable by design");
    } else if (mode == "observer") {
        observer_state state;
        meta_auth::diag::set_violation_observer(&observe_violation, &state);
        META_AUTH_ASSERT(zero == 1);
    } else {
        std::fprintf(stderr, "unknown mode: %s\n", mode.data());
        report_usage(argv[0]);
        return 2;
    }

    // Reaching this line means a violated contract did not stop the process,
    // which is the defect the failure tests are looking for.
    std::fputs("probe: survived a violated contract\n", stderr);
    return 1;
}
