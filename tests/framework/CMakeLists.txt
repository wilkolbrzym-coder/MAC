# ---------------------------------------------------------------------------
# Test framework.
#
# The framework is not a library: `main.cpp` is compiled into every test
# binary (see `meta_auth_add_test`), and the header is on the private include
# path of each of them. Nothing here is installed.
#
# The framework is itself tested. A harness whose failure path does not work
# converts every later "all tests passed" into an unsupported claim, so the
# two ways it can fail -- a failed CHECK and a failed REQUIRE -- are exercised
# as failure tests that assert both the exit status and the report text.
# ---------------------------------------------------------------------------
add_library(meta_auth_test_framework INTERFACE)
target_include_directories(meta_auth_test_framework INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(meta_auth_test_framework INTERFACE meta_auth::meta_auth)

meta_auth_add_test(meta_auth_framework_selftest
    GROUP unit
    SOURCES framework_selftest.cpp
    TIMEOUT 60)

# A failed CHECK must make the process exit non-zero and name the case.
meta_auth_add_failure_test(framework.check_failure_is_reported
    PROGRAM "$<TARGET_FILE:meta_auth_framework_selftest>"
    ARGS --verbose
    RESULT_REGEX "^1$"
    OUTPUT_REGEX "FAIL self_report\\.deliberate_check_failure"
    ENVIRONMENT "META_AUTH_FRAMEWORK_SELFTEST=check"
    LABELS "unit"
    TIMEOUT 60)

# A failed REQUIRE must abandon the case at that point. The evidence is the
# check count: exactly one check ran, and the case still endures no further
# evaluation.
meta_auth_add_failure_test(framework.require_failure_is_fatal
    PROGRAM "$<TARGET_FILE:meta_auth_framework_selftest>"
    ARGS --verbose
    RESULT_REGEX "^1$"
    OUTPUT_REGEX "failures : 1 in 1 case"
    ENVIRONMENT "META_AUTH_FRAMEWORK_SELFTEST=require"
    LABELS "unit"
    TIMEOUT 60)

# A filter that matches nothing must not be reported as a green run.
meta_auth_add_failure_test(framework.empty_selection_is_an_error
    PROGRAM "$<TARGET_FILE:meta_auth_framework_selftest>"
    ARGS --filter=no_such_case_exists
    RESULT_REGEX "^2$"
    OUTPUT_REGEX "no test cases matched filter"
    LABELS "unit"
    TIMEOUT 60)

# A misspelled option must fail the run. It used to exit 0 with the usage
# text, so a CI job that passed `--filtr=...` ran every case and reported a
# pass -- the failure mode the runner's exit codes exist to prevent.
meta_auth_add_failure_test(framework.unknown_argument_is_an_error
    PROGRAM "$<TARGET_FILE:meta_auth_framework_selftest>"
    ARGS --filtr=stringify
    RESULT_REGEX "^3$"
    OUTPUT_REGEX "unrecognised argument: --filtr=stringify"
    LABELS "unit"
    TIMEOUT 60)
