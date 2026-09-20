# ---------------------------------------------------------------------------
# MetaAuthCompileFail -- driver for one negative test.
#
# Purpose
# -------
# This library claims that certain programs are *ill-formed*, not merely
# rejected at run time. Such a claim is only evidence if the build actually
# tries to compile those programs and inspects the diagnostic. This script is
# that attempt: it compiles a source that must fail, and checks that the
# diagnostic contains the marker recorded next to it.
#
# Why a script rather than `try_compile`
# --------------------------------------
# `try_compile` answers "did it build?", not "why did it not build?". The
# expectation file turns each negative test into an assertion about the
# *reason*, so an unrelated breakage (a typo, a missing include) cannot be
# mistaken for the guarantee being tested.
#
# Expectation file format
# -----------------------
#   * blank lines and lines starting with '#' are ignored;
#   * every other line is a substring that must occur in the compiler output;
#   * a line of the form '!<text>' must NOT occur in the output.
#
# Requires: META_AUTH_NEGATIVE_SOURCE, META_AUTH_NEGATIVE_EXPECTATION,
#           META_AUTH_NEGATIVE_COMPILER, META_AUTH_NEGATIVE_INCLUDE_DIR,
#           META_AUTH_NEGATIVE_STANDARD, and optionally
#           META_AUTH_NEGATIVE_CONTRACTS / META_AUTH_NEGATIVE_REFLECTION.
# ---------------------------------------------------------------------------

foreach(_required
        META_AUTH_NEGATIVE_SOURCE
        META_AUTH_NEGATIVE_EXPECTATION
        META_AUTH_NEGATIVE_COMPILER
        META_AUTH_NEGATIVE_INCLUDE_DIR)
    if(NOT DEFINED ${_required})
        message(FATAL_ERROR "MetaAuthCompileFail.cmake: ${_required} is not set.")
    endif()
endforeach()

if(NOT DEFINED META_AUTH_NEGATIVE_STANDARD)
    set(META_AUTH_NEGATIVE_STANDARD 26)
endif()

# The negative test must be compiled with the same dialect switches as the
# library itself. Otherwise a test could "pass" because a feature was off,
# which would assert the opposite of what it claims.
set(_flags "-std=c++${META_AUTH_NEGATIVE_STANDARD}")
if(META_AUTH_NEGATIVE_CONTRACTS)
    list(APPEND _flags "-fcontracts")
endif()
if(META_AUTH_NEGATIVE_REFLECTION)
    list(APPEND _flags "-freflection")
endif()
list(APPEND _flags "-fsyntax-only")
list(APPEND _flags "-I${META_AUTH_NEGATIVE_INCLUDE_DIR}")

execute_process(
    COMMAND "${META_AUTH_NEGATIVE_COMPILER}" ${_flags} "${META_AUTH_NEGATIVE_SOURCE}"
    RESULT_VARIABLE _result
    OUTPUT_VARIABLE _stdout
    ERROR_VARIABLE _stderr)

set(_diagnostics "${_stdout}${_stderr}")

get_filename_component(_case_name "${META_AUTH_NEGATIVE_SOURCE}" NAME)

# --- 1. The program must not compile. -------------------------------------
if(_result EQUAL 0)
    message(FATAL_ERROR
        "NEGATIVE TEST FAILED: ${_case_name} compiled successfully.\n"
        "This program is supposed to be ill-formed. Either the guarantee it "
        "documents has regressed, or the test no longer exercises it.")
endif()

# A compiler that fails for an environmental reason (missing header, bad
# flag) would make every negative test pass vacuously. That failure mode is
# ruled out by requiring the diagnostic to look like a C++ diagnostic.
if(NOT _diagnostics MATCHES "error:")
    message(FATAL_ERROR
        "NEGATIVE TEST INCONCLUSIVE: ${_case_name} failed to compile without "
        "producing a diagnostic containing 'error:'. The failure is probably "
        "environmental, not the rejection this test asserts.\n"
        "--- output ---\n${_diagnostics}")
endif()

# --- 2. The diagnostic must say what the test claims it says. -------------
file(STRINGS "${META_AUTH_NEGATIVE_EXPECTATION}" _expectation_lines)

set(_required_count 0)
foreach(_line IN LISTS _expectation_lines)
    string(STRIP "${_line}" _line)
    if(_line STREQUAL "" OR _line MATCHES "^#")
        continue()
    endif()

    if(_line MATCHES "^!(.*)")
        set(_forbidden "${CMAKE_MATCH_1}")
        if(_diagnostics MATCHES "${_forbidden}")
            message(FATAL_ERROR
                "NEGATIVE TEST FAILED: ${_case_name} produced a diagnostic "
                "that the expectation file forbids: '${_forbidden}'.\n"
                "--- output ---\n${_diagnostics}")
        endif()
    else()
        math(EXPR _required_count "${_required_count} + 1")
        if(NOT _diagnostics MATCHES "${_line}")
            message(FATAL_ERROR
                "NEGATIVE TEST FAILED: ${_case_name} was rejected, but not for "
                "the documented reason.\n"
                "  expected diagnostic containing: ${_line}\n"
                "--- output ---\n${_diagnostics}")
        endif()
    endif()
endforeach()

if(_required_count EQUAL 0)
    message(FATAL_ERROR
        "NEGATIVE TEST INCONCLUSIVE: ${_case_name} has no required diagnostic "
        "in '${META_AUTH_NEGATIVE_EXPECTATION}'. An expectation file that only "
        "forbids things asserts nothing about why the program was rejected.")
endif()

message(STATUS "compile-failure test '${_case_name}' rejected as documented.")
