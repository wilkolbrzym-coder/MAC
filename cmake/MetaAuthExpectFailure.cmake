# ---------------------------------------------------------------------------
# MetaAuthExpectFailure -- assert *how* a process fails.
#
# Several guarantees in this library are fail-stop: the process must die, and
# it must die for the documented reason. CTest's WILL_FAIL only inverts the
# exit status, which accepts any failure at all -- including the wrong one.
# This driver asserts both halves:
#
#   * the exit status matches RESULT_REGEX (a number, or the message CMake
#     reports for a signal-terminated child such as "Subprocess aborted");
#   * the combined output matches OUTPUT_REGEX, so "it crashed" becomes "it
#     aborted after reporting a contract violation in <function>".
#
# Requires: META_AUTH_EXPECT_PROGRAM, META_AUTH_EXPECT_RESULT_REGEX and
#           optionally META_AUTH_EXPECT_ARGS, META_AUTH_EXPECT_OUTPUT_REGEX.
# ---------------------------------------------------------------------------
foreach(_required META_AUTH_EXPECT_PROGRAM META_AUTH_EXPECT_RESULT_REGEX)
    if(NOT DEFINED ${_required})
        message(FATAL_ERROR "MetaAuthExpectFailure.cmake: ${_required} is not set.")
    endif()
endforeach()

execute_process(
    COMMAND "${META_AUTH_EXPECT_PROGRAM}" ${META_AUTH_EXPECT_ARGS}
    RESULT_VARIABLE _result
    OUTPUT_VARIABLE _stdout
    ERROR_VARIABLE _stderr)

set(_output "${_stdout}${_stderr}")

if(NOT "${_result}" MATCHES "${META_AUTH_EXPECT_RESULT_REGEX}")
    message(FATAL_ERROR
        "FAILURE TEST FAILED: '${META_AUTH_EXPECT_PROGRAM}' exited with '${_result}', "
        "which does not match the expected '${META_AUTH_EXPECT_RESULT_REGEX}'.\n"
        "--- output ---\n${_output}")
endif()

if(DEFINED META_AUTH_EXPECT_OUTPUT_REGEX AND NOT _output MATCHES "${META_AUTH_EXPECT_OUTPUT_REGEX}")
    message(FATAL_ERROR
        "FAILURE TEST FAILED: '${META_AUTH_EXPECT_PROGRAM}' failed as expected, but not "
        "for the documented reason.\n"
        "  expected output matching: ${META_AUTH_EXPECT_OUTPUT_REGEX}\n"
        "--- output ---\n${_output}")
endif()

message(STATUS "failure test '${META_AUTH_EXPECT_PROGRAM}' failed as documented (result: ${_result}).")
