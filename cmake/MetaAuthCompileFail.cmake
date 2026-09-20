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
#   * every other line is a substring that must occur in the compiler output,
#     compared *literally*;
#   * a line of the form '!<text>' must NOT occur in the output, also literally.
#
# The comparison is literal -- `string(FIND ...)`, not `MATCHES` -- because the
# expected text is C++ source, and C++ source is full of regex metacharacters.
# `capability(const capability<R, Rights>&)` as a regex means "capability
# immediately followed by const capability<R, Rights>&": the parentheses
# become a group and stop matching themselves, so the check silently stops
# checking. That is not hypothetical; it is how the first version of this
# driver matched `use of deleted function` and quietly failed on every
# signature it was supposed to pin down.
#
# Two files, and the union of their lines is what must appear:
#
#   * `expected/<case>.txt` is the portable half. It holds the sentences this
#     library writes into its own `= delete("...")` declarations -- which every
#     compiler reproduces verbatim, because they are part of the program -- and
#     at most a token all three families agree on.
#   * `expected/<case>.<family>.txt` is the compiler-specific half, where
#     <family> is gcc, clang or msvc. It holds the spellings that are not
#     shared: "use of deleted function" against "call to deleted constructor of"
#     against "attempting to reference a deleted function".
#
# The split is what makes the suite portable without making it vague. The
# alternative -- one file of GCC spellings -- is a suite that reports a green
# run on the one compiler it was written for and an unintelligible failure
# everywhere else, which is how a negative suite ends up deleted rather than
# fixed.
#
# Requires: META_AUTH_NEGATIVE_SOURCE, META_AUTH_NEGATIVE_EXPECTATION,
#           META_AUTH_NEGATIVE_COMPILER, META_AUTH_NEGATIVE_INCLUDE_DIR,
#           META_AUTH_NEGATIVE_STANDARD, META_AUTH_NEGATIVE_FAMILY, and
#           optionally META_AUTH_NEGATIVE_CONTRACTS /
#           META_AUTH_NEGATIVE_REFLECTION.
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

if(NOT DEFINED META_AUTH_NEGATIVE_FAMILY)
    set(META_AUTH_NEGATIVE_FAMILY "gcc")
endif()

# --- 1. The command line, in this compiler's dialect. ---------------------
#
# The negative test must be compiled with the same dialect switches as the
# library itself. Otherwise a test could "pass" because a feature was off,
# which would assert the opposite of what it claims.
set(_flags "")
if(META_AUTH_NEGATIVE_FAMILY STREQUAL "msvc")
    list(APPEND _flags "/nologo" "/std:c++latest" "/Zs" "/Zc:__cplusplus"
         "/Zc:preprocessor" "/permissive-"
         "/I${META_AUTH_NEGATIVE_INCLUDE_DIR}")
    # A marker that says "this is a C++ diagnostic", which MSVC spells with a
    # number that the other two do not have.
    set(_error_pattern "error C[0-9]+:")
else()
    list(APPEND _flags "-std=c++${META_AUTH_NEGATIVE_STANDARD}")
    if(META_AUTH_NEGATIVE_CONTRACTS)
        list(APPEND _flags "-fcontracts")
    endif()
    if(META_AUTH_NEGATIVE_REFLECTION)
        list(APPEND _flags "-freflection")
    endif()
    list(APPEND _flags "-fsyntax-only")
    list(APPEND _flags "-I${META_AUTH_NEGATIVE_INCLUDE_DIR}")
    set(_error_pattern "error:")
endif()

execute_process(
    COMMAND "${META_AUTH_NEGATIVE_COMPILER}" ${_flags} "${META_AUTH_NEGATIVE_SOURCE}"
    RESULT_VARIABLE _result
    OUTPUT_VARIABLE _stdout
    ERROR_VARIABLE _stderr)

set(_diagnostics "${_stdout}${_stderr}")

get_filename_component(_case_name "${META_AUTH_NEGATIVE_SOURCE}" NAME)

# --- 2. The program must not compile. -------------------------------------
if(_result EQUAL 0)
    message(FATAL_ERROR
        "NEGATIVE TEST FAILED: ${_case_name} compiled successfully.\n"
        "This program is supposed to be ill-formed. Either the guarantee it "
        "documents has regressed, or the test no longer exercises it.")
endif()

# A compiler that fails for an environmental reason (missing header, bad
# flag) would make every negative test pass vacuously. That failure mode is
# ruled out by requiring the diagnostic to look like a C++ diagnostic.
if(NOT _diagnostics MATCHES "${_error_pattern}")
    message(FATAL_ERROR
        "NEGATIVE TEST INCONCLUSIVE: ${_case_name} failed to compile without "
        "producing a diagnostic matching '${_error_pattern}'. The failure is probably "
        "environmental, not the rejection this test asserts.\n"
        "--- command line ---\n${META_AUTH_NEGATIVE_COMPILER} ${_flags}\n"
        "--- output ---\n${_diagnostics}")
endif()

# --- 3. The diagnostic must say what the test claims it says. -------------
#
# The portable file, plus this compiler's file when one exists. The family file
# lives next to the portable one: `<dir>/expected/<case>.<family>.txt`.
get_filename_component(_expectation_dir "${META_AUTH_NEGATIVE_EXPECTATION}" DIRECTORY)
get_filename_component(_expectation_stem "${META_AUTH_NEGATIVE_EXPECTATION}" NAME_WE)

set(_expectation_files "${META_AUTH_NEGATIVE_EXPECTATION}")
set(_family_file "${_expectation_dir}/${_expectation_stem}.${META_AUTH_NEGATIVE_FAMILY}.txt")
if(EXISTS "${_family_file}")
    list(APPEND _expectation_files "${_family_file}")
endif()

# Read a file as a list of lines, one element per line.
#
# Not `file(STRINGS)`: that also returns a CMake list, and a CMake list is a
# semicolon-delimited string, so a line containing a semicolon is silently
# split into two elements -- which then become two independent requirements,
# neither of them the line the author wrote. Expectation files quote C++
# signatures and compiler messages, where a semicolon is ordinary punctuation;
# this driver failed on a comment containing one.
function(meta_auth_read_lines path out_var)
    file(READ "${path}" _remaining)
    set(_lines "")
    while(TRUE)
        string(FIND "${_remaining}" "\n" _newline)
        if(_newline EQUAL -1)
            break()
        endif()
        string(SUBSTRING "${_remaining}" 0 ${_newline} _line)
        math(EXPR _after "${_newline} + 1")
        string(SUBSTRING "${_remaining}" ${_after} -1 _remaining)
        string(REPLACE ";" "\\;" _line "${_line}")
        list(APPEND _lines "${_line}")
    endwhile()
    if(NOT _remaining STREQUAL "")
        string(REPLACE ";" "\\;" _remaining "${_remaining}")
        list(APPEND _lines "${_remaining}")
    endif()
    set(${out_var} "${_lines}" PARENT_SCOPE)
endfunction()

set(_required_count 0)

# Each file is read and checked inside the same loop. Accumulating the lines
# into one list first would undo the escaping above: `list(APPEND out ${part})`
# re-splits on the semicolons that were just escaped, which is how the first
# version of this fix reintroduced the bug it was written to remove.
foreach(_file IN LISTS _expectation_files)
    meta_auth_read_lines("${_file}" _expectation_lines)

    foreach(_line IN LISTS _expectation_lines)
        string(STRIP "${_line}" _line)
        if(_line STREQUAL "" OR _line MATCHES "^#")
            continue()
        endif()

        if(_line MATCHES "^!(.*)")
            set(_forbidden "${CMAKE_MATCH_1}")
            string(FIND "${_diagnostics}" "${_forbidden}" _forbidden_position)
            if(NOT _forbidden_position EQUAL -1)
                message(FATAL_ERROR
                    "NEGATIVE TEST FAILED: ${_case_name} produced a diagnostic "
                    "that the expectation file forbids: '${_forbidden}'.\n"
                    "--- output ---\n${_diagnostics}")
            endif()
        else()
            math(EXPR _required_count "${_required_count} + 1")
            string(FIND "${_diagnostics}" "${_line}" _found_position)
            if(_found_position EQUAL -1)
                message(FATAL_ERROR
                    "NEGATIVE TEST FAILED: ${_case_name} was rejected, but not for "
                    "the documented reason.\n"
                    "  expected diagnostic containing: ${_line}\n"
                    "  expectation files: ${_expectation_files}\n"
                    "--- command line ---\n${META_AUTH_NEGATIVE_COMPILER} ${_flags}\n"
                    "--- output ---\n${_diagnostics}")
            endif()
        endif()
    endforeach()
endforeach()

if(_required_count EQUAL 0)
    message(FATAL_ERROR
        "NEGATIVE TEST INCONCLUSIVE: ${_case_name} has no required diagnostic "
        "in '${META_AUTH_NEGATIVE_EXPECTATION}'. An expectation file that only "
        "forbids things asserts nothing about why the program was rejected.")
endif()

message(STATUS "compile-failure test '${_case_name}' rejected as documented "
               "(${META_AUTH_NEGATIVE_FAMILY}).")
