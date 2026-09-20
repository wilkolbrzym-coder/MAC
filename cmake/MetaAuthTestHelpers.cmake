# ---------------------------------------------------------------------------
# MetaAuthTestHelpers -- declaration of how a test is allowed to look.
#
# Conventions this module enforces, so that the suite stays uniform:
#
#   * a test target links `meta_auth::meta_auth` plus the instrumentation
#     interface, never a hand-written include path;
#   * every test is registered with CTest under the group it belongs to, so
#     `ctest -L unit` and `ctest -L compile_fail` select meaningful subsets;
#   * a test that is expected to crash (the fail-stop tests around contract
#     violations) is registered through `meta_auth_add_crash_test()` rather
#     than by weakening the assertion.
# ---------------------------------------------------------------------------

# meta_auth_add_test(<name>
#                    GROUP <unit|property|concurrency|dialect|integration>
#                    SOURCES <file>...
#                    [LIBRARIES <target>...]
#                    [LABELS <label>...]
#                    [TIMEOUT <seconds>])
function(meta_auth_add_test name)
    cmake_parse_arguments(ARG "" "GROUP;TIMEOUT" "SOURCES;LIBRARIES;LABELS" ${ARGN})

    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "meta_auth_add_test(${name}) requires SOURCES.")
    endif()
    if(NOT ARG_GROUP)
        set(ARG_GROUP "unit")
    endif()

    # The runner is compiled into every test binary, so a test source file
    # contains test cases and nothing else. The variables are set by
    # tests/CMakeLists.txt and are required rather than defaulted: a silently
    # missing runner would produce a link error that says nothing about why.
    if(NOT DEFINED META_AUTH_TEST_FRAMEWORK_MAIN OR NOT DEFINED META_AUTH_TEST_FRAMEWORK_DIR)
        message(FATAL_ERROR
            "meta_auth_add_test() used before tests/CMakeLists.txt defined "
            "META_AUTH_TEST_FRAMEWORK_MAIN / META_AUTH_TEST_FRAMEWORK_DIR.")
    endif()

    add_executable(${name} ${ARG_SOURCES} "${META_AUTH_TEST_FRAMEWORK_MAIN}")
    target_include_directories(${name} PRIVATE "${META_AUTH_TEST_FRAMEWORK_DIR}")
    target_link_libraries(${name} PRIVATE
        meta_auth::meta_auth
        meta_auth_sanitizers
        ${ARG_LIBRARIES})

    # Tests are compiled with the project's warning set but not with
    # -Werror-by-default on other toolchains; the library target already
    # publishes the warnings, this only adds the test-specific clamp.
    set_target_properties(${name} PROPERTIES
        CXX_STANDARD 26
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES
        LABELS "${ARG_GROUP};${ARG_LABELS}"
        TIMEOUT "${ARG_TIMEOUT}")
endfunction()

# meta_auth_add_failure_test(<name>
#                            PROGRAM <executable>
#                            RESULT_REGEX <regex>
#                            [ARGS <arg>...]
#                            [OUTPUT_REGEX <regex>]
#                            [ENVIRONMENT <var=value>...]
#                            [LABELS <label>...]
#                            [TIMEOUT <seconds>])
#
# Registers a test whose *success* is the process failing in a documented way.
# Fail-stop behaviour cannot be asserted from inside the process that stops,
# so it is asserted from the harness, and the driver checks the reason as well
# as the status (see cmake/MetaAuthExpectFailure.cmake).
function(meta_auth_add_failure_test name)
    cmake_parse_arguments(ARG "" "PROGRAM;RESULT_REGEX;OUTPUT_REGEX;TIMEOUT"
                              "ARGS;ENVIRONMENT;LABELS" ${ARGN})

    if(NOT ARG_PROGRAM)
        message(FATAL_ERROR "meta_auth_add_failure_test(${name}) requires PROGRAM.")
    endif()
    if(NOT ARG_RESULT_REGEX)
        message(FATAL_ERROR
            "meta_auth_add_failure_test(${name}) requires RESULT_REGEX. "
            "'It must fail' is not a testable claim; state the expected status.")
    endif()

    add_test(NAME ${name}
        COMMAND "${CMAKE_COMMAND}"
            "-DMETA_AUTH_EXPECT_PROGRAM=${ARG_PROGRAM}"
            "-DMETA_AUTH_EXPECT_RESULT_REGEX=${ARG_RESULT_REGEX}"
            "-DMETA_AUTH_EXPECT_ARGS=${ARG_ARGS}"
            "-DMETA_AUTH_EXPECT_OUTPUT_REGEX=${ARG_OUTPUT_REGEX}"
            -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/MetaAuthExpectFailure.cmake")

    set_tests_properties(${name} PROPERTIES
        LABELS "fail_stop;${ARG_LABELS}"
        TIMEOUT "${ARG_TIMEOUT}")

    if(ARG_ENVIRONMENT)
        set_tests_properties(${name} PROPERTIES ENVIRONMENT "${ARG_ENVIRONMENT}")
    endif()
endfunction()

# meta_auth_add_compile_fail_test(<source> [TIMEOUT <seconds>])
#
# Registers one negative test: the translation unit must NOT compile, and its
# diagnostics must contain the marker recorded in the adjacent `.expected`
# file. Deleting the marker from the expectation file is how a reviewer
# acknowledges that a rejected program became legal.
function(meta_auth_add_compile_fail_test source)
    cmake_parse_arguments(ARG "" "TIMEOUT" "" ${ARGN})

    get_filename_component(_name "${source}" NAME_WE)
    get_filename_component(_dir "${source}" DIRECTORY)
    set(_expectation "${_dir}/expected/${_name}.txt")

    if(NOT EXISTS "${_expectation}")
        message(FATAL_ERROR
            "Compile-failure test '${source}' has no expectation file "
            "'${_expectation}'. Every negative test must state the diagnostic "
            "it expects, otherwise 'it fails to compile' is not evidence.")
    endif()

    add_test(NAME compile_fail.${_name}
        COMMAND "${CMAKE_COMMAND}"
            "-DMETA_AUTH_NEGATIVE_SOURCE=${source}"
            "-DMETA_AUTH_NEGATIVE_EXPECTATION=${_expectation}"
            "-DMETA_AUTH_NEGATIVE_COMPILER=${CMAKE_CXX_COMPILER}"
            "-DMETA_AUTH_NEGATIVE_STANDARD=${CMAKE_CXX_STANDARD}"
            "-DMETA_AUTH_NEGATIVE_INCLUDE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/../include"
            "-DMETA_AUTH_NEGATIVE_CONTRACTS=${META_AUTH_COMPILER_HAS_CONTRACTS}"
            "-DMETA_AUTH_NEGATIVE_REFLECTION=${META_AUTH_COMPILER_HAS_REFLECTION}"
            -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/MetaAuthCompileFail.cmake")

    set_tests_properties(compile_fail.${_name} PROPERTIES
        LABELS "compile_fail"
        TIMEOUT "${ARG_TIMEOUT}")
endfunction()
