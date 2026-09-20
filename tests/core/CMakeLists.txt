# ---------------------------------------------------------------------------
# Core layer tests: the vocabulary every other layer speaks.
# ---------------------------------------------------------------------------
meta_auth_add_test(meta_auth_core_error
    GROUP unit
    SOURCES test_error.cpp
    TIMEOUT 60)

meta_auth_add_test(meta_auth_core_contract
    GROUP unit
    SOURCES test_contract.cpp
    TIMEOUT 60)

# ---------------------------------------------------------------------------
# The fail-stop probe.
#
# It has its own `main` (it needs argv), so it is a plain executable rather
# than a harness target.
# ---------------------------------------------------------------------------
add_executable(meta_auth_contract_probe contract_probe.cpp)
target_link_libraries(meta_auth_contract_probe PRIVATE meta_auth::meta_auth meta_auth_sanitizers)
set_target_properties(meta_auth_contract_probe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# The classification of a violated contract depends on the dialect, and the
# difference is real rather than cosmetic: with contract support the compiler
# knows a `pre` from a `post`, while the portable path can only report the
# statement form `contract_assert`, which is an assertion. The *condition* and
# the abort are identical in both, and both are asserted.
if(META_AUTH_COMPILER_HAS_CONTRACTS)
    set(_pre_kind "precondition")
    set(_post_kind "postcondition")
else()
    set(_pre_kind "assertion")
    set(_post_kind "assertion")
endif()

foreach(_mode pre post assert unreachable)
    meta_auth_add_failure_test(contract.${_mode}_violation_stops_the_process
        PROGRAM "$<TARGET_FILE:meta_auth_contract_probe>"
        ARGS ${_mode}
        RESULT_REGEX "Subprocess aborted|^134$"
        OUTPUT_REGEX "meta-auth: contract violation"
        LABELS "core"
        TIMEOUT 30)
endforeach()

# The condition and the classification are asserted separately, so that a
# report which lost its detail cannot pass on the strength of its headline.
meta_auth_add_failure_test(contract.precondition_reports_its_condition
    PROGRAM "$<TARGET_FILE:meta_auth_contract_probe>"
    ARGS pre
    RESULT_REGEX "Subprocess aborted|^134$"
    OUTPUT_REGEX "denominator != 0.*${_pre_kind}"
    LABELS "core"
    TIMEOUT 30)

meta_auth_add_failure_test(contract.postcondition_reports_its_condition
    PROGRAM "$<TARGET_FILE:meta_auth_contract_probe>"
    ARGS post
    RESULT_REGEX "Subprocess aborted|^134$"
    OUTPUT_REGEX "result >= 0\\.0.*${_post_kind}"
    LABELS "core"
    TIMEOUT 30)

# The observer must have been called before the process stopped: that is the
# whole point of "fail stop *and* leave a record".
meta_auth_add_failure_test(contract.observer_runs_before_termination
    PROGRAM "$<TARGET_FILE:meta_auth_contract_probe>"
    ARGS observer
    RESULT_REGEX "Subprocess aborted|^134$"
    OUTPUT_REGEX "observer: call=1 kind=assertion sequence=1"
    LABELS "core"
    TIMEOUT 30)

# An unknown mode is a usage error, not a crash: the probe must be usable by
# hand without producing a core dump.
meta_auth_add_failure_test(contract.probe_rejects_an_unknown_mode
    PROGRAM "$<TARGET_FILE:meta_auth_contract_probe>"
    ARGS no_such_mode
    RESULT_REGEX "^2$"
    OUTPUT_REGEX "unknown mode"
    LABELS "core"
    TIMEOUT 30)
