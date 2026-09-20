# ---------------------------------------------------------------------------
# Runnable examples.
#
# The demo doubles as an end-to-end test: it asserts every step and returns a
# non-zero exit code when one of them misbehaves, so it is registered with
# CTest as well as being runnable by hand.
# ---------------------------------------------------------------------------
add_executable(meta_auth_demo meta_auth_demo.cpp)
target_link_libraries(meta_auth_demo PRIVATE meta_auth::meta_auth meta_auth_sanitizers)
set_target_properties(meta_auth_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if(META_AUTH_BUILD_TESTS)
    add_test(NAME demo.walks_the_whole_model COMMAND meta_auth_demo)
    set_tests_properties(demo.walks_the_whole_model PROPERTIES
        LABELS "integration"
        TIMEOUT 60)
endif()
