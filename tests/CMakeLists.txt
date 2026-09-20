# ---------------------------------------------------------------------------
# Test suite.
#
# The layout mirrors the library's layers, and each directory is a *group*
# with its own CTest label, so a developer can run the layer they touched:
#
#   ctest -L dialect       what the compiler configuration guarantees
#   ctest -L unit          functional behaviour of one component
#   ctest -L property      laws that must hold for every input
#   ctest -L concurrency   claims about shared mutable state
#   ctest -L compile_fail  programs that must remain ill-formed
#   ctest -L integration   the layers wired together
#   ctest -L fail_stop     processes that must terminate in a documented way
# ---------------------------------------------------------------------------
include(MetaAuthTestHelpers)

# The runner is compiled into every test binary, so a test source file
# contains test cases and nothing else.
set(META_AUTH_TEST_FRAMEWORK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/framework")
set(META_AUTH_TEST_FRAMEWORK_MAIN "${META_AUTH_TEST_FRAMEWORK_DIR}/main.cpp")

# The harness is registered first: if it cannot report a failure, no result
# produced by the rest of the suite means anything.
add_subdirectory(framework)

# The dialect group comes next, for the same reason one level up: if the
# compiler configuration is not what the suite assumes, every later result is
# uninterpretable.
add_subdirectory(dialect)

add_subdirectory(core)

add_subdirectory(crypto)

add_subdirectory(capability)

add_subdirectory(identity)

add_subdirectory(auth)

add_subdirectory(sandbox)
