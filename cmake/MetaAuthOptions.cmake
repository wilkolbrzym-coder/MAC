# ---------------------------------------------------------------------------
# MetaAuthOptions -- user-facing build switches.
#
# Every option is documented at the point of definition: a switch that a
# reviewer cannot explain without reading the implementation is a switch that
# should not exist.
# ---------------------------------------------------------------------------

include(CMakeDependentOption)

# Default the component switches to ON only when this project is the root of
# the build: a consumer that adds meta-auth-core as a subdirectory must not
# inherit our test and benchmark targets.
option(META_AUTH_BUILD_TESTS
    "Build the test suite (unit, property, compile-failure, concurrency)"
    ${META_AUTH_IS_TOP_LEVEL})

option(META_AUTH_BUILD_BENCHMARKS
    "Build the micro-benchmark suite"
    OFF)

option(META_AUTH_BUILD_EXAMPLES
    "Build the runnable examples"
    ${META_AUTH_IS_TOP_LEVEL})

option(META_AUTH_ENABLE_CONTRACTS
    "Use C++26 contract assertions (P2900) when the compiler implements them"
    ON)

option(META_AUTH_ENABLE_REFLECTION
    "Use C++26 static reflection (P2996) when the compiler implements it"
    ON)

option(META_AUTH_WARNINGS_AS_ERRORS
    "Treat every diagnostic from the warning set as an error"
    ON)

option(META_AUTH_ENABLE_HARDENING
    "Enable the defensive code-generation and linker flags"
    ON)

set(META_AUTH_SANITIZER "none"
    CACHE STRING "Instrumentation to build with: none, address, thread, undefined, address+undefined, leak")
set_property(CACHE META_AUTH_SANITIZER PROPERTY STRINGS
    none address thread undefined address+undefined leak)

option(META_AUTH_ENABLE_COVERAGE
    "Instrument the test binaries for coverage collection (GCC only)"
    OFF)

# The build type is part of the contract of a security library: an unset build
# type means `-O0` and no `NDEBUG`, which is a defensible default for
# development but must never be what a release artifact is built from.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release RelWithDebInfo MinSizeRel)
endif()
