# ===========================================================================
#  meta-auth-core -- Compile-Time User/Device Authentication
#                    and Object-Capability Sandbox
#
#  Top-level build description.
#
#  Design rules honoured by this file:
#    1. The library is header-only and has no third-party dependencies, so a
#       consumer can vendor `include/` and be done. CMake is a convenience,
#       never a requirement.
#    2. The headers are the single source of truth for the project version and
#       for feature detection; the build system validates them instead of
#       duplicating them (see cmake/MetaAuthVersion.cmake).
#    3. Optional language features (contracts, reflection) are probed, not
#       assumed. Everything that is not probed must still build and pass its
#       tests -- that property is what makes the portable CI preset meaningful.
# ===========================================================================
cmake_minimum_required(VERSION 3.28)

project(meta-auth-core
    VERSION 0.1.0
    DESCRIPTION "Compile-time user/device authentication and object-capability sandbox"
    HOMEPAGE_URL "https://github.com/wilkolbrzym-coder/MAC"
    LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# The C++26 dialect is a hard requirement: the library is built on contracts,
# deleted functions with diagnostics, pack indexing and reflection. The
# *optional* members of that set are detected below and degrade gracefully.
#
# MSVC is spelled separately, and the reason is CMake's rather than the
# compiler's. CMake has no CXX26 mapping for MSVC -- its module stops at CXX23,
# which MSVC spells `/std:c++latest` -- so `CMAKE_CXX_STANDARD 26` makes CMake
# refuse to generate: every `try_compile` in this build died with "requires the
# language dialect CXX26 ... CMake does not know the flags to enable it", the
# hardening probe being the first one reached. MSVC has the mode; the build
# system has no name for it. The mode is requested the way the compiler spells
# it, on the target below, so that the probes configure at all and a consumer of
# the package compiles in the mode the library was built in. `/Zc:__cplusplus`
# is what keeps `__cplusplus` honest under it, which is why that flag is in the
# MSVC warning set.
if(MSVC)
    set(META_AUTH_CXX_MODE /std:c++latest)
else()
    set(CMAKE_CXX_STANDARD 26)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(META_AUTH_IS_TOP_LEVEL ON)
else()
    set(META_AUTH_IS_TOP_LEVEL OFF)
endif()

include(MetaAuthOptions)
include(MetaAuthDialect)
include(MetaAuthWarnings)
include(MetaAuthSanitizers)
include(MetaAuthHardening)
include(MetaAuthVersion)

# ---------------------------------------------------------------------------
#  Core library
#
#  `meta_auth` is an INTERFACE target: the entire implementation lives in
#  headers. The target still carries compile options because several of them
#  (contracts, reflection) change the *dialect*, not just the diagnostics, and
#  a consumer compiled without them would silently lose the guarantees.
# ---------------------------------------------------------------------------
add_library(meta_auth INTERFACE)
add_library(meta_auth::meta_auth ALIAS meta_auth)

target_include_directories(meta_auth INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

# The dialect travels with the target on MSVC and as a compile feature
# everywhere else, which is the same requirement said in the two ways the two
# build systems can hear it. It is published as an INTERFACE requirement, not
# as a build-only one: a consumer compiled in another mode would lose the
# guarantees this library sells.
if(MSVC)
    target_compile_options(meta_auth INTERFACE "${META_AUTH_CXX_MODE}")
else()
    target_compile_features(meta_auth INTERFACE cxx_std_26)
endif()

meta_auth_configure_dialect(meta_auth)
meta_auth_configure_warnings(meta_auth)
meta_auth_configure_hardening(meta_auth)

# ---------------------------------------------------------------------------
#  Optional components
# ---------------------------------------------------------------------------
if(META_AUTH_BUILD_TESTS)
    # The concurrency tests construct std::thread, and `Threads::Threads` is
    # what supplies the platform's threading library where it is separate from
    # the C runtime. On this machine glibc has absorbed libpthread, so the
    # omission was invisible; on macOS and Windows the target is a no-op, and
    # on older Linux distributions it is the difference between a link error
    # and a build. Required rather than optional: a build that cannot link is
    # not a supported build.
    find_package(Threads REQUIRED)
    enable_testing()
    add_subdirectory(tests)
endif()

if(META_AUTH_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

if(META_AUTH_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ---------------------------------------------------------------------------
#  Installation and package export
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS meta_auth EXPORT meta-auth-core-targets)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    COMPONENT Development)

install(EXPORT meta-auth-core-targets
    FILE meta-auth-core-targets.cmake
    NAMESPACE meta_auth::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/meta-auth-core"
    COMPONENT Development)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/meta-auth-core-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/meta-auth-core-config.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/meta-auth-core")

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/meta-auth-core-config-version.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
    ARCH_INDEPENDENT)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/meta-auth-core-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/meta-auth-core-config-version.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/meta-auth-core"
    COMPONENT Development)

# ---------------------------------------------------------------------------
#  Configure-time report
# ---------------------------------------------------------------------------
if(META_AUTH_IS_TOP_LEVEL)
    message(STATUS "")
    message(STATUS "meta-auth-core ${PROJECT_VERSION} -- build configuration")
    message(STATUS "  compiler .............. ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
    message(STATUS "  dialect ............... ${CMAKE_CXX_STANDARD} (extensions: ${CMAKE_CXX_EXTENSIONS})")
    message(STATUS "  build type ............ ${CMAKE_BUILD_TYPE}")
    message(STATUS "  contracts (P2900) ..... ${META_AUTH_CONTRACTS_STATUS}")
    message(STATUS "  reflection (P2996) .... ${META_AUTH_REFLECTION_STATUS}")
    message(STATUS "  warnings as errors .... ${META_AUTH_WARNINGS_AS_ERRORS}")
    message(STATUS "  sanitizers ............ ${META_AUTH_SANITIZER}")
    message(STATUS "  hardening ............. ${META_AUTH_ENABLE_HARDENING}")
    message(STATUS "  tests ................. ${META_AUTH_BUILD_TESTS}")
    message(STATUS "  benchmarks ............ ${META_AUTH_BUILD_BENCHMARKS}")
    message(STATUS "  examples .............. ${META_AUTH_BUILD_EXAMPLES}")
    message(STATUS "")
endif()
