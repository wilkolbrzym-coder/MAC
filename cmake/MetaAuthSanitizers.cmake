# ---------------------------------------------------------------------------
# MetaAuthSanitizers -- runtime instrumentation presets.
#
# The sanitizers are not decoration here. The library makes strong claims
# about memory safety and about data races on the audit trail; the only way
# those claims mean anything is if a CI configuration actually runs the suite
# under ASan+UBSan and under TSan.
#
# Sanitizers are applied through a private interface target,
# `meta_auth_sanitizers`, which the test, benchmark and example targets link.
# They are deliberately NOT INTERFACE properties of `meta_auth` itself: a
# consumer must not inherit instrumentation from a header-only dependency.
# ---------------------------------------------------------------------------
# A consumer that adds this project with `add_subdirectory` may already have a
# target by this name; creating a second one is a configure error in CMake, so
# the guard turns a collision into a reused target.
if(NOT TARGET meta_auth_sanitizers)
    add_library(meta_auth_sanitizers INTERFACE)
endif()

# Every sanitizer combination this project supports, mapped to its flags.
# ASan and TSan are mutually exclusive by construction; asking for both is a
# configuration error and is rejected rather than silently resolved.
set(META_AUTH_SANITIZER_ADDRESS
    -fsanitize=address
    -fsanitize-address-use-after-scope
    -fno-omit-frame-pointer
    -fno-common)

set(META_AUTH_SANITIZER_UNDEFINED
    -fsanitize=undefined
    -fsanitize=float-divide-by-zero
    -fsanitize=integer-divide-by-zero
    -fsanitize=null
    -fsanitize=return
    -fsanitize=shift
    -fsanitize=signed-integer-overflow
    -fsanitize=vla-bound
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer)

set(META_AUTH_SANITIZER_THREAD
    -fsanitize=thread
    -fno-omit-frame-pointer)

set(META_AUTH_SANITIZER_LEAK
    -fsanitize=leak
    -fno-omit-frame-pointer)

set(_meta_auth_sanitizer_flags "")

if(META_AUTH_SANITIZER STREQUAL "none")
    # Nothing to do: the default configuration is an uninstrumented build.
elseif(META_AUTH_SANITIZER STREQUAL "address")
    list(APPEND _meta_auth_sanitizer_flags ${META_AUTH_SANITIZER_ADDRESS})
elseif(META_AUTH_SANITIZER STREQUAL "undefined")
    list(APPEND _meta_auth_sanitizer_flags ${META_AUTH_SANITIZER_UNDEFINED})
elseif(META_AUTH_SANITIZER STREQUAL "address+undefined")
    list(APPEND _meta_auth_sanitizer_flags
        ${META_AUTH_SANITIZER_ADDRESS} ${META_AUTH_SANITIZER_UNDEFINED})
elseif(META_AUTH_SANITIZER STREQUAL "thread")
    list(APPEND _meta_auth_sanitizer_flags ${META_AUTH_SANITIZER_THREAD})
elseif(META_AUTH_SANITIZER STREQUAL "leak")
    list(APPEND _meta_auth_sanitizer_flags ${META_AUTH_SANITIZER_LEAK})
else()
    message(FATAL_ERROR
        "META_AUTH_SANITIZER='${META_AUTH_SANITIZER}' is not a supported value. "
        "Expected one of: none, address, thread, undefined, address+undefined, leak.")
endif()

# ---------------------------------------------------------------------------
# Availability
#
# Compilers do not implement the same set, and the failure has to be visible.
# A configure that quietly drops the instrumentation produces a green CI job
# that proves nothing about memory safety -- which is the specific claim these
# presets exist to support -- so an unsupported request warns loudly rather
# than being silently ignored.
#
# Rewriting the flag list per compiler is also what keeps the presets usable:
# `-fsanitize=thread` handed to cl.exe is an unknown option, and cl.exe's
# response to an unknown option is a warning followed by a build that does not
# do what it says.
# ---------------------------------------------------------------------------
if(MSVC)
    if(META_AUTH_SANITIZER STREQUAL "address")
        set(_meta_auth_sanitizer_flags /fsanitize=address)
    elseif(NOT META_AUTH_SANITIZER STREQUAL "none")
        message(WARNING
            "META_AUTH_SANITIZER='${META_AUTH_SANITIZER}' is not implemented by MSVC, which "
            "ships AddressSanitizer only. Building uninstrumented. Use the 'address' preset if "
            "you want memory-safety instrumentation, and do not read a run on this platform as "
            "evidence about the thread-safety or undefined-behaviour claims.")
        set(_meta_auth_sanitizer_flags "")
    endif()
elseif(APPLE AND META_AUTH_SANITIZER STREQUAL "leak")
    message(WARNING
        "The leak sanitizer is not available on macOS: Apple's clang does not ship "
        "LeakSanitizer. Building uninstrumented. AddressSanitizer's leak checker does work "
        "there, so the 'address' preset is the one to use.")
    set(_meta_auth_sanitizer_flags "")
endif()

if(_meta_auth_sanitizer_flags)
    target_compile_options(meta_auth_sanitizers INTERFACE ${_meta_auth_sanitizer_flags})
    target_link_options(meta_auth_sanitizers INTERFACE ${_meta_auth_sanitizer_flags})

    # UBSan's default runtime prints a diagnostic and continues, which turns a
    # detected defect into a passing test. The suite must fail instead. MSVC
    # has no UBSan, and the flag is not an option there.
    if(META_AUTH_SANITIZER MATCHES "undefined" AND NOT MSVC)
        target_compile_options(meta_auth_sanitizers INTERFACE -fno-sanitize-recover=all)
    endif()

    # Leak detection is only meaningful when the process is allowed to report
    # at exit; ASan's leak checker is off in some distributions by default.
    if(META_AUTH_SANITIZER MATCHES "address|leak")
        target_compile_definitions(meta_auth_sanitizers INTERFACE
            META_AUTH_SANITIZER_ACTIVE=1)
    endif()
endif()

# Coverage is orthogonal to sanitizers and can be combined with them, but not
# with optimisation: `-O0` keeps the line tables honest.
if(META_AUTH_ENABLE_COVERAGE)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        message(WARNING "META_AUTH_ENABLE_COVERAGE is only implemented for GCC; ignoring.")
    else()
        target_compile_options(meta_auth_sanitizers INTERFACE
            --coverage -fprofile-abs-path -O0 -fno-inline)
        target_link_options(meta_auth_sanitizers INTERFACE --coverage)
    endif()
endif()
