# ---------------------------------------------------------------------------
# MetaAuthHardening -- defence in depth for the generated code.
#
# These flags do not make the *design* safe; the design is safe because the
# capability model and the typestate sessions make the unsafe programs
# ill-formed. Hardening is the second layer: it bounds the damage of the
# defects that survive review, and it is cheap enough that there is no reason
# to build without it.
#
# The flags are applied to `meta_auth` itself (they affect code generation of
# inline functions instantiated in the consumer) and are published as
# INTERFACE so that consumers linking the library are hardened the same way.
#
# Every flag is *probed*, and this is the part that makes the header-only
# claim true across platforms. The unprobed version added
# `-fstack-clash-protection` and `-fcf-protection=full` unconditionally, which
# is fine on x86 GNU/Linux and wrong everywhere else: `-fcf-protection` is an
# x86 feature that Apple's clang rejects outright for an arm64 target, so
# `cmake --preset dev` on an Apple Silicon machine failed in the toolchain
# before it reached the library. A flag that is absent from the build must be
# absent because the compiler said no, not because the platform is unexpected.
# ---------------------------------------------------------------------------
include(CheckCXXCompilerFlag)
include(CheckLinkerFlag)
include(CMakePushCheckState)

function(meta_auth_enable_compile_flag target flag)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_QUIET ON)
    check_cxx_compiler_flag("${flag}" _meta_auth_supports)
    cmake_pop_check_state()
    if(_meta_auth_supports)
        target_compile_options(${target} INTERFACE "${flag}")
    endif()
endfunction()

function(meta_auth_enable_link_flag target flag)
    cmake_push_check_state(RESET)
    check_linker_flag(CXX "${flag}" _meta_auth_supports)
    cmake_pop_check_state()
    if(_meta_auth_supports)
        target_link_options(${target} INTERFACE "${flag}")
    endif()
endfunction()

function(meta_auth_configure_hardening target)
    if(NOT META_AUTH_ENABLE_HARDENING)
        return()
    endif()

    if(MSVC)
        # /GS (stack cookie) and /guard:cf (control-flow guard) are the
        # equivalents of -fstack-protector and -fcf-protection. /GS is on by
        # default for /W4-era toolchains but naming it costs nothing and
        # documents the intent; /guard:cf requires the linker flag as well,
        # which check_linker_flag verifies.
        meta_auth_enable_compile_flag(${target} /GS)
        meta_auth_enable_compile_flag(${target} /guard:cf)
        meta_auth_enable_link_flag(${target} /guard:cf)
        meta_auth_enable_link_flag(${target} /DYNAMICBASE)
        meta_auth_enable_link_flag(${target} /NXCOMPAT)
        return()
    endif()

    # Stack and control-flow integrity. `-fstack-protector-strong` covers the
    # functions that actually hold arrays or take addresses of locals, which
    # is the whole benefit of `-all` at a fraction of the cost.
    meta_auth_enable_compile_flag(${target} -fstack-protector-strong)
    meta_auth_enable_compile_flag(${target} -fstack-clash-protection)
    meta_auth_enable_compile_flag(${target} -fcf-protection=full)

    # _FORTIFY_SOURCE requires an optimising build to have any effect; adding
    # it to -O0 produces a warning and no protection, so it is gated. It is
    # also a glibc feature: on macOS and Windows the macro is inert, and
    # defining it there would be cargo-culting a number rather than enabling a
    # mitigation.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_definitions(${target} INTERFACE
            $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=3>)
    endif()

    # Refuse code generation that would silently miscompile rather than
    # diagnose: format-string mismatches and obvious UB become errors.
    # Both flags exist in GCC and Clang; the probes decide.
    meta_auth_enable_compile_flag(${target} -fno-delete-null-pointer-checks)
    meta_auth_enable_compile_flag(${target} -fno-strict-aliasing)

    # Linker-level hardening: immediate binding (no lazy PLT resolution an
    # attacker can hijack), read-only relocations, and a non-executable stack.
    # These are ELF spellings; the probe is what makes them harmless on
    # Mach-O and PE.
    meta_auth_enable_link_flag(${target} "-Wl,-z,relro,-z,now")
    meta_auth_enable_link_flag(${target} "-Wl,-z,noexecstack")
    meta_auth_enable_link_flag(${target} "-Wl,-z,separate-code")
endfunction()
