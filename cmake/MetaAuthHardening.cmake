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
# ---------------------------------------------------------------------------
function(meta_auth_configure_hardening target)
    if(NOT META_AUTH_ENABLE_HARDENING)
        return()
    endif()

    # Stack and control-flow integrity. `-fstack-protector-strong` covers the
    # functions that actually hold arrays or take addresses of locals, which
    # is the whole benefit of `-all` at a fraction of the cost.
    target_compile_options(${target} INTERFACE
        -fstack-protector-strong
        -fstack-clash-protection
        -fcf-protection=full)

    # _FORTIFY_SOURCE requires an optimising build to have any effect; adding
    # it to -O0 produces a warning and no protection, so it is gated.
    target_compile_definitions(${target} INTERFACE
        $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=3>)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        # Refuse code generation that would silently miscompile rather than
        # diagnose: format-string mismatches and obvious UB become errors.
        target_compile_options(${target} INTERFACE
            -fno-delete-null-pointer-checks
            -fno-strict-aliasing)
    endif()

    # Linker-level hardening: immediate binding (no lazy PLT resolution an
    # attacker can hijack), read-only relocations, and a non-executable stack.
    include(CheckLinkerFlag)
    check_linker_flag(CXX "-Wl,-z,relro,-z,now" META_AUTH_LINKER_HAS_RELRO_NOW)
    check_linker_flag(CXX "-Wl,-z,noexecstack" META_AUTH_LINKER_HAS_NOEXECSTACK)
    check_linker_flag(CXX "-Wl,-z,separate-code" META_AUTH_LINKER_HAS_SEPARATE_CODE)

    if(META_AUTH_LINKER_HAS_RELRO_NOW)
        target_link_options(${target} INTERFACE "-Wl,-z,relro,-z,now")
    endif()
    if(META_AUTH_LINKER_HAS_NOEXECSTACK)
        target_link_options(${target} INTERFACE "-Wl,-z,noexecstack")
    endif()
    if(META_AUTH_LINKER_HAS_SEPARATE_CODE)
        target_link_options(${target} INTERFACE "-Wl,-z,separate-code")
    endif()
endfunction()
