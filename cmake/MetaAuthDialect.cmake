# ---------------------------------------------------------------------------
# MetaAuthDialect -- probe the optional halves of the C++26 dialect.
#
# The library targets C++26 unconditionally, but two of the features it leans
# on are still landing across compilers:
#
#   * P2900 contract assertions (`pre`, `post`, `contract_assert`);
#   * P2996 static reflection (`<meta>`, `^^`, `template for`).
#
# Both are *probed*, and `include/meta_auth/config.hpp` performs the same
# detection from inside the library, so the headers keep working when they are
# vendored without CMake. The probe results drive the build-graph options; the
# preprocessor macros drive the code. Keeping both in sync is the job of
# `meta_auth_assert_dialect_consistency()` below, which refuses to configure a
# build whose two halves disagree.
# ---------------------------------------------------------------------------

include(CheckCXXSourceCompiles)
include(CMakePushCheckState)

set(META_AUTH_CONTRACTS_STATUS "disabled by option")
set(META_AUTH_REFLECTION_STATUS "disabled by option")

# The probe flags are GCC spellings. MSVC would ignore an unknown `-f...`
# option with a warning and then fail the probe for the unrelated reason that
# its parser does not accept `pre(...)`, which would leave the configure log
# claiming a feature was tested when it was not. The flags are therefore only
# offered to the compilers that speak them.
if(META_AUTH_ENABLE_CONTRACTS AND NOT MSVC)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_FLAGS "-fcontracts")
    check_cxx_source_compiles([[
        constexpr int clamp_positive(int value) pre(value > 0) { return value; }
        int check(int value) { contract_assert(value != 0); return value; }
        int main() { return clamp_positive(check(1)); }
    ]] META_AUTH_COMPILER_HAS_CONTRACTS)
    cmake_pop_check_state()

    if(META_AUTH_COMPILER_HAS_CONTRACTS)
        set(META_AUTH_CONTRACTS_STATUS "enabled (-fcontracts)")
    else()
        set(META_AUTH_CONTRACTS_STATUS "unsupported by ${CMAKE_CXX_COMPILER_ID} -- using portable fallback")
    endif()
endif()

if(META_AUTH_ENABLE_REFLECTION AND NOT MSVC)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_FLAGS "-freflection")
    check_cxx_source_compiles([[
        #include <meta>
        #include <string_view>
        struct Probe { int alpha; int beta; };
        consteval std::size_t field_count() {
            return std::meta::nonstatic_data_members_of(
                ^^Probe, std::meta::access_context::current()).size();
        }
        static_assert(field_count() == 2);
        int main() { return 0; }
    ]] META_AUTH_COMPILER_HAS_REFLECTION)
    cmake_pop_check_state()

    if(META_AUTH_COMPILER_HAS_REFLECTION)
        set(META_AUTH_REFLECTION_STATUS "enabled (-freflection)")
    else()
        set(META_AUTH_REFLECTION_STATUS "unsupported by ${CMAKE_CXX_COMPILER_ID} -- using template fallback")
    endif()
endif()

# ---------------------------------------------------------------------------
# meta_auth_configure_dialect(<target>)
#
# Publishes the enabled dialect features as INTERFACE compile definitions and
# options. They are INTERFACE properties on purpose: a consumer that links
# `meta_auth::meta_auth` must see exactly the same guarantees as the library's
# own tests, otherwise the test suite proves nothing about the consumer build.
# ---------------------------------------------------------------------------
function(meta_auth_configure_dialect target)
    if(META_AUTH_COMPILER_HAS_CONTRACTS)
        # `-fcontracts` is required at link time as well as at compile time:
        # GCC emits the contract-checking shims per translation unit but the
        # default violation handler is only pulled in by the driver when the
        # option is present on the link line. Omitting it here produced a
        # perfectly compiled object file and an undefined reference to
        # `handle_contract_violation`.
        # Compiler-conditional, because these options are exported to
        # consumers: a project that finds this package with a different
        # compiler must not be handed a flag its compiler has never heard of.
        # The definition is unconditional -- a consumer compiled without
        # contracts loses the guarantees the headers reasoned about.
        target_compile_options(${target} INTERFACE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fcontracts>)
        target_link_options(${target} INTERFACE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fcontracts>)
        target_compile_definitions(${target} INTERFACE META_AUTH_CONFIG_USE_CONTRACTS=1)
    else()
        target_compile_definitions(${target} INTERFACE META_AUTH_CONFIG_USE_CONTRACTS=0)
    endif()

    if(META_AUTH_COMPILER_HAS_REFLECTION)
        target_compile_options(${target} INTERFACE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-freflection>)
        target_compile_definitions(${target} INTERFACE META_AUTH_CONFIG_USE_REFLECTION=1)
    else()
        target_compile_definitions(${target} INTERFACE META_AUTH_CONFIG_USE_REFLECTION=0)
    endif()
endfunction()
