// ===========================================================================
//  meta-auth-core -- compile-time configuration
//
//  This header is the single point where the library decides which optional
//  parts of the C++26 dialect it can rely on. It is deliberately free of any
//  build-system knowledge: `__has_include`, feature-test macros and the two
//  override macros below are the entire input, so vendoring `include/` into a
//  foreign build produces exactly the same configuration as a CMake build.
//
//  Override macros (normally set by the build system, see
//  cmake/MetaAuthDialect.cmake):
//
//    META_AUTH_CONFIG_USE_CONTRACTS  0/1  force contract assertions off/on
//    META_AUTH_CONFIG_USE_REFLECTION 0/1  force reflection off/on
//
//  Why the overrides exist at all: on GCC 16 the macro `__cpp_contracts` is
//  defined in C++26 mode even when `-fcontracts` is *not* passed, but the
//  program then fails to link. The language macro therefore describes the
//  dialect, not the build. The build system probes the build and overrides the
//  guess; the defaults below are the best a standalone translation unit can
//  do, and they fail loudly (link-time) rather than silently.
// ===========================================================================
#ifndef META_AUTH_CONFIG_HPP
#define META_AUTH_CONFIG_HPP

// ---------------------------------------------------------------------------
// Dialect floor
//
// The post-C++23 value of __cplusplus is how compilers spell "C++26" today;
// the published standard value is not yet fixed, so the check is expressed as
// "strictly newer than C++23" rather than against a magic number.
//
// MSVC reports 199711L from __cplusplus unless /Zc:__cplusplus is passed, and
// the flag is not on by default: the compiler has been able to report the
// truth since VS2017 15.7 and still does not, because changing it would break
// code that sniffs the macro. The real level is in _MSVC_LANG, so that is what
// the check uses when it is defined. Without this, every MSVC build fails the
// #error below no matter how the command line is spelled -- which is a
// confusing way to be told "this library needs C++26".
// ---------------------------------------------------------------------------
#if defined(_MSVC_LANG)
#define META_AUTH_DIALECT_LEVEL _MSVC_LANG
#else
#define META_AUTH_DIALECT_LEVEL __cplusplus
#endif

#if !defined(__cplusplus)
#error "meta-auth-core requires a C++ compiler; __cplusplus is not defined."
#elif META_AUTH_DIALECT_LEVEL <= 202302L
#error "meta-auth-core requires C++26. Compile with -std=c++26 (GCC 15+, Clang 21+) or /std:c++latest (MSVC 19.4x+). This library is built on contract assertions, static reflection, deleted functions with diagnostics and pack indexing; a pre-C++26 dialect cannot express its core invariants."
#endif

// ---------------------------------------------------------------------------
// Library feature-test macros
//
// <version> is the standard-only, implementation-provided list of feature-test
// macros. Including it first is what makes the checks below depend on the
// standard library's actual capabilities rather than on a guess.
// ---------------------------------------------------------------------------
#if __has_include(<version>)
#include <version>
#elif __has_include(<expected>)
// Fallback for implementations without <version>: <expected> is the one C++23
// header this library cannot do without, so it is also the best available
// proxy for "the library features are present".
#include <expected>
#endif

// Contract assertions were standardised with a language feature-test macro.
// GCC reports 202502L, the value assigned by P2900R14.
#if !defined(META_AUTH_CONFIG_USE_CONTRACTS)
#if defined(__cpp_contracts) && __cpp_contracts >= 202502L
#define META_AUTH_CONFIG_USE_CONTRACTS 1
#else
#define META_AUTH_CONFIG_USE_CONTRACTS 0
#endif
#endif

// Static reflection. `__cpp_lib_reflection` is published by <version> in
// libstdc++ when the compiler is invoked with -freflection; `__cpp_reflection`
// is the language-side spelling used by other implementations. Either one
// being present means the <meta> facilities this library uses are available.
#if !defined(META_AUTH_CONFIG_USE_REFLECTION)
#if defined(__cpp_reflection) || defined(__cpp_lib_reflection)
#define META_AUTH_CONFIG_USE_REFLECTION 1
#else
#define META_AUTH_CONFIG_USE_REFLECTION 0
#endif
#endif

// ---------------------------------------------------------------------------
// Public feature switches
// ---------------------------------------------------------------------------
#define META_AUTH_HAS_CONTRACTS (META_AUTH_CONFIG_USE_CONTRACTS != 0)
#define META_AUTH_HAS_REFLECTION (META_AUTH_CONFIG_USE_REFLECTION != 0)

// P2662 pack indexing: `Args...[0]`. Used to give the policy engine a
// positional view over a parameter pack without a helper metafunction.
#if defined(__cpp_pack_indexing) && __cpp_pack_indexing >= 202311L
#define META_AUTH_HAS_PACK_INDEXING 1
#else
#define META_AUTH_HAS_PACK_INDEXING 0
#endif

// P2573 deleted functions with a diagnostic message: `= delete("reason")`.
// This is what turns "you called an operation that does not exist in this
// session state" into a sentence the developer can act on.
//
// Unlike contracts and reflection this one is *required*, not optional. The
// library's rejections are its user interface -- a session that cannot act, a
// capability that cannot be copied, a proof that cannot be fetched from
// nowhere -- and without P2573 every one of them degrades to "no matching
// function" and a page of candidate notes. The macro was defined and never
// consulted, so a compiler without the feature produced a wall of syntax
// errors instead of this sentence.
#if defined(__cpp_deleted_function) && __cpp_deleted_function >= 202403L
#define META_AUTH_HAS_DELETED_WITH_MESSAGE 1
#else
#define META_AUTH_HAS_DELETED_WITH_MESSAGE 0
#endif

#if META_AUTH_HAS_DELETED_WITH_MESSAGE == 0
#error "meta-auth-core requires P2573 deleted functions with a diagnostic message (__cpp_deleted_function >= 202403L). GCC 15+, Clang 19+ and MSVC 19.40+ implement it. The library's diagnostics are built on it: every operation that a state, a policy or a capability forbids is reported by a sentence saying which one."
#endif

// C++26 fixed-capacity vector. The capability tables and the audit ring are
// sized at compile time, so an allocation-free container is the natural fit.
#if __has_include(<inplace_vector>) && defined(__cpp_lib_inplace_vector)
#define META_AUTH_HAS_INPLACE_VECTOR 1
#else
#define META_AUTH_HAS_INPLACE_VECTOR 0
#endif

// C++23 vocabulary this library depends on unconditionally.
#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
#define META_AUTH_HAS_EXPECTED 1
#else
#define META_AUTH_HAS_EXPECTED 0
#endif

#if META_AUTH_HAS_EXPECTED == 0
#error "meta-auth-core requires std::expected (C++23). Every fallible operation in the library returns result<T> = std::expected<T, auth_error>; the error channel is part of the API contract and is not optional."
#endif

// ---------------------------------------------------------------------------
// Diagnostics helper used by the tests and by the configure-time report.
// ---------------------------------------------------------------------------
#define META_AUTH_STRINGIFY_IMPL(x) #x
#define META_AUTH_STRINGIFY(x) META_AUTH_STRINGIFY_IMPL(x)

namespace meta_auth::config {

/// True when the build asserts C++26 contracts (P2900) at every boundary.
inline constexpr bool contracts_enabled = META_AUTH_HAS_CONTRACTS;

/// True when the build can introspect types at compile time (P2996).
inline constexpr bool reflection_enabled = META_AUTH_HAS_REFLECTION;

/// Human-readable summary of the dialect this translation unit was built with.
/// Used by the CLI's `--diagnostics` output and by the test suite, so a
/// surprising test result can always be traced back to how it was compiled.
[[nodiscard]] constexpr auto dialect_summary() noexcept -> const char* {
    return "C++26"
           " contracts=" META_AUTH_STRINGIFY(META_AUTH_CONFIG_USE_CONTRACTS)
           " reflection=" META_AUTH_STRINGIFY(META_AUTH_CONFIG_USE_REFLECTION);
}

} // namespace meta_auth::config

#endif // META_AUTH_CONFIG_HPP
