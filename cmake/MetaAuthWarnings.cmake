# ---------------------------------------------------------------------------
# MetaAuthWarnings -- the diagnostic set this project holds itself to.
#
# A security library that argues "this defect class cannot be expressed" has
# no standing if it ships with avoidable warnings, so the set is broad and
# promoted to errors by default. Each group below states what it buys.
#
# Three compilers, three spellings, and the sets are genuinely different --
# not one list translated. GCC's curated set is the reference; Clang accepts a
# subset and rejects the rest loudly; MSVC warns about a different world
# entirely. A single list relying on the compiler to ignore what it does not
# recognise would look tidier and would silently check less on two of the
# three.
#
# `-Werror`/`/WX` is deliberately scoped with `$<BUILD_INTERFACE:...>`: it is
# this project's bar for its own sources, not something to impose on a
# consumer that links a header-only library. It used to be exported
# unconditionally, so `find_package(meta-auth-core)` turned a downstream
# project's warnings into build failures of its own code.
#
# `-Wconversion`/`-Wsign-conversion` are included deliberately: every one of
# the constant-time primitives in this library operates on unsigned byte
# buffers, and an accidental signed widening there is a correctness bug, not a
# style issue.
# ---------------------------------------------------------------------------

# Language-level correctness: constructs that are legal but almost always
# wrong. Kept separate from the style group because these are the warnings a
# reviewer should never have to argue about.
set(META_AUTH_WARNINGS_GCC_CORRECTNESS
    -Wall
    -Wextra
    -Wpedantic
    -Wcast-qual
    -Wcast-align
    -Wconversion
    -Wsign-conversion
    -Wdouble-promotion
    -Wformat=2
    -Wformat-security
    -Wformat-overflow=2
    -Wformat-truncation=2
    -Wnull-dereference
    -Wimplicit-fallthrough=5
    -Wshift-overflow=2
    -Wshift-negative-value
    -Wstrict-overflow=2
    # Level 2 of -Warray-bounds is documented as producing false positives
    # under aggressive inlining, and it does: the SHA-256 compression function
    # inlined into HMAC reports a subscript 225 into a 32-byte digest at -O3.
    # A false positive in a project that treats warnings as errors is a build
    # that cannot be produced, so the level is the default one -- which is what
    # -Wall enables -- and the aggressive analysis is left out.
    -Warray-bounds
    -Wstringop-overflow=4
    -Wstringop-truncation
    -Walloc-zero
    -Winfinite-recursion
    -Wduplicated-cond
    -Wduplicated-branches
    -Wlogical-op
    -Wtautological-compare
    -Wmismatched-new-delete
    -Wdelete-incomplete
    -Wuseless-cast
    -Wold-style-cast
    -Wzero-as-null-pointer-constant
    -Wshadow
    -Wundef
    -Wredundant-decls
    -Wmissing-declarations
    -Wswitch-enum
    -Wpointer-arith
    -Wvla
    -Wbidi-chars=any,ucn
    -Woverflow
    -Wc++23-extensions
    -Wc++26-extensions
)

# C++-specific hygiene: the class of mistake that a template-heavy library
# creates and that a compiler is uniquely good at catching.
#
# `-Weffc++` and `-Wtemplates` are deliberately absent: both are documented as
# heuristic, and both fire on idiomatic standard-library use (value semantics
# over std::array members, thin constexpr wrappers around standard algorithms).
# A warning set that produces false positives gets switched off, which is
# strictly worse than a shorter set that is always believed.
set(META_AUTH_WARNINGS_GCC_CPP
    -Wnon-virtual-dtor
    -Wctor-dtor-privacy
    -Woverloaded-virtual
    -Wextra-semi
    -Wsuggest-override
    -Wvirtual-inheritance
    -Wmultiple-inheritance
    -Wnoexcept
    -Wcatch-value=2
    -Wterminate
    -Wplacement-new=2
    -Wdeprecated
    -Wdeprecated-copy
    -Wdeprecated-declarations
    -Wreorder
    -Wpessimizing-move
    -Wredundant-move
    -Wrange-loop-construct
    -Wreturn-type
    -Wuninitialized
    -Wmaybe-uninitialized
)

# `-Wmissing-field-initializers` is deliberately absent. The library's records
# carry defaults precisely so that a caller names the fields it means
# (`violation_record{.expression = ..., .file = ..., .line = ...}`), and the
# warning fires on exactly that idiom while `-Wextra` already reports the case
# it was written for -- an aggregate initialised positionally and incompletely,
# which this codebase never does.

# `-Wswitch-default` is deliberately absent next to `-Wswitch-enum`. The two
# together demand a `default:` label *and* a case for every enumerator, and a
# `default:` label is precisely what silences the diagnostic that fires when a
# new enumerator is added. This library wants that diagnostic: an unhandled
# enumerator in `to_string` or in the policy engine is a defect, not a default.

# Warnings that are valuable but that a header-only, template-heavy library
# legitimately trips in unevaluated or discarded contexts. They are requested
# at the strongest level that still produces an actionable message.
set(META_AUTH_WARNINGS_GCC_NOISY
    -Wdisabled-optimization
    -Wunsafe-loop-optimizations
)

# Clang's subset. Every flag here exists in Clang; the ones only GCC has
# (`-Wduplicated-branches`, `-Wlogical-op`, `-Wuseless-cast`, `-Wnoexcept`,
# `-Wuseless-cast`, `-Wc++26-extensions`) are left out rather than papered over
# with `-Wno-unknown-warning-option`, which would suppress the typo that
# motivated the suppression as well.
set(META_AUTH_WARNINGS_CLANG
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wshadow
    -Wold-style-cast
    -Wnon-virtual-dtor
    -Woverloaded-virtual
    -Wcast-qual
    -Wcast-align
    -Wundef
    -Wzero-as-null-pointer-constant
    -Wformat=2
    -Wimplicit-fallthrough
    -Wvla
    -Wdouble-promotion
    -Wswitch-enum
    -Wunreachable-code
    -Wconditional-uninitialized
    -Wcomma
    -Wdocumentation
    -Wrange-loop-analysis
    -Wunused-exception-parameter
)

# MSVC's equivalent bar. `/W4` is the level that is expected to be clean, and
# it is not the default (`/W3` is). `/permissive-` turns off the permissive
# fallbacks that accept non-conforming code; `/Zc:__cplusplus` and
# `/Zc:preprocessor` make the compiler report the truth about its own dialect,
# which `config.hpp` relies on.
#
# `/bigobj` is not a diagnostic but belongs here: the policy engine and the
# capability lattice instantiate enough templates that a translation unit can
# exceed the default section limit, and that failure mode is an unhelpful
# "fatal error C1128: number of sections exceeded object file format limit".
#
# The numbered `/w14xxx` flags re-enable diagnostics that `/W4` leaves off.
# They are the ones that correspond to the -Wconversion and -Wshadow families
# in the GCC set, because those two families are where this library's defects
# have actually been.
set(META_AUTH_WARNINGS_MSVC
    /W4
    /permissive-
    /Zc:__cplusplus
    /Zc:preprocessor
    /Zc:inline
    /utf-8
    /EHsc
    /bigobj
    /w14242   # conversion from 'T1' to 'T2', possible loss of data
    /w14254   # 'operator': conversion from 'T1' to 'T2', possible loss of data
    /w14263   # member function does not override any base class virtual member
    /w14265   # class has virtual functions, but its destructor is not virtual
    /w14287   # unsigned/negative constant mismatch
    /w14296   # expression is always false or always true
    /w14311   # pointer truncation
    /w14456   # declaration hides previous local declaration
    /w14545   # expression before comma evaluates to a function
    /w14546   # function call before comma missing argument list
    /w14547   # operator before comma has no effect
    /w14555   # expression has no effect
    /w14619   # pragma warning: there is no warning number
    /w14826   # conversion from integral type to bool
    /w14905   # wide string literal cast to LPSTR
    /w14906   # string literal cast to LPWSTR
    /w14928   # illegal copy-initialization
)

function(meta_auth_configure_warnings target)
    if(MSVC)
        target_compile_options(${target} INTERFACE
            $<BUILD_INTERFACE:${META_AUTH_WARNINGS_MSVC}>)
        if(META_AUTH_WARNINGS_AS_ERRORS)
            target_compile_options(${target} INTERFACE $<BUILD_INTERFACE:/WX>)
        endif()
        return()
    endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${target} INTERFACE
            $<BUILD_INTERFACE:${META_AUTH_WARNINGS_GCC_CORRECTNESS}>
            $<BUILD_INTERFACE:${META_AUTH_WARNINGS_GCC_CPP}>
            $<BUILD_INTERFACE:${META_AUTH_WARNINGS_GCC_NOISY}>
            # Aggressive inlining analysis is noisy for thin constexpr wrappers
            # that exist only to be constant-evaluated, which is most of this
            # library; the diagnostic is therefore reported but not promoted.
            #
            # `-Wno-error=noexcept` is here for a different reason: GCC 15
            # diagnoses `std::thread`'s constructor as potentially throwing
            # through libstdc++'s own headers, which turns every threaded test
            # into a build failure. The warning stays visible where it fires;
            # only its promotion is relaxed.
            $<BUILD_INTERFACE:-Wno-missing-field-initializers>
            $<BUILD_INTERFACE:-Wno-error=inline>
            $<BUILD_INTERFACE:-Wno-error=unsafe-loop-optimizations>
            $<BUILD_INTERFACE:-Wno-error=disabled-optimization>
            $<BUILD_INTERFACE:-Wno-error=noexcept>)
        if(META_AUTH_WARNINGS_AS_ERRORS)
            target_compile_options(${target} INTERFACE $<BUILD_INTERFACE:-Werror>)
        endif()
        return()
    endif()

    # Clang, AppleClang, and anything else that speaks the GCC dialect.
    target_compile_options(${target} INTERFACE
        $<BUILD_INTERFACE:${META_AUTH_WARNINGS_CLANG}>)
    if(META_AUTH_WARNINGS_AS_ERRORS)
        target_compile_options(${target} INTERFACE $<BUILD_INTERFACE:-Werror>)
    endif()
endfunction()
