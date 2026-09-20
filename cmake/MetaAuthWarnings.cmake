# ---------------------------------------------------------------------------
# MetaAuthWarnings -- the diagnostic set this project holds itself to.
#
# A security library that argues "this defect class cannot be expressed" has
# no standing if it ships with avoidable warnings, so the set is broad and
# promoted to errors by default. Each group below states what it buys.
#
# `-Wconversion`/`-Wsign-conversion` are included deliberately: every one of
# the constant-time primitives in this library operates on unsigned byte
# buffers, and an accidental signed widening there is a correctness bug, not a
# style issue.
# ---------------------------------------------------------------------------

# Language-level correctness: constructs that are legal but almost always
# wrong. Kept separate from the style group because these are the warnings a
# reviewer should never have to argue about.
set(META_AUTH_WARNINGS_CORRECTNESS
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
set(META_AUTH_WARNINGS_CPP
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
set(META_AUTH_WARNINGS_NOISY
    -Wdisabled-optimization
    -Wunsafe-loop-optimizations
)

function(meta_auth_configure_warnings target)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        # The curated sets above are GCC spellings. Clang accepts most of them
        # but not all; rather than silently dropping flags via
        # -Wno-unknown-warning-option, the project asks for the portable
        # subset it has actually validated.
        target_compile_options(${target} INTERFACE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
            -Wshadow -Wold-style-cast -Wnon-virtual-dtor -Woverloaded-virtual
            -Wcast-qual -Wcast-align -Wundef -Wzero-as-null-pointer-constant
            -Wformat=2 -Wimplicit-fallthrough -Wvla -Wdouble-promotion)
    else()
        target_compile_options(${target} INTERFACE
            ${META_AUTH_WARNINGS_CORRECTNESS}
            ${META_AUTH_WARNINGS_CPP}
            ${META_AUTH_WARNINGS_NOISY})

        # Aggressive inlining analysis is noisy for thin constexpr wrappers
        # that exist only to be constant-evaluated, which is most of this
        # library; the diagnostic is therefore reported but not promoted.
        target_compile_options(${target} INTERFACE
            $<$<BOOL:${META_AUTH_WARNINGS_AS_ERRORS}>:-Werror>
            -Wno-missing-field-initializers
            -Wno-error=inline
            -Wno-error=unsafe-loop-optimizations
            -Wno-error=disabled-optimization)
    endif()
endfunction()
