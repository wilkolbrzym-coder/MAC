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
# ---------------------------------------------------------------------------
include(MetaAuthTestHelpers)

# The dialect group is registered first: if the compiler configuration is not
# what the rest of the suite assumes, every later result is uninterpretable.
add_subdirectory(dialect)
