# ---------------------------------------------------------------------------
# Capability layer tests: the rights lattice, minting, attenuation and
# revocation.
# ---------------------------------------------------------------------------
# The rights lattice is the one component whose tests are *laws* rather than
# examples: every ordered pair of the 128 sets is checked against reflexivity,
# antisymmetry, transitivity and the bounds property. It carries both labels
# because it is both -- a unit of the capability layer, and the group that
# `ctest -L property` is documented to select. It carried only `unit`, so the
# documented label selected nothing and still exited successfully.
meta_auth_add_test(meta_auth_capability_rights
    GROUP property
    LABELS unit
    SOURCES test_rights.cpp
    TIMEOUT 120)

meta_auth_add_test(meta_auth_capability
    GROUP unit
    SOURCES test_capability.cpp
    TIMEOUT 120)

meta_auth_add_test(meta_auth_capability_revocation
    GROUP concurrency
    SOURCES test_revocation.cpp
    TIMEOUT 180)
