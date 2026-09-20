# ---------------------------------------------------------------------------
# Capability layer tests: the rights lattice, minting, attenuation and
# revocation.
# ---------------------------------------------------------------------------
meta_auth_add_test(meta_auth_capability_rights
    GROUP unit
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
