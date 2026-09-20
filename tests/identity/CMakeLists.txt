# ---------------------------------------------------------------------------
# Identity layer tests: principals, device descriptors, trust anchors and the
# attestation path.
# ---------------------------------------------------------------------------
meta_auth_add_test(meta_auth_identity
    GROUP unit
    SOURCES test_identity.cpp
    TIMEOUT 120)
