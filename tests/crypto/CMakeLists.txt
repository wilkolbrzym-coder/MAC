# ---------------------------------------------------------------------------
# Crypto layer tests: the FIPS and RFC vectors, the constant-time primitives
# and the erasure path.
# ---------------------------------------------------------------------------
meta_auth_add_test(meta_auth_crypto
    GROUP unit
    SOURCES test_crypto.cpp
    TIMEOUT 120)
