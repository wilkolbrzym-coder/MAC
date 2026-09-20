# ---------------------------------------------------------------------------
# Dialect group: assertions about the compiler configuration itself.
#
# These tests are cheap and they are the ones that must run first. A build in
# which contracts silently stopped being enforced would otherwise pass the
# entire suite while providing less protection than the documentation claims.
# ---------------------------------------------------------------------------
meta_auth_add_test(meta_auth_dialect_smoke
    GROUP dialect
    SOURCES dialect_smoke.cpp
    TIMEOUT 30)
