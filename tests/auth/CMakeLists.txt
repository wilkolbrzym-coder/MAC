# ---------------------------------------------------------------------------
# Auth layer tests: the session type-state, credentials and the policy engine.
# ---------------------------------------------------------------------------
meta_auth_add_test(meta_auth_auth
    GROUP unit
    SOURCES test_auth.cpp
    TIMEOUT 120)
