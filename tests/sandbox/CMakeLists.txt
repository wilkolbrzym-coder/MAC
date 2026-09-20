# ---------------------------------------------------------------------------
# Sandbox layer tests: the audit trail, the mediation gate, protected objects.
# ---------------------------------------------------------------------------
meta_auth_add_test(meta_auth_sandbox
    GROUP unit
    SOURCES test_sandbox.cpp
    TIMEOUT 120)
