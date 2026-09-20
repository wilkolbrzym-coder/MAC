# ---------------------------------------------------------------------------
# Core layer tests: the vocabulary every other layer speaks.
# ---------------------------------------------------------------------------
meta_auth_add_test(meta_auth_core_error
    GROUP unit
    SOURCES test_error.cpp
    TIMEOUT 60)
