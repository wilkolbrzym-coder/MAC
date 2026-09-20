# ---------------------------------------------------------------------------
# Compile-failure suite.
#
# Each file here is a program that must NOT compile, paired with an expectation
# file recording the *reason* it must not. `meta_auth_add_compile_fail_test`
# compiles it, requires the compilation to fail, and requires the diagnostics to
# contain the recorded reason.
#
# This is the only mechanism that distinguishes "this is refused" from "this is
# refused for the documented reason", and the second is the claim the
# documentation makes. A positive test cannot express it.
#
# Adding a test here is a three-step ritual, and the ritual is the point:
#   1. write the program that should be rejected;
#   2. compile it by hand and read the diagnostic;
#   3. record the fragment of the diagnostic that states the reason.
# Deleting a line from an expectation file is how a reviewer acknowledges that a
# previously rejected program became legal.
# ---------------------------------------------------------------------------
set(_negative_sources
    authority_mint_beyond_max.cpp
    authority_widen.cpp
    capability_amplify.cpp
    capability_copy.cpp
    capability_construct.cpp
    capability_delegate_beyond_held.cpp
    capability_delegate_without_grant.cpp
    policy_denied_request.cpp
    policy_missing_rule.cpp
    protected_object_direct_access.cpp
    session_credential_of_another_principal.cpp
    session_elevate_without_authenticating.cpp
    session_operate_after_revocation.cpp
    session_revoke_twice.cpp
    strong_id_mixed_up.cpp)

foreach(_source IN LISTS _negative_sources)
    meta_auth_add_compile_fail_test("${CMAKE_CURRENT_SOURCE_DIR}/${_source}" TIMEOUT 120)
endforeach()
