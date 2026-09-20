// Shared preamble for the negative tests.
//
// Every file here is a program that must NOT compile, and each one is compiled
// by ctest through cmake/MetaAuthCompileFail.cmake, which also checks that the
// diagnostic contains the reason recorded next to it in `expected/`.
//
// A suite of positive tests cannot distinguish "this is refused" from "this is
// refused for the reason we documented", and the second is the claim the
// documentation makes. These files are that distinction.
#include "meta_auth/auth/policy.hpp"
#include "meta_auth/auth/session.hpp"
#include "meta_auth/capability/capability.hpp"
#include "meta_auth/sandbox/gate.hpp"

using namespace meta_auth;

namespace negative_test {

using device_resource = named_resource<"devices">;
using device_authority = authority<device_resource, rights_set::all()>;

using service_policy = policy<
    allow<resource_kind::devices, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::devices, action::modify, exactly<admin_principal>>,
    allow<resource_kind::sessions, action::observe, any_principal<principal_kind::user>>,
    allow<resource_kind::credentials, action::observe, exactly<admin_principal>>,
    allow<resource_kind::audit_log, action::audit, any_principal<principal_kind::user>>,
    allow<resource_kind::policy_store, action::modify, exactly<admin_principal>>>;

inline const credential_record<operator_principal> operator_credential =
    credential_record<operator_principal>::enrol("secret");

inline const second_factor<operator_principal> operator_second_factor =
    second_factor<operator_principal>::enrol("totp");

} // namespace negative_test
