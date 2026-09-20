# meta-auth-core

**Compile-time user and device authentication with an object-capability sandbox.**

`meta-auth-core` is a header-only C++26 library in which the *authorisation
model is part of the type system*. A program that would escalate a privilege,
forge a capability, use a revoked one, or act on behalf of a device that failed
attestation is not caught at run time — it does not compile.

[![CI](https://github.com/wilkolbrzym-coder/MAC/actions/workflows/ci.yml/badge.svg)](https://github.com/wilkolbrzym-coder/MAC/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Standard](https://img.shields.io/badge/C%2B%2B-26-blue.svg)](https://en.cppreference.com/w/cpp/26)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#design-thesis)

---

## The problem

Authentication code is usually written as a sequence of run-time checks:

```cpp
if (!session.authenticated())            return Error::unauthenticated;
if (!session.has_role(Role::admin))      return Error::forbidden;
if (device.revoked())                    return Error::revoked;
admin_wipe(device);                      // ...until someone adds a call site
```

Every one of those lines is a promise that the *next* call site will remember
to repeat it. The failure modes are well known, and all of them are failure
modes of *runtime* enforcement:

| Defect | Why a runtime check does not stop it |
| --- | --- |
| Privilege escalation | A new code path reaches the operation without the check |
| Confused deputy | A privileged component is tricked into using its own authority for a caller that lacks it |
| Capability forgery | The token is a value; values can be constructed, copied, deserialised |
| Time-of-check-to-time-of-use | The check and the use are separated by mutable state |
| Use after revocation | Revocation is a flag someone must remember to consult |
| Silent degradation | A security check that stopped running looks exactly like one that passed |

## Design thesis

> A check that can be performed at compile time must be performed at compile
> time, so that the failure modes above are not *caught* but *unrepresentable*.

Five commitments follow, and every layer exists to enforce one of them:

1. **Authority is a value you hold, not a flag you check.** Capabilities are
   unforgeable — their constructor is private and an `authority` is the only
   friend — and *affine*: they can be moved and attenuated, never copied. There
   is no ambient authority to abuse, so the confused deputy has nothing to be
   confused about.
2. **Rights form a lattice, and attenuation is the only direction of travel.**
   Delegation is constrained by `requires`, not validated at run time: handing
   out a capability stronger than the one you hold fails to compile.
3. **Authentication is a type-state, not a boolean.** `session<P, anonymous>`
   has no `wipe_device()`. The transition to `authenticated` is the only way to
   obtain one, and the wrong transition is reported by a `= delete("...")`
   declaration that says which one was missing.
4. **Authorisation proofs are values the compiler can demand.** A protected
   operation takes an `authorization<Resource, Action>`. You cannot call it
   without one, and the only way to obtain one is to satisfy the policy at
   compile time.
5. **Every declared resource has a policy, enforced by reflection.** Adding an
   enumerator to `resource_kind` without a policy rule is a build failure, not
   an uncovered branch.

Alongside those, the library keeps its obligations to the parts of security
that genuinely are run-time properties — hashing, constant-time comparison,
attestation digests, revocation epochs, audit trails — and treats them with the
same care: `consteval` where possible, NIST and RFC vectors asserted at compile
time, no exceptions on the hot path, no allocation in the audit trail.

## Quick start

```sh
cmake --preset dev              # configure (GCC 16, contracts + reflection)
cmake --build --preset dev      # build the tests, the examples and the probe
ctest --preset dev              # run everything, including the negative suite
./build/dev/bin/meta_auth_demo  # the whole model, end to end
```

## What the library does

```cpp
// 1. A device proves what it is, against a trust store that is a compile-time
//    value. A device that is not in it cannot be trusted whatever it sends.
using deployment = trust_store<bench_device.digest()>;
auto claim = attest(descriptor, device_key);
verify_attestation_against<deployment>(claim, descriptor, device_key);   // -> status

// 2. A principal authenticates, and the session's *type* carries the state.
auto session = session<operator_principal, session_state::anonymous>::begin()
                   .authenticate(credential, password);                  // -> result<...authenticated>
auto elevated = std::move(*session).elevate(second_factor, code);        // -> result<...elevated>

// 3. Authority is minted by an authority, then only ever weakened.
authority<devices, rights_set::all()> root;
auto strong = root.mint<rights_set::all()>();
auto handed_out = strong.delegate<rights_set{right::read}>();            // needs right::grant

// 4. A protected operation demands a policy proof *and* a capability.
auto proof = authorize<policy, operator_principal,                             // consteval:
                       resource_kind::devices, action::modify>();              // denial does not compile
registry.write<rights_set::all(), operator_principal>(strong, std::move(proof), gate, 0x5678U);

// 5. Revocation is one atomic increment; the gate refuses what it invalidated.
revoke_all<devices>();
```

## Guarantees, and where each is enforced

| Guarantee | Mechanism | Proof |
| --- | --- | --- |
| A capability cannot be forged | private constructor, `authority` is the only friend | `compile_fail/capability_construct.cpp` |
| A capability cannot be duplicated | deleted copy operations; `delegate` needs `grant` | `compile_fail/capability_copy.cpp` |
| Authority is monotonically non-increasing | `requires (Requested ⊆ Held)` on `attenuate`/`delegate` | `compile_fail/capability_amplify.cpp`, exhaustive lattice tests |
| A revoked capability is refused | epoch comparison at the gate, one atomic increment to revoke | `tests/capability/test_revocation.cpp` |
| An illegal session transition does not exist | `requires` on the transition + `= delete("...")` | `compile_fail/session_*.cpp` (4 cases) |
| A denied request does not compile | `consteval` policy evaluation + constrained `authorize` | `compile_fail/policy_denied_request.cpp` |
| No resource is left without a policy | `static_assert` inside `policy`, driven by reflection | `compile_fail/policy_missing_rule.cpp` |
| A device is trusted only if compiled in | `trust_store<digests...>` as a non-type template parameter | `tests/identity/test_identity.cpp` |
| Secret comparison does not leak by timing | accumulate-and-compare with an optimisation barrier | `benchmarks/` measures the spread, and gates on it |
| The audit trail is readable while written | stamped slots, relaxed atomics | `tests/sandbox/test_sandbox.cpp` under ThreadSanitizer |

## Repository layout

```
include/meta_auth/   the library (header-only), one directory per layer
  core/              errors, results, contracts, structural strings, identifiers
  crypto/            SHA-256, HMAC-SHA256, constant-time primitives, erasure
  capability/        rights lattice, capabilities, authorities, revocation
  identity/          principals, device descriptors, trust anchors, attestation
  auth/              type-state sessions, credentials, the policy engine
  sandbox/           audit trail, mediation gate, protected objects
tests/               one directory per layer, plus the harness and the negative suite
tests/compile_fail/  programs that must not compile, with the reason recorded
examples/            a runnable demonstration that doubles as a test
benchmarks/          micro-benchmarks, including the constant-time gate
cmake/               build modules and the two test drivers
docs/                architecture, threat model, models, decisions
```

## Building

Requirements: a C++26 compiler and Ninja (the presets pin the generator, so
that a build behaves the same in a minimal container as it does locally — the
first CI run failed in every job because the container image has no `make` and
CMake's default generator is Unix Makefiles). The reference configuration is
**GCC 16**,
which implements the three dialect features the library is built on (contracts,
static reflection, pack indexing). GCC 15 and Clang 21 build it with the
optional features switched off; the test suite covers both configurations, and
`ctest --preset portable` is the configuration that proves it.

Presets: `dev`, `portable` (no contracts, no reflection), `release`, `asan`,
`tsan`, `coverage`, `bench`. See `CMakePresets.json`.

There are no third-party dependencies, at build time or in the headers. The
library is an INTERFACE target; vendoring `include/meta_auth/` into an existing
build is a supported way to use it. Two things are worth knowing if you do:

* pass `-fcontracts` on the **link** line as well as the compile line, or define
  `META_AUTH_CONFIG_USE_CONTRACTS=0`;
* pass `-freflection` to get the reflection-driven policy checks, or define
  `META_AUTH_CONFIG_USE_REFLECTION=0`. See `docs/contracts.md`.

## Measurements

From `benchmarks/meta_auth_bench` on the development machine, in a
contracts-enabled release build:

| Operation | Cost |
| --- | --- |
| Mediated write (policy proof + capability check + audit record) | ~431 ns |
| Refused write (the same, denied and recorded) | ~438 ns |
| Audit record | ~20 ns |
| SHA-256 of 1 KiB | ~6.1 µs |
| HMAC-SHA256 of 64 B | ~356 ns |
| Constant-time compare, 32 B | ~2.1 ns, spread **0.15 ns** across all differing positions |

A denial costs the same as a grant, which is deliberate: if denials were
cheaper, they would be a lever. The constant-time spread is the number that
matters, and the benchmark fails the run when it exceeds 25% of the fastest
measurement, so it is a regression gate rather than a report.

## Documentation

| Document | Answers |
| --- | --- |
| [docs/DESIGN-PRINCIPLES.md](docs/DESIGN-PRINCIPLES.md) | What the project commits to, and how each commitment is enforced |
| [docs/architecture.md](docs/architecture.md) | How the layers fit together, and what each one may depend on |
| [docs/threat-model.md](docs/threat-model.md) | What is defended against, and what is explicitly out of scope |
| [docs/capability-model.md](docs/capability-model.md) | The object-capability semantics and the monotonicity argument |
| [docs/contracts.md](docs/contracts.md) | Contracts, the portable fallback, and the compiler limitations found |
| [docs/testing.md](docs/testing.md) | What each group of tests is for, and how to add one |
| [docs/decisions.md](docs/decisions.md) | The decisions with their alternatives and consequences |
| [SECURITY.md](SECURITY.md) | How to report a problem, and what the library does not claim |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Building, testing, and the standard a change is held to |
| [CHANGELOG.md](CHANGELOG.md) | What changed, in the order it changed |

## Status

Version 0.1.0. All six layers are implemented and tested; the documentation and
the test suite are complete for what exists. Nothing here has been deployed in
production, and nothing here should be the only thing between an attacker and a
system: see the non-goals in [docs/threat-model.md](docs/threat-model.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
