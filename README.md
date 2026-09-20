# meta-auth-core

**Compile-time user and device authentication with an object-capability sandbox.**

`meta-auth-core` is a header-only C++26 library in which the *authorisation
model is part of the type system*. A program that would escalate a privilege,
forge a capability, use a revoked one, or act on behalf of a device that failed
attestation is not caught at run time — it does not compile.

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
to repeat it. The failure modes are well known and all of them are failure
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

Five commitments follow from that, and every layer of the library exists to
enforce one of them:

1. **Authority is a value you hold, not a flag you check** (`capability`).
   Capabilities are unforgeable — their constructor is private and the only
   minting path is an `authority` — and *affine*: they can be moved and
   attenuated, never copied. There is no ambient authority to abuse, so the
   confused deputy has nothing to be confused about.

2. **Rights form a lattice, and attenuation is the only direction of travel**
   (`rights_set`, `attenuate`). Delegation is constrained by `requires`, not
   validated at run time: handing out a capability that is stronger than the
   one you hold fails to compile. Amplification is not a rule that is
   enforced; it is a program that cannot be written.

3. **Authentication is a type-state, not a boolean** (`session`).
   `session<anonymous>` has no `wipe_device()`. The transition to
   `session<authenticated>` is the only way to obtain one, and it requires an
   attestation that the type system asked for by name. Calling an operation in
   the wrong state produces a diagnostic sentence via `= delete("reason")`
   rather than an exception at three in the morning.

4. **Authorisation proofs are values the compiler can demand** (`authorize`,
   `authz_proof`). A protected operation takes an `authz_proof` argument. You
   cannot call it without one, and the only way to obtain one is to satisfy the
   policy at compile time.

5. **Every declared resource has a policy, enforced by reflection** (P2996).
   Adding an enumerator to `resource_kind` without a corresponding policy rule
   is a build failure, not an uncovered branch. Exhaustiveness is checked, not
   reviewed.

Alongside those, the library keeps its obligations to the parts of security
that genuinely are run-time properties — hashing, constant-time comparison,
attestation digests, revocation epochs, audit trails — and treats them with the
same care: `consteval` where possible, NIST test vectors asserted at compile
time, no exceptions on the hot path, no allocation in the audit trail.

## Status

This repository is under active construction; the table is the roadmap and the
record of what is finished.

| Layer | Contents | State |
| --- | --- | --- |
| `core` | error/result plumbing, contracts, structural strings | planned |
| `crypto` | `consteval` SHA-256, HMAC, constant-time primitives, secure erasure | planned |
| `capability` | rights lattice, capabilities, authorities, attenuation, revocation | planned |
| `identity` | principals, device descriptors, attestation digests | planned |
| `auth` | type-state sessions, policy engine, authorisation proofs | planned |
| `sandbox` | mediation gate, protected objects, audit trail | planned |
| `reflect` | reflection-driven policy exhaustiveness and descriptions | planned |
| `app` | runnable CLI demonstrating the whole flow | planned |

## Building

Requirements: a C++26 compiler. The reference configuration is **GCC 16**,
which implements all three dialect features the library is built on
(contracts, static reflection, pack indexing). GCC 15 and Clang 21 build the
library with the optional features switched off; the test suite covers both
configurations.

```sh
cmake --preset dev          # configure
cmake --build --preset dev  # build
ctest --preset dev          # test
```

Presets: `dev`, `portable` (no contracts, no reflection), `release`, `asan`,
`tsan`, `coverage`, `bench`. See `CMakePresets.json`.

There are no third-party dependencies, at build time or in the headers. The
library is an INTERFACE target; vendoring `include/meta_auth/` into an existing
build is a supported way to use it.

## Repository layout

```
include/meta_auth/   the library (header-only)
tests/               unit, property, concurrency, compile-failure, integration
benchmarks/          micro-benchmarks with a published baseline
examples/            runnable examples, one per feature
docs/                architecture, threat model, ADRs, design notes
cmake/               build modules and the compile-failure test driver
```

## Documentation

| Document | Answers |
| --- | --- |
| [docs/DESIGN-PRINCIPLES.md](docs/DESIGN-PRINCIPLES.md) | What this project commits to, and how each commitment is enforced |
| `docs/architecture.md` | How the layers fit together | *(planned)* |
| `docs/threat-model.md` | What is defended against, and what is explicitly out of scope | *(planned)* |
| `docs/capability-model.md` | The object-capability semantics and the monotonicity argument | *(planned)* |
| `docs/contracts.md` | How C++26 contracts are used, and why some checks are not contracts | *(planned)* |
| `docs/adr/` | Decisions with their alternatives and consequences | *(planned)* |

## License

Apache License 2.0. See [LICENSE](LICENSE).
