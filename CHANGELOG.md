# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because the library is header-only, the version that matters is the one in
`include/meta_auth/version.hpp`, which the build system validates against
`project(VERSION ...)`.

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-09-20

The first release: all six layers, the full test suite, the benchmarks and the
documentation.

### Added

**Core**

* `auth_error`, a closed enumeration of every domain error, with stable numeric
  codes, names, a domain classification, and a recoverability judgement that is
  deliberately asymmetric (a forged capability is not recoverable; a rejected
  credential is).
* `result<T>` / `status` over `std::expected`, with propagation macros that
  expand to plain declarations and `if` statements — no statement expressions,
  no GNU extensions.
* Contract assertions in both forms (declarator `pre`/`post` and statement
  `contract_assert`) with a portable fallback that produces the same report and
  the same abort, and a library-provided `handle_contract_violation` with a
  redirectable stream and an observer hook.
* `fixed_string`, usable as a non-type template parameter, with concatenation,
  prefix/suffix/contains and FNV-1a hashing.
* `strong_id`, a phantom-typed identifier that cannot be confused with an
  identifier of another kind, with tags that can name themselves.

**Crypto**

* `sha256` and `hmac_sha256`, fully `constexpr`, verified against the FIPS 180-4
  and RFC 4231 vectors by `static_assert`.
* `constant_time_equal`, `constant_time_select`, `constant_time_less`,
  `constant_time_is_zero`, with an optimisation barrier that cannot be constexpr
  (an `asm` declaration is forbidden in a constexpr body) and is therefore
  called only from the run-time branch.
* `secure_erase` and `secret_buffer`, the latter movable-and-wiping, refusing a
  value that does not fit rather than truncating it.

**Capability**

* `rights_set`, a structural type usable as a template argument, with the full
  lattice algebra.
* `capability<Resource, Rights>`, unforgeable and affine, carrying its rights in
  its type and its provenance in its value.
* `authority`, the only route to a capability, with `mint`, `mint_consteval` and
  `restrict`.
* Monotone attenuation and delegation, constrained by `requires` and reported by
  `= delete("...")` declarations.
* `revocation_epoch` and `revoke_all<Resource>()`, one atomic increment per
  resource type.

**Identity**

* `principal<Name, Kind>`, with the kind bound into the identity digest.
* `device_descriptor` with a length-prefixed canonical encoding, its digest, and
  the collision test that justifies the prefixes.
* `trust_store<digests...>`, a compile-time set of trusted device identities.
* `device_key` and the `attest` / `verify_attestation` pair, with distinct
  outcomes for a mismatched descriptor, a bad MAC and an unknown anchor.

**Auth**

* `session<Principal, State>`, a four-state type-state machine with the
  transitions as the only way in and `= delete("...")` for the illegal ones.
* `credential_record` and `second_factor`, keyed by principal so that a record
  cannot be used for another principal, and compared in constant time.
* `policy<Rules...>`, which asserts its own exhaustiveness over `resource_kind`,
  and `consteval evaluate<...>()`, deny by default.
* `authorization<Resource, Action>`, the proof token, obtainable only through
  `authorize`.

**Sandbox**

* `audit_trail`, a fixed ring of stamped atomic slots: allocation-free,
  non-throwing, readable while written, counting its own overwrites.
* `gate<Resource>::admit`, which demands a policy proof and a capability, checks
  the right and the epoch, and records the outcome before returning it.
* `protected_object<T, Resource>`, whose value is private and whose only
  accessors take both.

**Tests and tooling**

* A dependency-free test harness, itself tested, with an isolation guard that
  lets the harness's failure path be asserted by cases that pass.
* Sixteen compile-failure tests, each with the reason it must fail recorded and
  asserted.
* Two failure-test drivers that assert *how* a process fails, not merely that it
  did.
* Benchmarks including a constant-time measurement that gates on its own spread.
* CMake presets for the four configurations CI runs, plus `bench`, `release` and
  `coverage`.
* A CI matrix over the four configurations, with the container pinned to the
  distribution the toolchain comes from.

**Documentation**

Architecture, threat model, capability model, contracts, testing, ten recorded
decisions, a security policy, a contributor guide, and a runnable demonstration
that doubles as an integration test.

### Compiler notes

Built and tested against GCC 16.0.1. Five compiler behaviours were found and
designed around rather than worked around; each is recorded with its
reproduction in `docs/contracts.md`:

* `-fcontracts` is needed on the link line, not only the compile line;
* `__cpp_contracts` is defined even when `-fcontracts` is absent;
* a named-result postcondition makes a scalar `constexpr` variable ill-formed;
* `if consteval` is constant-folded into a `const` initialiser, silently
  discarding the run-time branch — the reason `mint` and `mint_consteval` are
  separate functions;
* a call to a constrained function is a hard error inside a
  `requires`-expression, so the negative half of the API is asserted by
  compile-failure tests instead.

[Unreleased]: https://github.com/wilkolbrzym-coder/MAC/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/wilkolbrzym-coder/MAC/releases/tag/v0.1.0
