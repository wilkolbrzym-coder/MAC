# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because the library is header-only, the version that matters is the one in
`include/meta_auth/version.hpp`, which the build system validates against
`project(VERSION ...)`.

## [Unreleased]

An adversarial review of the whole tree, and the changes it produced. The
security-relevant entries are first, because the rest are ordinary engineering
and those are not.

### Fixed

**Security**

* **A session state could be fabricated.** `detail::session_core` was an
  aggregate with public members and a public `create()`, and `session`'s
  constructor took one, so
  `session<admin_principal, session_state::elevated>{detail::session_core{}}`
  produced a fully elevated session for the administrator with no credential and
  no second factor. It compiled, and it did not look like a bypass. The core is
  now a class with private constructors, a deleted default constructor carrying
  a message, and user-provided copy and move operations so that `std::bit_cast`
  cannot fabricate one either. `compile_fail/session_forged_state.cpp`.
* **A policy proof could be forged with `std::bit_cast`.** `authorization` was
  an empty class with a defaulted move constructor, which made it trivially
  copyable, so `std::bit_cast<authorization<R, A>>(std::array<std::byte, 1>{})`
  produced a valid-looking proof without `authorize` ever being evaluated — the
  one line that defeated "a denied request does not compile". The move
  constructor is now user-provided, which makes the class non-trivially
  copyable, and two `static_assert`s in `auth/policy.hpp` hold the property.
* **A proof was not bound to a principal.** `authorization` carried a resource
  and an action, and `gate::admit` took the principal as a free template
  argument, so a proof obtained for one principal could be presented by an
  admission naming another — and the audit record then said the *other*
  principal acted. The proof now carries its principal and `admit` takes it in
  both positions, so the two must agree.
  `compile_fail/gate_proof_for_another_principal.cpp`.
* **A rule could name a principal and mean its whole kind.**
  `pattern_matches` discriminated on `requires { Pattern::kind; }`, and every
  `principal<Name, Kind>` has a `static constexpr principal_kind kind`, so
  `allow<devices, revoke, admin_principal>` meant "any principal of kind user
  may revoke" — one principal written, all of them authorised. A rule's pattern
  is now checked where the rule is written, and a bare principal type is a
  compile error naming the two spellings that exist.
  `compile_fail/policy_bare_principal_rule.cpp`.
* **`attenuate` did not consume what it weakened.** The documentation said that
  after attenuation there is exactly one capability and it is the weaker one,
  and that duplication requires `delegate` — which requires `right::grant`. The
  source was left fully usable, so *any* capability could be duplicated without
  `grant`. Capabilities now carry a validity flag, `attenuate` and the move
  operations neutralise their source, `has` and `is_live` report a spent value
  as holding nothing, and the gate refuses it with a distinct audit outcome
  (`denied_neutralised`) and error (`capability_neutralised`).
* **The one-shot HMAC did not erase anything.** It left the padded key and both
  pads on the stack, and the streaming hasher's `destroy()` erased only the
  pads — not the inner hasher's state, which is the compression of the inner
  padding block and therefore a deterministic function of the key. Both forms
  now erase everything they derived, and `sha256_hasher` has a `destroy()` for
  the state. `hmac_test_case` in `tests/crypto/test_crypto.cpp` asserts that
  every byte of the hasher is zero after `destroy()`.
* **`secret_buffer::wipe` erased only the used prefix.** `data()` hands out a
  writable pointer, so a caller that filled the buffer through it never
  advanced `size_` and `wipe()` — and the destructor — erased nothing. The
  whole capacity is erased now, and `copy_to` refuses a destination that cannot
  hold the secret instead of silently truncating it.
* **`revoke_all`'s epoch slot and the serial counter were handed out as mutable
  references** by `detail::epoch_slot` and `detail::serial_slot`. The threat
  model puts "code with write access to the process" out of scope, but a
  mutable reference to the epoch means a revocation can be *undone* by code that
  only reads the API. Both remain in `detail`, and the guarantee is now stated
  with its boundary in `docs/threat-model.md` rather than assumed.

**Correctness and memory safety**

* **`format_violation` wrote one byte past the end of its buffer** when the
  report exactly filled it: `result.size == buffer.size()` is not truncation,
  so the terminator branch ran and wrote at `buffer[size]`. On GCC 16 this is
  not a stray byte — libstdc++ hardens `span::operator[]` and the write aborts
  the process, on the fail-stop path whose purpose is to report a violation
  before stopping. The comparison is `>=` and the terminator is written only
  when there is room. `tests/core/test_contract.cpp` sizes a record to land
  exactly on the boundary.
* **`hmac_sha256`'s comment described a destructor that is `constexpr` as
  non-`constexpr`**, which is why the one-shot form was believed to need no
  erasure. The comment is corrected and the erasure added.
* **`detail::rotate_right(v, 0)` was undefined behaviour** (a shift by the width
  of the type). Unreachable from the current call sites, and now unreachable
  from any future one.
* **`constant_time_select` accepted `bool`**, for which `std::make_unsigned_t`
  is ill-formed: the diagnostic was a hard error inside the library rather than
  a constraint failure naming the caller's argument.
* **`constant_time_mask` returned 0 or 1, not a mask.** Renamed
  `constant_time_bit`, which is what it returns.
* **The MSVC fallback in `optimization_barrier` wrote a plain `volatile`
  counter from every thread**, which is a data race — in the one place in this
  library where a defect is invisible. It is an atomic relaxed RMW now.
* **`fixed_string::contains` used `std::string_view::find`, which is not a
  constant expression in libstdc++ 15 or in the libc++ shipped with recent
  Apple toolchains.** The three predicates are explicit loops now, which is what
  makes the test suite build on GCC 15 — the README claimed it did, and it did
  not.
* **`test_error.cpp` hard-coded the number of `auth_error` enumerators** as a
  literal array extent, so adding one made the reflective walk index past the
  end and the test that exists to catch an unhandled enumerator failed for an
  unrelated reason. The count comes from reflection.
* **`MSVC` was rejected by the dialect floor** because `config.hpp` tested
  `__cplusplus`, which MSVC reports as `199711L` unless `/Zc:__cplusplus` is
  passed. The check uses `_MSVC_LANG` where it exists.

**Tests**

* **A misspelled option made the test runner exit 0.** `--filtr=...` printed the
  usage text and *passed*, so a CI job that mistyped a filter ran the whole
  suite and reported success. An unknown argument is now exit 3.
  `framework.unknown_argument_is_an_error` asserts the status and the message.
* **The compile-failure suite did not check the reason it claimed to.**
  `expected/capability_copy.txt` required `use of deleted function` and the
  substring `capability`, which the other fourteen cases also satisfied;
  matching was done with `MATCHES`, so the parentheses in a C++ signature were
  regex groups and stopped matching themselves. Expectations are now literal
  substrings split into a portable half (the sentences this library writes) and
  a per-compiler half (the compiler's own spelling), and each was checked
  against the other cases' sources to confirm it rejects them.
* **`expected_decision` in `tests/auth/test_auth.cpp` was dead code.** A comment
  claimed the decision matrix was asserted over every combination; what ran was
  a check that the evaluator honours its own rules, which a policy that allowed
  too much satisfies perfectly. The 3 × 5 × 6 matrix is asserted now, and
  widening one rule makes the build fail.
* **`serials_are_unique_per_resource` could not see a shared counter.** Its
  assertions (`>= 64`, `>= 1`) are satisfied by one global sequence. A resource
  used nowhere else makes the counter's origin observable.
* **The revoked-session and bare-principal rejections had no message**, so they
  reported "no matching function" and a page of candidates. Both are now
  `= delete("...")` overloads, which is also what makes the negative suite
  portable: the message is the library's, not the compiler's.
* **Clang found dead code in the suite that GCC does not diagnose.** An unused
  `rights_set delegating` fixture in `test_capability.cpp` (a duplicate of
  `read_and_grant`), an `admin_credential` record in `test_auth.cpp` that no
  test consulted, and a `&start` capture in `test_revocation.cpp` that the
  lambda never used. Removed. This is the first thing Clang 21 was asked to do
  that GCC had not already done, and it is the kind of defect the suites are
  supposed to exclude: a fixture nobody uses is a claim nobody checks.

**Continuous integration**

The first run of the new workflow was red in seven of its ten jobs, and every
one of the seven was a defect in the job rather than in the library. Recorded
because a job that fails for its own reasons is worse than no job: it reports
the library's health as unknown while looking like a verdict on it.

* **The Clang job was testing a compiler below the library's floor.** It
  installed the runner image's `clang`, which on Ubuntu 24.04 is version 18, so
  every translation unit stopped at `config.hpp`'s one-sentence refusal
  (`__cpp_deleted_function >= 202403L`) — a job that measured Clang's release
  schedule rather than this library. It now runs in the reference container,
  where the distribution's `clang` is 21, the version the README claims.
* **The GCC 15 job could not install its compiler.** Ubuntu 24.04 has no
  `g++-15` package, so the install step failed and the job then reported
  `g++-15: command not found` twice. The same container carries it.
* **`asan`, `tsan` and `bench` found no compiler at all.** The container's only
  compiler is `g++-16`, which provides no unsuffixed `c++`, and those three
  presets ask CMake to find the host toolchain; they now name it. This also
  makes the sanitizer jobs run the *reference* configuration — GCC 16, contracts
  and reflection on — rather than a fallback of it.
* **The Windows job pinned a Visual Studio the runner image no longer has**, and
  failed in `project()` with "could not find any instance of Visual Studio"
  before compiling a line. The generator is no longer pinned: the job is
  testing MSVC, not a release of MSVC.
* **The macOS job failed on a flag the probe had accepted, twice over.** Apple's
  clang reports an unimplemented `-fstack-clash-protection` for arm64 as a
  warning ("argument unused during compilation"), so a probe that reads only the
  exit status said yes and the build then failed under `-Werror` with the flag in
  place. The probe now promotes diagnostics to errors for the duration of its own
  run — the question is whether the compiler accepts the flag *silently*, because
  that is what the build does with it. That alone did not fix the job, because
  both flag helpers passed the *same result variable* for every flag and CMake
  skips a probe whose result is already defined: only the first flag,
  `-fstack-protector-strong`, which every compiler accepts, was ever compiled,
  and the rest inherited its verdict. Each flag is now probed under its own name.
* **The ASan job ran for the first time and immediately found something**, which
  is the point of it: `sandbox.concurrent_records_all_land` failed with a
  retained record missing from the snapshot. Recorded in `docs/testing.md` and in
  `sandbox/audit.hpp` rather than fixed here — the fix is to the audit trail's
  write path, not to this workflow, and the bound it corrects was prose that the
  test disproved.

* **The macOS job then failed one step further in**, on `__COUNTER__`: Homebrew
  LLVM is version 23, which reports the macro as a C2y extension under
  `-Wpedantic` — and the test framework used it to give each case a unique name.
  It uses `__LINE__` now, which is in the standard and unique per declaration
  site for the same reason. `__COUNTER__` is a common extension that C2y
  standardised for C, not for C++, so the diagnostic is correct and will spread
  rather than regress.
* **Every test target pinned `CXX_STANDARD 26` as well**, so the MSVC fix to the
  library target was not enough: the Windows job then reported the same
  "requires the language dialect CXX26" for each of them. The pin is for every
  compiler that can hear it; MSVC takes the mode from the library's interface
  requirement.

* **MSVC does not implement P2573, and the job now says so.** With the CMake
  dialect fixed and the sources reached, MSVC 19.51 stopped at `config.hpp`'s
  floor: `__cpp_deleted_function` is not defined by the compiler, and
  cppreference's C++26 support table lists P2573R2 for GCC 15 and Clang 19 only.
  The README, `SECURITY.md` and the `#error` sentence all claimed "MSVC 19.40+
  implements it", which was never measured and is false. The claims are
  corrected, and `windows/msvc` is now the negative assertion the project style
  asks for: it configures, builds, and requires the build to stop at that
  sentence — green while MSVC lacks the feature, red the day it ships, with the
  instruction to enable the configuration instead of a silent rot.

* **MSVC could not configure at all**, and the cause was CMake's: CMake has no
  CXX26 dialect for MSVC (its module stops at CXX23, which MSVC spells
  `/std:c++latest`), so `CMAKE_CXX_STANDARD 26` made every `try_compile` in the
  build fail with "requires the language dialect CXX26 … CMake does not know the
  flags to enable it" — the hardening probe being the first one reached. The
  mode is requested the way the compiler spells it, on the target, and travels
  to consumers as an interface requirement.

### Changed

* **The presets no longer pin GCC 16.** `cmake --preset dev` uses the host
  toolchain, so the first command in the README works on Linux, macOS and
  Windows. `dev-gcc16` and `portable-gcc16` are the pinned reference
  configurations CI runs; `dev-clang` and `windows-msvc` cover the other
  front ends.
* **Every hardening flag is probed, and the probe reads diagnostics rather than
  exit status.** `-fstack-clash-protection` and `-fcf-protection=full` were
  added unconditionally, which is correct on x86 GNU/Linux and wrong everywhere
  else: Apple's clang rejects `-fcf-protection` outright for an arm64 target, so
  the build failed in the toolchain before it reached the library. The first
  probe fixed that one and missed its sibling, because a compiler reports an
  unsupported `-f` flag as a warning; warnings are now errors for the probe.
* **`-Wunreachable-code` is out of the Clang set.** Clang 21 reports the arm of
  a constant ternary that is not taken — `META_AUTH_HAS_CONTRACTS ? "enforced" :
  "disabled"` in the dialect report, a line whose whole purpose is to print
  which arm was taken — as code that "will never be executed". The diagnostic is
  a source-level heuristic rather than a data-flow fact, and a warning set that
  produces false positives gets switched off wholesale, which is worse than a
  shorter set that is always believed. The data-flow facts that caught the dead
  code above stay.
* **The warning set is three sets, not one.** Clang gets a validated subset,
  MSVC gets `/W4 /permissive- /Zc:__cplusplus` and the numbered `/w14xxx`
  diagnostics that correspond to `-Wconversion` and `-Wshadow`, and GCC keeps
  its curated list. `-Werror`/`/WX` is scoped with `$<BUILD_INTERFACE:...>`, so
  a project that finds the package no longer inherits it — and the build no
  longer claims "warnings as errors" on compilers where that was not true.
* **Sanitizer and coverage flags are compiler-aware**, and an unsupported
  request warns instead of silently producing an uninstrumented build that a CI
  job would report as sanitized.
* **`Threads::Threads` is linked explicitly.** The concurrency tests construct
  `std::thread`, which resolved here only because this machine's glibc merged
  libpthread.
* **The compile-failure driver speaks three dialects** (`-fsyntax-only` against
  `/Zs`, `error:` against `error C####:`), and the family-specific expectations
  live in `expected/<case>.<family>.txt`.
* `cmake/MetaAuthSanitizers.cmake` no longer creates its global target
  unconditionally, and `TIMEOUT` has a default instead of passing an empty
  string to `set_tests_properties`.
* `required_right` falls through to `right::revoke` rather than `right::read`
  for an unmapped action: unreachable, and if it stops being unreachable the
  failure is a demand for the strongest right rather than the weakest.
* `version_packed()` masks its fields, so a component above 255 cannot carry
  into the next one.
* `META_AUTH_WEAK_SYMBOL` is `#undef`ed at the end of the header that defines
  it, instead of leaking a generic name into every translation unit.

### Added

* Six new programs to the compile-failure suite, for the five rejections above
  plus a session that acts after revocation.
* Tests for attenuation consuming its source, for a moved-from capability being
  refused by the gate, for `secret_buffer` erasing its whole capacity, for
  `destroy()` leaving no derived key material in an HMAC hasher, and for the
  policy's decision matrix.
* CI jobs for GCC 15, Clang, macOS (Homebrew LLVM) and Windows (MSVC), and a
  `documentation` job that no longer needs a `git` binary it does not install.
  The reference container stays pinned to Ubuntu 26.04 and GCC 16.

### Documented

* `docs/testing.md` states how the negative suite is split, why the matching is
  literal, and — under "Known gaps" — that Clang, AppleClang and MSVC have not
  been run on the machine this was developed on, that the audit trail's seqlock
  bounds the number of concurrent writers, and that revocation is not
  transactional with the operation it revokes.
* `sandbox/audit.hpp` states that bound next to the claim it qualifies, rather
  than leaving the reader to infer it.
* `README.md` no longer claims that GCC 15 and Clang 21 build the library; it
  says which configurations have been run and where.


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
