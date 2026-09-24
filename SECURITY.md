# Security policy

## Reporting a problem

Open a [private security advisory](https://github.com/wilkolbrzym-coder/MAC/security/advisories/new)
or email the maintainer. Please do not open a public issue for a defect that
could be exploited before it is fixed.

What helps most, in order:

1. **A program that should not compile but does**, with the diagnostic it
   produced. The library's central claims are about programs that must be
   rejected, so a counterexample to one of those is the most serious class of
   report there is.
2. **A program that compiles and misbehaves**, with the output you expected and
   the output you got.
3. **A measurement**, if the claim is about timing: the benchmark, the machine,
   and the spread you observed. `benchmarks/meta_auth_bench` reports a spread
   across every differing position and fails above 25%; a counterexample that
   stays under that bound is worth knowing about, because the bound is a smoke
   test and not a side-channel analysis.

There is no bug bounty. There is a commitment to answer, to say plainly whether
the report is a defect, and to record what was decided.

## What this library claims, and what backs each claim

Every row names the artefact that would fail if the claim stopped being true.
A claim without one of those is not a claim this project makes.

| Claim | Evidence |
| --- | --- |
| A capability cannot be constructed, copied or strengthened | `tests/compile_fail/` (5 cases), the lattice tests |
| An illegal session transition does not exist | `tests/compile_fail/session_*.cpp` (4 cases) |
| A request the policy denies does not compile | `tests/compile_fail/policy_denied_request.cpp` |
| An incomplete policy is a build failure | `tests/compile_fail/policy_missing_rule.cpp` |
| A device is trusted only if its digest is in the compiled-in store | `tests/identity/test_identity.cpp` |
| A revoked capability is refused by every mediated path | `tests/capability/test_revocation.cpp`, `tests/sandbox/test_sandbox.cpp` |
| SHA-256 and HMAC-SHA256 match the published vectors | `static_assert`s in `tests/crypto/test_crypto.cpp` |
| Secret comparison does not leak the position of a difference | `benchmarks/` measures it and gates on the result |
| The audit trail is readable while it is written | `tests/sandbox/test_sandbox.cpp` under ThreadSanitizer |
| No secret survives in memory after its owner is destroyed | `tests/crypto/test_crypto.cpp`; the erasure path is a volatile store plus a fence |

## What this library does not claim

These are the limits, stated here because a security component that does not
state them invites the reader to assume it does everything.

* **It is not a defence against an author with write access to the source.** The
  object-capability discipline prevents *defects* — forgery, duplication,
  amplification, use after revocation — not sabotage. Anyone who can add a line
  can declare an `authority` and mint what they like; what they cannot do is
  make the result invisible, because every mint and every decision is recorded
  and every authority is a source-level declaration a reviewer can grep for.
* **It is not a defence against code that ignores the API.** The sandbox
  constrains what code can do *through this library*. A component that holds
  the protected object directly, or that reaches into it with a cast, is
  outside the model. The `protected_object` type makes the value private, which
  raises the cost of doing that to writing a deliberate, reviewable lie.
* **It is not a cryptographic library.** The hash and the MAC are correct and
  vector-verified; they are not hardened against cache-timing attacks on the
  message schedule, and they are not a substitute for a vetted library in a
  system that needs one. They exist because a capability model needs a binding.
* **It is not a key-management system.** Where an enrolment key comes from, how
  it is provisioned and how it is rotated is the caller's problem. The library
  makes verification unfoolable once a key is in hand; it does not get the key
  there.
* **It is not a side-channel-hardened implementation.** The constant-time
  primitives are constant-time in the sense that their control flow and their
  memory access pattern do not depend on secret data, with one measured
  counterexample-free spread. They have not been analysed against power
  analysis, fault injection, or a microarchitectural attacker with the ability
  to run co-resident code.
* **It is not deployed.** Version 0.1.0 has no production history. The test
  suite is the evidence, and the test suite is a finite thing written by one
  person.

## Supported versions

The project is at 0.1.0; there are no maintained release branches yet. Fixes
land on `main`.

## Compiler support and its consequences

The guarantees are strongest on GCC 16, which implements the three dialect
features the library is built on. One of them is required and two are optional.

**Required: P2573 deleted functions with a message** (`= delete("reason")`,
`__cpp_deleted_function >= 202403L` — GCC 15+ and Clang 19+; **MSVC does not
implement it** as of 19.51 / Visual Studio 18, so this library does not build
there, and the CI job asserts that it does not rather than implying it might).
The
diagnostics are the library's user interface: every operation that a state, a
policy or a capability forbids is rejected by a sentence saying which one. On a
compiler without the feature that degrades to "no matching function" and a page
of candidates, which is why `config.hpp` refuses to compile rather than letting
the suite's negative half quietly stop asserting anything.

The two optional features are probed, and the library degrades — visibly, and
without losing the rejections — when they are absent:

| Configuration | What changes |
| --- | --- |
| Contracts on (GCC 16) | A violated invariant is reported with the compiler's own diagnostic, which names the condition and the function |
| Contracts off | The same facts are checked by the portable fallback, through the same report and the same abort; only the *classification* differs (`pre`/`post` become `assertion`) |
| Reflection on | `resource_kind_count` is derived from the enumeration, and the policy exhaustiveness check cannot drift from it |
| Reflection off | `resource_kind_count` is a hand-maintained constant, and the test suite asserts it agrees with reflection in every build that has reflection — so the fallback is verified where it can be, rather than assumed everywhere |

`ctest --preset portable` runs the same suite, including all eighteen
compile-failure cases, in the configuration without either optional feature. If
a guarantee held only in the reference configuration, that preset is where it
would show up.

What has been *run*, as opposed to argued: GCC 15 and GCC 16 on Linux, both
configurations, plus the sanitizer configurations. Clang, AppleClang and MSVC
are covered by CI jobs and have not been run on the machine this was developed
on; `docs/testing.md` lists that under its known gaps rather than in a footnote.
