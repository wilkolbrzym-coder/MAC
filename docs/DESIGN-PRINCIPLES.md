# Design principles

This document is the charter of `meta-auth-core`. It states what the library
commits to, why, and — the part that makes it a charter rather than a wish list
— **how each commitment is enforced mechanically**. A principle that is only
documented is a principle that will be violated by the next contributor in a
hurry; a principle that breaks the build is one that will not.

The principles are ordered by how much they constrain the API. When two of them
conflict, the lower-numbered one wins.

---

## P1 — Authority is held, never assumed

**Commitment.** There is no ambient authority anywhere in the library. Every
operation that touches a mediated resource takes the authority to do so as an
explicit, typed argument. Code that does not hold the authority cannot express
the call.

**Why.** Ambient authority is what makes the confused deputy possible: a
component checks a caller's identity and then acts using *its own* privilege,
so any caller that can reach the component inherits that privilege. When the
privilege must be passed in, a component can only do what it was handed the
right to do, which is exactly the property an operating-system sandbox cannot
give you inside one address space.

**Enforcement.** Protected objects expose no public accessor that does not take
a `capability`. The capability's constructors are private; `authority` is the
only minting path and is not copyable. Tests assert the negative direction:
`tests/compile_fail/` contains programs that try to reach the object directly
and are required to fail with a specific diagnostic.

---

## P2 — Attenuation is the only direction of travel

**Commitment.** A capability can be weakened, split, or handed to someone else
in a weaker form. It can never be strengthened, and it can never be delegated
by a holder that does not itself hold the right to delegate.

**Why.** This is the monotonicity property that makes the object-capability
model decidable in practice: the set of rights reachable from a principal is a
monotonically non-increasing function of the operations performed on it. If
amplification were possible, every reachable-rights argument would have to be
re-derived by hand at each call site.

**Enforcement.** Delegation is a constrained template: the requested rights are
a template argument, and the `requires` clause demands
`requested ⊆ held ∧ grant ∈ held`. A program that asks for more fails overload
resolution and receives a `= delete("...")` diagnostic naming the missing
rights. Property tests enumerate the full rights lattice (128 subsets is small
enough to be exhaustive) and assert reflexivity, antisymmetry, transitivity and
the absence of an amplification path.

---

## P3 — Deny by default, and prove the default is total

**Commitment.** A request that no rule matches is denied. Every declared
resource must have at least one rule, and every rule must be reachable.

**Why.** "Deny by default" is easy to write and easy to defeat: adding a new
resource to an enumeration and forgetting to extend the policy silently creates
a resource that is either unreachable or, worse, covered by a wildcard nobody
re-read. The failure is invisible because nothing fails.

**Enforcement.** The policy is a compile-time value. A reflection pass
enumerates the resource enumeration and the policy's rules and `static_assert`s
that the two are in bijection. Adding an enumerator without a rule is a build
failure with a diagnostic that names the missing resource — not a code-review
comment, not a coverage gap.

---

## P4 — Make the illegal state unrepresentable, not merely unreachable

**Commitment.** Where a state machine exists, the states are types. An
operation that is meaningful only in one state exists only in that state. The
"you cannot do this yet" case is a compile-time diagnostic, and it is phrased
as a sentence a developer can act on.

**Why.** A boolean `authenticated` flag admits an exponential number of states,
of which a handful are legal. Type-state reduces the legal states to the ones
that exist. Erring on the side of *unrepresentable* also removes an entire
category of test: there is no test for "elevate a session that is not
authenticated", because the call does not typecheck — only a negative
compilation test that proves it stays that way.

**Enforcement.** State-carrying types are class templates; the transitions are
the only members that produce the next state; forbidden transitions are
declared `= delete("...")` with a message that names the required state and the
operation that reaches it. Every deleted transition has a compile-failure test
pinning its diagnostic.

---

## P5 — Compile time is free; run time is not

**Commitment.** Anything that can be computed from the policy, the identities
and the device descriptors is computed before `main` starts. What remains at
run time is the part that genuinely depends on run-time input, and it is
written to fail closed and fail stop.

**Why.** A compile-time decision cannot be misconfigured in production, cannot
be skipped by a code path that forgot to call it, and cannot be turned off by
an environment variable. It also makes the run-time surface small enough to
audit: everything left is a bounded, allocation-free, exception-free check.

**Enforcement.** Cryptographic digests, policy evaluation, capability tables
and attestation comparisons used with compiled-in trust anchors are `consteval`
or `constexpr`. The suite asserts this: the same functions are evaluated in
`static_assert`s, so a change that makes them non-constant fails to build.

---

## P6 — Secrets are treated as a lifetime, not as a value

**Commitment.** A secret has a beginning, a period of use, and an end that is
explicit in the code. Comparison of secrets is constant time. Storage is
zeroed on destruction, and the zeroing is not something the optimiser may
remove.

**Why.** Copying a key into a `std::string` puts it in a heap block that may be
reallocated, swapped, and left in freed memory; comparing it with `==` leaks
its prefix through timing. Both defects are invisible at the call site, and
both are demonstrated in the test suite rather than asserted in prose.

**Enforcement.** Secret types are non-copyable and non-swappable by default,
`secure_erase` uses a barrier the optimiser must honour, and `constant_time_eq`
is tested against timing-independent properties (the result depends only on
whether the inputs are equal, never on *where* they differ).

---

## P7 — Fail stop, and leave a record

**Commitment.** A violated invariant terminates the process. It does not throw,
it does not return an error, and it does not continue in a degraded mode. The
violation is recorded — in a fixed-capacity, allocation-free trail that a
supervisor can read — before the process ends.

**Why.** The alternative to failing stop is failing quiet, and a security
component that continues after its invariants are broken is the definition of a
vulnerability. Recoverable *domain* errors (wrong credential, expired
attestation) are values, because callers must handle them; broken *invariants*
(an impossible state, an out-of-range span) are not the caller's business and
must not be silently survivable.

**Enforcement.** Invariants are contract assertions; the library installs its
own `handle_contract_violation` so that the report is structured and audited
before `abort()`. The distinction between a domain error and an invariant is
stated at each API in `docs/contracts.md`, and the fail-stop path is tested by
a test that is expected to die.

---

## P8 — The tests are part of the interface

**Commitment.** Every claim in this document has a test that fails when the
claim stops being true. Claims about programs that must *not* compile are
tested by compiling them and inspecting the diagnostic, not by commenting them
out.

**Why.** A security library whose guarantees are only checked by the compiler
has no way to notice when a compiler upgrade, a flag change, or a refactor
removes them. The compile-failure suite is the only mechanism that distinguishes
"this is rejected" from "this is rejected *for the reason we documented*".

**Enforcement.** The suite is organised by the kind of claim it makes — unit,
property, concurrency, compile-failure, dialect — and CI runs the full matrix
of presets, including the one where the optional dialect features are off, so
that the degraded configuration is a tested configuration rather than an
untested assumption.

---

## Non-goals

Stating these is as important as stating the commitments:

* **Not a cryptographic library.** The hash and MAC exist because the capability
  model needs a digest and a binding, and they are implemented to be
  correct-under-scrutiny rather than fast. They are not side-channel hardened
  beyond constant-time comparison, and they are not a substitute for a vetted
  crypto library in a system that needs one.
* **Not a key-management system.** The library consumes trust anchors; where
  they come from, how they are provisioned and how they are rotated is the
  caller's problem.
* **Not a sandbox in the operating-system sense.** The sandbox is a
  *capability* sandbox inside one address space. It constrains what code can
  do through this library's API; it does not constrain code that ignores the
  API, and it is not a defence against an attacker who already has arbitrary
  code execution in the process.
* **Not a policy language.** Policies are C++ declarations compiled into the
  binary. There is deliberately no parser, no configuration file and no
  run-time policy loading, because all three would reintroduce the
  misconfiguration surface the design exists to remove.
