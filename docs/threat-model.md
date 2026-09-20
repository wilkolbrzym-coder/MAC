# Threat model

A security component that does not say what it does not defend against invites
its reader to assume it defends against everything. This document is the
opposite of that: what is in scope, what is out, and which artefact supports
each claim.

## Assets

| Asset | Where it lives | What protects it |
| --- | --- | --- |
| The authority to act on a resource | `capability<Resource, Rights>` values | unforgeable, affine, monotone, epoch-bound |
| Enrolment keys | `device_key`, `secret_buffer` | not copyable, erased on destruction, compared in constant time |
| Credentials | `credential_record<Principal>` | only a MAC of the secret is stored, keyed by the principal |
| The record of what happened | `audit_trail` | written before the decision is returned; overwrites are counted |
| The protected values themselves | `protected_object<T, Resource>` | private; the only accessors demand a capability and a proof |

## Adversaries in scope

### A1 — A remote device that lies

The device sends a descriptor and an attestation. It may claim another device's
identity, describe itself as something it is not, replay a genuine attestation
with a modified descriptor, or present a tag it guessed.

**Defended by.** The verifier re-hashes the descriptor it was given, so a claim
and a description cannot disagree (`descriptor_mismatch`); the MAC is compared
in constant time, so the number of guesses an attacker gets is the number of
attempts, not the number of bytes (`constant_time_equal`); and the digest is
looked up in `trust_store`, which is a compile-time value, so a device that is
not enrolled cannot be trusted however good its proof is.

**Evidence.** `tests/identity/test_identity.cpp`, including all 256 single-bit
forgeries of a genuine tag, and the demo's steps 2 and 3.

### A2 — A caller with a capability it should not have

The caller holds a valid capability and asks for something it does not grant,
or holds one that has been revoked, or tries to make a stronger one.

**Defended by.** The gate checks `required_right(Action)` and the epoch before
doing anything; `attenuate` and `delegate` are constrained by `requires`, so
amplification does not compile; `delegate` additionally requires `grant`, so a
holder cannot manufacture authority for a third party.

**Evidence.** `tests/sandbox/test_sandbox.cpp` for the run-time half;
`tests/compile_fail/capability_*.cpp` (5 cases) for the compile-time half.

### A3 — A caller that has no authority at all

The caller has no capability and looks for a way to act anyway: forging one,
copying someone else's, or talking a privileged component into using its own.

**Defended by.** Capabilities cannot be constructed (private constructor, no
friend but `authority`), cannot be copied (deleted copy operations), and cannot
be obtained from a serialised form (there is no such form). The confused deputy
is addressed structurally: `gate` holds no authority of its own, and
`protected_object`'s accessors take the capability as a parameter, so a
component can only do what it was handed authority for.

**Evidence.** `compile_fail/capability_construct.cpp`,
`compile_fail/capability_copy.cpp`, and the deputy case in
`tests/sandbox/test_sandbox.cpp`.

### A4 — A caller that races the checks

The caller tries to make the world change between a check and the use: revoke
after a capability was admitted, mutate an object between validating it and
acting on it.

**Defended by.** The gate performs the rights and epoch checks immediately
before returning, and the operation that follows is on the protected object
whose value is private. The epoch is read with acquire semantics from an atomic
slot, and `revoke_all` is one `fetch_add`, so a concurrent revocation either
happens before the check or after it — never halfway.

**Evidence.** `tests/capability/test_revocation.cpp` asserts that concurrent
revocations all take effect (a load-then-store would lose them); the whole
suite runs under ThreadSanitizer in CI.

### A5 — A caller that attacks the log

The caller tries to make a denial unrecorded, or to make the record useless: by
flooding the trail, by reading a half-written entry, or by making the log an
availability problem.

**Defended by.** The trail never fails: it overwrites the oldest entry and
counts the loss, so a flood cannot make a later decision unrecorded and cannot
turn a full log into a denial of service. Each slot is stamped before and after
its fields, and a reader that sees a torn record skips it rather than reporting
a mixture. Records store hashes rather than pointers, so a record cannot dangle.

**Evidence.** `tests/sandbox/test_sandbox.cpp`, including the full-ring case
that asserts both the retention and the dropped count, and 1600 concurrent
records whose snapshot is checked for torn entries.

## Adversaries out of scope

### B1 — An author with write access to the source

Anyone who can add a line can declare `authority<Resource, rights_set::all()>`
and mint what they like. The model prevents *defects*, not sabotage, and it
does not pretend otherwise. What it does give a reviewer is that authority is
*source-visible*: a search for `authority<` finds every place the program
decided to be able to do something, and every mint is recorded with a serial.

### B2 — Code that ignores the API

The sandbox constrains what code does *through this library*. A component that
holds the protected object, that casts it, or that links its own implementation
of the same header is outside the model. `protected_object`'s value is private
and `capability`'s constructors are private, which raises the cost of bypassing
to writing a deliberate, reviewable act — but a determined author can write it,
and nothing here stops them.

### B3 — A compromised platform

If the attacker controls the process's memory, the keys in it, or the clock, the
model is not a defence. The library assumes a platform that executes its code
and keeps its memory private; it does not detect a hostile one. It has no
mechanism against memory disclosure, fault injection, or a debugger.

### B4 — Microarchitectural side channels

Constant-time in this library means *control flow and memory access patterns do
not depend on secret data*, with one measured spread reported by
`benchmarks/`. That is not the same as resistance to a motivated side-channel
attacker with cache-co-residency or power measurement, and no claim is made
that it is. In particular:

* SHA-256 is not constant time and is not claimed to be. It hashes public data;
  the MAC is applied to public data under a secret key;
* the constant-time comparison's bound (25% of the fastest measurement) is a
  smoke test that catches a return-to-early-exit regression. It is not a
  side-channel analysis, and passing it does not prove the absence of one.

### B5 — Availability

The library is not a denial-of-service defence. `revoke_all` is cheap and
anyone who can call it can invalidate every capability for a resource; the
policy engine will happily authorise a rule that makes a resource unusable; the
audit ring overwrites. These are deliberate: each one is a decision an operator
should be able to make quickly, and making them expensive would make them
unusable in the situation where they matter most.

### B6 — Key management

Where an enrolment key comes from, how it is provisioned, stored, rotated and
destroyed is out of scope. The library starts from "a key is in hand, of the
right length, and not all zeroes" — it checks that much, because a
misconfigured keystore returns zeroes and a device attesting under a key
everybody knows is worse than one that fails to attest — and it ends at
"verification is unfoolable".

## Attacks that are not attacks here

Worth stating, because each is a plausible-sounding objection:

* **Replay of an attestation.** The attestation binds the descriptor, and the
  descriptor is what the policy is about. A replayed attestation asserts the
  same facts as the original; the freshness question is a session-level
  property (the session's epoch and identifier) rather than a property of the
  proof.
* **Guessing a serial number.** Serials are allotted from a per-resource atomic
  and are visible in the audit trail. They identify a capability; they do not
  authenticate one, and knowing one grants nothing, because a capability cannot
  be constructed from it.
* **Revoking a capability the attacker does not hold.** `authority` declares
  who may revoke — the policy's `revoke` rule on the resource — and the gate
  records every revocation. A caller who can revoke was given the right to.

## Reviewing this model

If you are looking for holes, these are the places to look, in the order that
seems most likely to pay off:

1. **`gate::admit`** — the only place that checks rights and epochs. A path that
   reaches a protected value without it is a hole; `protected_object`'s value is
   private, so such a path has to be a deliberate bypass (B2).
2. **The epoch protocol** — `epoch_is_current` uses equality, so an epoch ahead
   of the current one is rejected. If that ever became `>=`, inventing an epoch
   would bypass revocation.
3. **The transition constraints** — every `requires` clause on a session
   transition, `attenuate` and `delegate`. Each has a compile-failure test; a
   constraint that was loosened without deleting the test's expectation file
   would be caught, and one loosened *with* the expectation deleted would be
   visible in the diff.
4. **The trust store** — if membership ever became a run-time lookup, enrolling
   a device would become a configuration change rather than a source change,
   and the property that a device cannot talk its way in would be gone.
