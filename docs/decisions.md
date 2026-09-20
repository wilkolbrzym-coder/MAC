# Decisions

Each entry states the decision, the alternatives that were considered, and the
consequence — including the ones that are costs. A decision recorded without its
cost is a decision that will be revisited by someone who cannot see why it was
made.

---

## D1 — Compile-time policy evaluation, not a run-time policy table

**Decision.** Policies are C++ types; `evaluate<Policy, Principal, Resource,
Action>()` is `consteval`; a denied request is a compile error.

**Alternatives.** (a) A JSON or YAML policy loaded at start-up. (b) A C++ table
of rules evaluated at run time. (c) A policy DSL with a parser.

**Why not.** All three are configuration surfaces, and a configuration surface
is something that can be wrong in production in a way no test catches, because
the test runs with the right configuration. A wildcard rule nobody re-read after
a new resource was added is the classic failure, and it is invisible: the
request is granted, the operation succeeds, and nothing anywhere says that a
rule nobody intended matched it.

**Consequence, and the cost.** A policy cannot be changed without a rebuild, and
`authorize` cannot be handed a resource or an action computed at run time. A
system that genuinely needs run-time policy variation would have to express the
*set* of policies it might select as compile-time values and choose between them
at run time — which is possible but is not what this library does, and a caller
who needs it should know that before adopting it.

---

## D2 — Capabilities are affine (move-only)

**Decision.** `capability` deletes its copy operations. Duplication requires
`delegate`, which requires `grant`.

**Alternatives.** (a) Copyable capabilities with a reference count. (b)
Copyable and unrestricted, with delegation uncontrolled.

**Why not.** A copyable capability makes "how many copies exist, and who holds
them" unanswerable, and that is precisely the question an incident asks. Making
`delegate` the only route to a second capability turns it into a source-level
event that a reviewer can find.

**Consequence, and the cost.** Capabilities cannot be stored in a `std::vector`
by copy, cannot be captured by value in a lambda that outlives them, and cannot
be used in any interface that takes its argument by value and needs to keep it.
Every one of those becomes a move or a `delegate`, which is the intended
friction — but it is friction, and code that wants a capability table has to
build one explicitly.

---

## D3 — Revocation by epoch, not by list

**Decision.** Each resource type has one epoch. A capability records the epoch
it was minted in; `revoke_all<Resource>()` is one atomic increment; the gate
compares for equality.

**Alternatives.** (a) A revocation list of capability serials, consulted per
admission. (b) A per-capability "revoked" flag. (c) Reference-counted
capabilities with a shared cell.

**Why not.** (a) makes every admission a lookup whose cost grows with the number
of revoked capabilities — a denial-of-service lever. (b) requires every holder's
copy to be reachable, which an uncopyable token deliberately makes impossible.
(c) reintroduces shared mutable state on the path an attacker drives.

**Consequence, and the cost.** Revocation is all-or-nothing per resource:
revoking one holder's capability revokes every holder's, for that resource.
Per-holder revocation would need a per-holder epoch, which is a larger design
(a principal-indexed epoch table) and was not chosen, because in an incident the
question is "stop everything touching this resource now" and an O(1) answer to
that is worth more than a fine-grained answer that takes thought to apply.

---

## D4 — Two questions, two mechanisms

**Decision.** The policy answers "may this principal do this at all" at compile
time; the capability answers "does this holder hold the right, now" at run time.
`gate::admit` demands both.

**Alternatives.** (a) Capabilities alone, with no policy (pure object-capability
style). (b) A policy alone, with no capabilities (role-based access control).

**Why not.** (a) has no answer to "this rule exists for a reason" — an authority
that mints a capability grants everything it can mint. (b) has no answer to
"which of these two administrators is acting", and possession, which is what
makes a stolen token dangerous, is not represented at all.

**Consequence, and the cost.** Every protected operation takes two arguments
that mean different things, and a caller has to understand both. The
`protected_object` API makes that visible at every call site — which is the
point, and it is verbose.

---

## D5 — The library owns `handle_contract_violation`

**Decision.** The library defines the P2900 violation hook (weakly), produces a
structured report, offers an observer hook, and aborts.

**Alternatives.** (a) Leave it to the consumer; the missing definition is a link
error. (b) Define it strongly. (c) Use the compiler's default handler.

**Why not.** (a) makes the first build of any consumer fail with a link error
about a symbol they have never heard of, and the natural fix is to define the
weakest possible handler. (b) is a duplicate-symbol error from two translation
units onwards. (c) gives no way to route a violation into an audit trail before
the process dies, which is the requirement that "fail stop **and** leave a
record" states.

**Consequence, and the cost.** A `#pragma`-free but compiler-specific mechanism
(`__attribute__((weak))`) is used, with a documented fallback for toolchains
that lack it. The alternative was requiring consumers to define the hook, which
trades a portability footnote for a footgun.

**Finding.** `inline` does not work here, and the failure is silent: the
compiler emits an *undefined* reference to the hook and never emits the inline
definition, so the program links against the standard library's default instead
— replacing the library's reporting and observer hook with no diagnostic at all.
It was caught by a test asserting the report text, not by a link error.

---

## D6 — Deny by default, with exhaustiveness asserted

**Decision.** `evaluate` returns `allow` only when a rule matches, and `policy`
asserts in its own body that every enumerator of `resource_kind` has a rule.

**Alternatives.** (a) Allow by default. (b) Deny by default without the
exhaustiveness assertion.

**Why not.** (a) is not a design anyone would defend, but it is what "no rule
matched, so carry on" amounts to, and it appears whenever a rule is deleted and
the deletion is not noticed. (b) is safe in the sense that nothing is
accidentally permitted, and it is unsafe in a worse way: the new resource is
silently unusable, and the failure appears as a support ticket rather than as a
build error.

**Consequence, and the cost.** Adding a resource kind to a program forces a
policy rule in the same commit, and the diagnostic names the resource that is
missing one. The cost is that a resource which is *deliberately* unmediated
cannot exist inside the enumeration — it has to be modelled differently, which
is arguably the right answer anyway.

---

## D7 — The audit trail never fails

**Decision.** A fixed-size ring; a full trail overwrites the oldest record and
counts the loss.

**Alternatives.** (a) A growable log. (b) Refuse to record when full, and
therefore refuse the operation. (c) Drop silently.

**Why not.** (a) allocates on the path an attacker drives, and an allocation
failure becomes a security decision. (b) turns a full log into a denial of
service, and the attacker controls the flood rate. (c) makes every later
statement about the trail unsound.

**Consequence, and the cost.** The trail is bounded at 256 records, and under
sustained load the interesting record may be overwritten before anybody reads
it. The `dropped()` counter is what keeps that visible, and the mitigation for a
real deployment is the observer hook on the contract path plus an external
collector — which is the caller's job, not the library's.

---

## D8 — No exceptions anywhere in the library

**Decision.** Fallible operations return `result<T>`; broken invariants abort.

**Alternatives.** (a) Exceptions for domain errors. (b) Exceptions for
invariants (a "logic_error" style). (c) `errno`-style out-parameters.

**Why not.** (a) makes the failure part of the *dynamic* type rather than the
static one, so a `catch (...)` somewhere up the stack can swallow a security
decision — the exact failure this library exists to prevent. (b) invites the
same swallow, and adds a type to every signature for a condition that has no
handler. (c) is what happens when a language has no sum types; C++ has them.

**Consequence, and the cost.** Every fallible call site has to handle the error
or propagate it with `META_AUTH_TRY_*`, and a caller who genuinely wants
exception-based error handling has to write the adapter. A side effect worth
noting: nothing in the library throws, so it should compile with exceptions
disabled (`-fno-exceptions`). That is a property a project like this would
normally claim, and this one does not, because no preset exercises it — see
*Known gaps* in `docs/testing.md`.

---

## D9 — The trust store is compile-time

**Decision.** `trust_store<sha256_digest...>` takes the digests as non-type
template parameters. Enrolling a device is a source change.

**Alternatives.** (a) A file of trusted digests loaded at start-up. (b) A
directory of certificates. (c) A network trust service.

**Why not.** Every one of them is a trust decision that can be changed on the
device, which is the definition of a trust anchor that is not an anchor: the
whole point of the digest is that it is the thing the device cannot alter. If
the list can be altered, an attacker who can write to the device writes to the
list.

**Consequence, and the cost.** Adding a device requires a rebuild and a
redeploy, which is unacceptable for a fleet that grows continuously — such a
deployment needs an intermediate: a compile-time anchor for a *provisioning*
authority, and a run-time store signed by it, which is a design this library
does not provide and a caller would have to build. That is a real limitation,
and it is the first thing to address in a 0.2.

---

## D10 — No dependencies, including in the tests

**Decision.** The library and its test harness have no third-party dependencies.
The harness is ~350 lines and is itself tested.

**Alternatives.** GoogleTest, Catch2, doctest for the tests; a vetted crypto
library for the hash.

**Why not.** For the harness: the repository's central claim is about what
compiles, and a suite that pulls in a framework makes "no dependencies" false
exactly where it is checked. For crypto: a vetted library is the right answer
for a system that needs one, and this is not that system — the hash exists
because a capability model needs a binding, and the header says so.

**Consequence, and the cost.** The harness has fewer features than a mature
framework (no parameterised fixtures, no death-test support beyond what CTest
gives, no XML output), and the SHA-256 implementation is a thing a reviewer has
to read rather than trust. The `docs/threat-model.md` non-goals say plainly that
this is not a cryptographic library and should not be the only thing between an
attacker and a system.
