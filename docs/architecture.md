# Architecture

## The shape of the thing

Six layers, each depending only on the ones above it in this list:

```
  core/         errors and results, contracts, structural strings, identifiers
    |
  crypto/       SHA-256, HMAC-SHA256, constant-time primitives, erasure
    |
  capability/   rights lattice, capabilities, authorities, revocation epochs
    |
  identity/     principals, device descriptors, trust anchors, attestation
    |
  auth/         type-state sessions, credentials, the policy engine
    |
  sandbox/      audit trail, mediation gate, protected objects
```

The dependency direction never reverses. `capability` does not know that
sessions exist; `auth` does not know that an audit trail exists; nothing knows
about `sandbox` except `sandbox`. That is not a stylistic preference — it is
what makes each layer's guarantees statable without reference to the layers
above, which is what makes them checkable.

The library is header-only and has no dependencies, so the diagram is also the
include graph: `#include "meta_auth/sandbox/gate.hpp"` pulls in everything
below it and nothing else pulls in `sandbox`.

## What each layer is responsible for

### `core/` — the vocabulary

`auth_error` is a closed enumeration of every domain error, with a stable
numeric code and a name; `result<T> = std::expected<T, auth_error>` is how a
fallible operation reports. The distinction the layer encodes is the one the
whole design rests on:

* a **domain error** is something the caller must handle — a wrong credential,
  a device that failed attestation, a capability that was revoked. It is a
  value, and it is part of the function's type.
* a **broken invariant** is not the caller's business — an impossible state, a
  descriptor that does not fit its buffer. It is a contract assertion, and it
  terminates the process.

`contract.hpp` provides both forms of contract (declarator `pre`/`post` and
statement `contract_assert`) with a portable fallback that produces the *same
report and the same abort*, and installs the library's own
`handle_contract_violation` so that a violation is structured and observable
before the process dies.

### `crypto/` — bindings

`sha256` and `hmac_sha256` are `constexpr`, so a digest can be a compile-time
constant and a trust anchor can be a template argument. They are verified
against the FIPS 180-4 and RFC 4231 vectors by `static_assert`.
`constant_time_equal` and `constant_time_select` are the primitives that keep a
comparison from leaking where two values differ. `secure_erase` and
`secret_buffer` are the primitives that keep a secret from surviving its owner.

### `capability/` — authority

`rights_set` is a lattice element; `capability<Resource, Rights>` carries its
rights in its *type*, so what a capability grants is a compile-time fact. The
constructor is private and `authority` is the only route to one, so a capability
cannot be forged; copy operations are deleted, so it cannot be duplicated
except through `delegate`, which requires `grant`. Revocation is an epoch per
resource type, and `revoke_all<Resource>()` is one atomic increment that
invalidates every capability minted before it.

### `identity/` — who

`principal<Name, Kind>` makes a principal a type and binds its kind into its
identity. `device_descriptor` is what a device says it is, encoded canonically
with length prefixes so that two different descriptors cannot encode
identically; its digest is the device's identity. `trust_store<digests...>` is a
compile-time set of trusted identities, so a device that is not in it cannot be
trusted whatever it sends. `attest`/`verify_attestation` are the two halves of
the proof.

### `auth/` — may

`session<Principal, State>` is the type-state machine: an operation that is
meaningful only in one state exists only in that state, and a transition that
is illegal is a `= delete("...")` declaration rather than a run-time check.
`policy<Rules...>` is a compile-time value that asserts its own exhaustiveness,
and `evaluate<Policy, Principal, Resource, Action>()` is a `consteval` decision.
`authorization<Resource, Action, Principal>` is the proof: opaque, move-only,
non-trivially-copyable (so `std::bit_cast` cannot fabricate one), and obtainable
only through `authorize`, which is where the decision is made. It carries the
principal it was issued for, and `gate::admit` takes that principal in the same
position, so a proof cannot be presented under another identity.

### `sandbox/` — how

`audit_trail` records every decision in a fixed ring of stamped slots, without
allocating and without failing. `gate<Resource>::admit` is the mediation point:
it demands a policy proof (compile time) and a capability (run time), checks the
right and the epoch, and records the outcome before returning it.
`protected_object<T, Resource>` is a value whose only accessors take both.

## The path of one operation

```
  caller                     gate                        trail
    |                         |                            |
    | authorize<P,R,A>()      |                            |
    |---- consteval --------->|  (denied -> does not compile)
    |  authorization proof    |                            |
    |                         |                            |
    | admit<A>(capability, proof)
    |------------------------>|                            |
    |                         | has(required_right(A))?     |
    |                         | is_live()?                  |
    |                         |---------------------------->| record(decision)
    |<------------------------|                            |
    | status                  |                            |
```

Two properties of that picture are the design:

* the policy decision happens **before** the call, in the compiler, and a
  denial never reaches the gate;
* the record is written **before** the caller learns the outcome, so a crash
  between the two leaves the evidence rather than the act.

## The other path: an operation that is refused

```
  caller                     gate                        trail
    | admit<A>(weak_capability, proof)
    |------------------------>| capability does not hold right::write
    |                         |---------------------------->| record(denied:insufficient-rights)
    |<------------------------| insufficient_rights
```

The refusal is a value, the capability is unchanged and still usable for what
it does grant, and the denial is on the record with the capability's serial. An
operator reading the trail can tell a permissions bug (rights 0x01 presented for
a write) from a revocation (rights 0x7f, epoch behind) from a forgery attempt
(the MAC did not verify, which never reaches the gate at all).

## Why the layers are in this order

An earlier design had the gate calling into the policy engine at run time, with
the policy held in a table. It was discarded for a reason worth recording: a
run-time policy table is a configuration surface, and a configuration surface
is something that can be wrong in production in a way that no test catches,
because the test runs with the right configuration. Moving the decision into
the compiler removed the surface rather than testing it.

The cost is real and is paid deliberately: a policy cannot be changed without a
rebuild, and `authorize` cannot be called with a request whose resource or
action is computed at run time. That is the trade this library makes, and
`docs/decisions.md` records it as such.
