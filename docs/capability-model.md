# The capability model

## What a capability is here

A capability is a value that *is* the authority to use a resource — not a claim
about authority, not a reference to a permission record, not a name that a
lookup resolves. In this library it is `capability<Resource, Rights>`:

```cpp
template <typename Resource, rights_set Rights>
class capability {
public:
    static constexpr rights_set rights = Rights;      // part of the type
    capability(const capability&) = delete;           // affine
    capability& operator=(const capability&) = delete;
    // ...
private:
    template <typename, rights_set> friend class capability;
    template <typename, rights_set> friend class authority;
    constexpr capability(std::uint64_t serial, revocation_epoch epoch,
                         std::optional<std::uint64_t> parent) noexcept;
};
```

Three things follow from that definition, and they are the whole model.

### 1. It cannot be forged

The only constructor is private, and the only route to it is `authority`, whose
`mint<Requested>()` is constrained by `Requested ⊆ MaxRights`. There is no
conversion from an integer, a string, or a serialised form, because there is no
serialised form. A program that tries to build one gets:

```
error: no matching function for call to
  'meta_auth::capability<...>::capability()'
```

`tests/compile_fail/capability_construct.cpp` pins that.

### 2. It cannot be duplicated

Copy construction and copy assignment are deleted. To obtain a second
capability, a holder must call `delegate<Smaller>()`, which requires the
`grant` right *and* requires `Smaller ⊆ Held`. So "how many copies of this
authority exist, and who holds them" is a question with an answer that a
reviewer can find in the source: every copy is a `delegate` call, and every
`delegate` call is a place where a holder decided to hand authority on.

`attenuate<Smaller>() &&` is the other direction: it *consumes* the capability
and returns a weaker one. The holder keeps the weaker authority and loses the
stronger, which is what makes "attenuation cannot be undone" a fact about the
value rather than a rule about the API.

### 3. It is monotone

`delegate` and `attenuate` are constrained by the lattice relation, so a
capability stronger than the one held is not an error condition — it is an
overload that does not exist, reported by a `= delete("...")` declaration that
names the missing right. The four cases are pinned by
`tests/compile_fail/capability_amplify.cpp`,
`capability_delegate_without_grant.cpp`, `capability_delegate_beyond_held.cpp`
and `authority_mint_beyond_max.cpp`.

## The monotonicity argument

Let `H(p)` be the rights a principal `p` holds. The claim is that every
operation on a capability either leaves `H` unchanged or lowers it.

* `mint<Requested>()` requires `Requested ⊆ MaxRights` of the authority, so the
  new capability adds nothing beyond what the authority already had.
* `attenuate<Smaller>() &&` requires `Smaller ⊆ Held` and consumes the source,
  so `H` becomes `Smaller`.
* `delegate<Smaller>()` requires `Smaller ⊆ Held` *and* `grant ∈ Held`, and does
  not consume the source, so `H` gains a holder with `Smaller` while the
  delegator keeps `Held`. The union of reachable authority grows in the number
  of holders, never in rights.
* `revoke_all<Resource>()` advances the epoch, which empties `H` for every
  capability minted before it — a strict decrease.
* There is no fifth operation. A capability can be inspected (`has`, `rights`,
  `serial`, `epoch`), presented to a gate, or destroyed.

The induction is over the operations, and the base case is `authority`, which
is a source-level declaration. That is the honest statement of the model's
strength: **the argument holds for every program that obtains its capabilities
through this API**, and the API is the only way to obtain one in a program that
does not deliberately reach around it (see B2 in `docs/threat-model.md`).

## Why the lattice matters

A policy that says "an operator may modify devices" and a capability that says
"this holder may read devices" are two different questions, and conflating them
is the classic authorisation bug: the request is *authorised* and the holder is
not *permitted*, and a system that checks only the first grants it.

The two answers live in different places on purpose:

| Question | Answered by | When |
| --- | --- | --- |
| May this principal do this to this resource at all? | `policy` + `authorize` | compile time |
| Does this particular holder hold the right, now? | `capability` + `gate::admit` | run time |

`gate::admit` demands both, so neither alone is enough. The compile-time half is
a *proof value* (`authorization<Resource, Action>`), which means a protected
operation cannot be called without it, and the run-time half is a value the
caller must possess, which means possession cannot be simulated.

## Revocation

An uncopyable token has no list to remove an entry from, because the holder's
copy *is* the only record. The mechanism is an epoch:

```cpp
template <typename Resource>
revocation_epoch revoke_all() noexcept;   // one atomic fetch_add
```

Every capability records the epoch it was minted in; the resource has one
current epoch; the gate compares them for equality. Three consequences:

* revocation is O(1) regardless of how many capabilities exist, and does not
  touch any holder;
* a stale capability is **rejected**, not invalidated — it remains a valid
  value, so the rejection is a decision that can be reported and audited rather
  than the capability silently ceasing to work;
* equality rather than `>=` is deliberate. An epoch *ahead* of the current one
  did not come from this resource's counter, and treating it as valid would let
  an attacker bypass revocation by inventing a value.

The epoch slot is a function-local static per resource type, so a lookup is one
acquire load and there is no table to size, scan or lock.

## What the model does not give you

* **Freshness.** A capability says what it grants; it does not say when it was
  last used or by whom. Sessions carry an identifier and an epoch for that, and
  the audit trail records every presentation.
* **Confidentiality of the resource.** A capability is authority, not
  encryption. A holder that can read a resource reads it.
* **Transfer prevention.** Capabilities are bearer tokens: whoever holds one can
  use it. The model's protection is that handing one on requires `grant` and is
  recorded, not that it is impossible.
* **Revocation of a *specific* holder.** `revoke_all` invalidates every
  capability for a resource. Per-holder revocation would need per-holder
  epochs, and the design chose the coarse mechanism because the coarse one is
  the one that can be reasoned about in an incident.
