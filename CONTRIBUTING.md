# Contributing

The library is small, the standard is high, and the two are related: everything
here is meant to be read in one sitting by someone who wants to find a hole in
it.

## Building and testing

```sh
cmake --preset dev               # configure
cmake --build --preset dev       # build
ctest --preset dev               # run everything
ctest --preset dev -L unit       # one group
```

Presets, and when to use each:

| Preset | Use it when |
| --- | --- |
| `dev` | Always. Contracts and reflection on, tests and examples built. |
| `portable` | Before pushing. Both optional dialect features off; the same suite must pass. |
| `asan` | Before pushing a change that touches memory. Address and UB sanitizers. |
| `tsan` | Before pushing a change that touches the audit trail or any of the revocation counters. |
| `bench` | When changing a hot path. The constant-time benchmark gates on its own measurement. |
| `release` | When changing anything that could break at `-O3`; the reference compiler's bounds analysis is more aggressive there. |

## The standard a change is held to

**Every diagnostic is an error.** `META_AUTH_WARNINGS_AS_ERRORS` is on by
default and the warning set is broad. If a warning is a false positive, the fix
is a narrowly scoped suppression with the reproduction written next to it — not
a global `-Wno-`. The two false positives already worked around are documented
in `cmake/MetaAuthWarnings.cmake` and `include/meta_auth/crypto/sha256.hpp`;
they are the model to follow.

**Every claim has an artefact.** If a comment says "this cannot happen", either
a `static_assert` proves it, a test asserts it, or the comment says why it
cannot be checked. A claim with none of those is a comment that will be wrong
within a year.

**Every rejection has a negative test.** If a program is supposed to be
ill-formed, `tests/compile_fail/` contains it, and the expectation file records
the *reason* — the fragment of the diagnostic that states why. Adding one is a
three-step ritual and the ritual is the point:

1. write the program that should be rejected;
2. compile it by hand and read the diagnostic;
3. record the fragment that states the reason.

**Comments explain why.** The code says what it does. A comment that restates
the next line is noise; a comment that records the constraint the code cannot
express — a compiler bug, a reason a simpler approach fails, the attack a check
prevents — is the most valuable thing in the repository.

**Nothing throws, nothing allocates on a path an attacker drives.** Domain
errors are `result<T>`; broken invariants are contract assertions that
terminate. The audit trail and the gate allocate nothing.

## Adding a layer or a type

The order the layers were built in is the order they depend on:
`core` → `crypto` → `capability` → `identity` → `auth` → `sandbox`. A new
component goes in the layer whose dependencies it needs, and the dependency
direction never reverses: `capability` does not know about `auth`, and nothing
knows about `sandbox` except `sandbox`.

A new type earns its place by enforcing something. Before adding one, the
question to answer in the commit message is: *what does this make
unrepresentable that was previously merely checked?* If the answer is "nothing",
it belongs in the layer that already exists.

## Adding a right, an action or a resource

These three enumerations are the vocabulary of the whole library, and each has
a mechanical consequence:

* a new `right` needs an entry in `right_names` and a line in
  `all_right_bits`; the test suite reflects over the enumeration and fails if
  the name table and the bit set disagree;
* a new `action` needs a `required_right` mapping; the test asserts the mapping
  is total and injective;
* a new `resource_kind` needs a `resource_for` specialisation and a policy rule;
  the policy's own `static_assert` names the resource that is missing one, and
  the sandbox test asserts that the policy-layer name and the capability-layer
  name agree.

## Commits

Conventional-commit subjects (`feat(scope):`, `fix(scope):`, `test:`,
`docs:`, `perf:`, `build:`, `chore:`), and a body that answers:

* what changed, in terms of behaviour rather than of files;
* **why this way and not the obvious way**, when there was an obvious way;
* what was verified, with the numbers.

The history is part of the deliverable. A reviewer who wants to know why the
audit trail uses relaxed atomics, or why the constant-token postcondition rule
exists, should be able to read it out of `git log` without asking.

## Formatting

`.clang-format` and `.clang-tidy` are committed and are the authority. The
style is LLVM-adjacent with 100 columns, unindented namespaces, and `snake_case`
functions with `CamelCase` types. Formatting is not a matter of taste here: the
repository is read as a document.
