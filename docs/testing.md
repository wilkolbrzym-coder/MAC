# Testing

## What the suite is for

The library claims that certain programs are *ill-formed*. That claim can only
be checked by trying to compile those programs, and the check has to inspect
*why* the compiler refused, because "it does not compile" is satisfied by a
typo. Every other test in the repository exists to support a claim in
`README.md`, `docs/threat-model.md` or a header comment, and a claim without a
test is a claim this project does not make.

## The groups

| Label | What it asserts | Where |
| --- | --- | --- |
| `dialect` | The compiler configuration is what the rest of the suite assumes | `tests/dialect/` |
| `unit` | One component behaves as documented | one directory per layer |
| `compile_fail` | Eighteen programs stay ill-formed, for the documented reason | `tests/compile_fail/` |
| `concurrency` | Claims about shared mutable state | `tests/capability/test_revocation.cpp`, `tests/sandbox/test_sandbox.cpp` |
| `fail_stop` | Processes that must die in a documented way | `tests/core/CMakeLists.txt`, `tests/framework/CMakeLists.txt` |
| `integration` | The layers wired together | `examples/meta_auth_demo.cpp` |

```sh
ctest --preset dev                  # everything
ctest --preset dev -L unit          # one group
ctest --preset dev -R revocation    # one topic, across groups
./build/dev/bin/meta_auth_capability --filter=attenuate --verbose   # one binary
```

## The harness

`tests/framework/` is a dependency-free runner compiled into every test binary,
so a test source file is a list of cases and nothing else. It is tested like any
other component, because a harness that cannot report a failure converts every
later "all tests passed" into an unsupported claim:

* `framework_selftest` exercises the recording path through an injectable
  failure sink, with an `isolation_guard` that keeps the deliberate failures out
  of the run totals;
* three failure tests assert that a failed `CHECK` exits non-zero and names the
  case, that a failed `REQUIRE` abandons the case at that point (asserted by the
  check count), and that a filter matching nothing is an error rather than a
  green run;
* an unknown command-line flag *fails the run* (exit 3) rather than being
  ignored or mistaken for a request for help, because a CI job that passes
  `--filtr=...` and gets a full green run is a job that tested nothing. It used
  to print the usage text and exit 0, which was that green run, one keystroke
  away.

## The compile-failure suite

`tests/compile_fail/` holds eighteen programs that must not compile, each with
an expectation file recording the fragment of the diagnostic that states the
reason. `cmake/MetaAuthCompileFail.cmake` compiles each one, requires the
compilation to fail, requires the diagnostic to contain the recorded fragment,
and — importantly — rejects an environmental failure, so a missing header
cannot make every negative test pass vacuously.

### Two files per case, and why

An expectation is split in two:

| File | Holds | Example |
| --- | --- | --- |
| `expected/<case>.txt` | the portable half: the sentences this library writes into its own `= delete("...")` declarations, plus at most one token all compilers agree on | `A capability cannot be copied. Authority is handed on with delegate` |
| `expected/<case>.<family>.txt` | the compiler's own spelling, where the families disagree | `use of deleted function`, `static assertion failed` |

`<family>` is `gcc`, `clang` or `msvc`. The two sets of lines are concatenated
and all of them are required, so the portable half is the contract and the
family half is the precision.

The split exists because one file of GCC spellings is a suite that reports a
green run on the compiler it was written for and an unintelligible failure
everywhere else — which is how a negative suite ends up deleted rather than
fixed. It also forced a real improvement in the library: the messages a
rejected program prints are now written by *this* library, in sentences that
say what is wrong, instead of being left to the compiler to describe. A
consequence worth knowing is that the negative suite is the strictest test of
the library's own wording that exists — a reworded diagnostic breaks it, and
that is the point.

Matching is *literal* (`string(FIND`), not a regular expression. The expected
text is C++ source, and C++ source is full of regex metacharacters:
`capability(const capability<R, Rights>&)` as a regex means "capability
immediately followed by `const capability<R, Rights>&`" — the parentheses
become a group and stop matching themselves, so the check silently stops
checking. That is not hypothetical; it is what the first version of this driver
did.

Adding one is a three-step ritual, and the ritual is the point:

1. write the program that should be rejected;
2. compile it by hand and read the diagnostic;
3. record the fragment that states the reason.

Deleting a line from an expectation file is how a reviewer acknowledges that a
previously rejected program became legal.

The suite runs in **both** configurations. `ctest --preset portable` compiles
the same eighteen programs without `-fcontracts` and without `-freflection`,
which is what makes "the guarantees do not depend on the optional dialect
features" a checked statement: the rejections come from the type system and
from `requires` clauses, not from contract assertions.

CI asserts that the number of registered negative tests equals the number of
sources, so a case that was added to the directory but not to the list — or a
list entry whose source was deleted — is a build failure rather than a quiet
loss of coverage.

## Fail-stop tests

A process that is supposed to die cannot assert its own death, so those tests
are driven from the outside. `meta_auth_add_failure_test` runs a program and
asserts both the status *and* the reason:

```cmake
meta_auth_add_failure_test(contract.precondition_reports_its_condition
    PROGRAM "$<TARGET_FILE:meta_auth_contract_probe>"
    ARGS pre
    RESULT_REGEX "Subprocess aborted|^134$"
    OUTPUT_REGEX "denominator != 0.*${_pre_kind}"
    ...)
```

CTest's `WILL_FAIL` only inverts the exit status, which would accept any failure
at all — including the wrong one. The driver (`cmake/MetaAuthExpectFailure.cmake`)
matches the status *and* the output, so "it crashed" becomes "it aborted after
reporting a contract violation in `checked_ratio`, naming `denominator != 0`".

## Property tests, and where sampling stops

The rights lattice has seven atoms, which is 128 sets and 16384 ordered pairs.
Every pair is checked against reflexivity, antisymmetry, transitivity, the
bounds property, inclusion–exclusion, the complement laws and De Morgan: it is a
proof by exhaustion, not a sample.

The cubic identities (associativity, distributivity, absorption) are checked
over a *generating family* — the atoms plus the two bounds — rather than over
all 128³ triples. The reduction is sound because the operations are pointwise:
each bit position is an independent two-element Boolean algebra, so an identity
that holds on the atoms holds at every bit position of every element. The
exhaustive version was measured at 57 seconds and proved exactly the same thing.
The family check at the end of the test is what keeps the reduction honest, and
it earned its place immediately: the first version of the family was missing
four atoms.

The lesson generalises: when a property test is reduced, the reduction itself
gets an assertion.

## Concurrency

Two components are written from several threads: the audit trail, and the
revocation counters. Both are tested under ThreadSanitizer in CI
(`ctest --preset tsan`), and the assertions are about the properties that a
weaker implementation would violate:

* `revoke_all` uses `fetch_add`, so concurrent revocations all take effect. A
  load-then-store would lose them, and the failure would appear as an epoch that
  lags — that is, as a capability that should have been revoked and was not. The
  test asserts the final epoch equals the number of revocations performed.
* The audit trail is read while it is written. Each slot is stamped before and
  after its fields and the fields are relaxed atomics, so a reader detects a
  torn record and skips it. The test asserts that every record in a snapshot
  after 1600 concurrent writes has a sequence number in range and that
  consecutive entries are adjacent — a torn record would mix two writers and
  break both.

## Determinism

* Test cases are sorted by `(suite, name)` rather than left in registration
  order, so CI output is comparable between compilers.
* Duplicate case names are reported as a failure: two cases with one name means
  one of them is not running.
* No test depends on the order of another. The revocation tests assert epoch
  *changes* rather than absolute values, because the cases in a binary share a
  process and a per-resource epoch.

## Running the whole matrix locally

```sh
# The presets without a suffix use whatever compiler the host provides, so this
# loop works on any platform. `dev-gcc16` / `portable-gcc16` are the pinned
# reference configurations CI runs.
for preset in dev portable asan tsan; do
    cmake --preset "$preset" && cmake --build --preset "$preset" \
        && ctest --preset "$preset" --output-on-failure || echo "$preset FAILED"
done
cmake --preset bench && cmake --build --preset bench && ./build/bench/bin/meta_auth_bench
```

If it passes locally and fails in CI, the difference is the machine, and the
first thing to look at is the constant-time benchmark's spread — it is the only
measurement in the suite that depends on the hardware.

## Known gaps

Stated because a test suite that does not say what it misses invites the reader
to assume it misses nothing.

* **`-fno-exceptions` is not exercised.** The library throws nothing, so it
  should compile with exceptions disabled, and no preset proves it. The claim is
  therefore not made in `SECURITY.md`.
* **Clang, AppleClang and MSVC have not been run on the machine this was
  developed on.** GCC 15 and GCC 16 have: `ctest --preset dev` and
  `--preset dev-gcc16` are green on both, and GCC 15 was the configuration in
  which the `fixed_string::contains` and `-Werror=noexcept` defects were found.
  The other compilers are covered by CI jobs — `linux/clang`, `macos/portable`
  (Homebrew LLVM, because Apple's clang predates P2573) and `windows/msvc` — and
  until those have run, "portable" means "portable by construction and by CI",
  not "portable as measured here".
* **The audit trail's seqlock bounds the number of concurrent writers.** Up to
  `capacity` (256) writers sharing a slot is impossible; beyond that the
  protocol assumes a single writer per slot and a reader could accept a mixed
  record. The bound is stated in `sandbox/audit.hpp` next to the claim, and the
  tests exercise dozens of threads, not hundreds.
* **Revocation is not transactional with the operation it revokes.** A
  revocation that lands between `admit` returning and the operation being
  performed is not observed by that operation, so a capability can be used once
  more in that window. `docs/threat-model.md` states this rather than claiming
  otherwise; closing it needs an epoch guard held across the operation.
* **No fuzzing.** The descriptor decoder, the hex parser and the policy
  evaluator are all total functions over their input domains and are tested
  exhaustively over small domains, but nothing feeds them random bytes. The
  descriptor encoder is the one that takes attacker-shaped input (field
  lengths), and its bounds behaviour is asserted for the oversized case only.
* **The constant-time bound is a smoke test.** It catches a return to an
  early-exit loop. It does not measure cache behaviour, and passing it is not
  evidence of resistance to a side-channel attacker.
* **`binutils`-level checks are not run.** The hardening flags are applied and
  the linker accepts them; nothing asserts that the resulting binary has a
  non-executable stack and full RELRO. `checksec`-style verification would need
  a dependency.
* **No cross-compiler run.** GCC 15, GCC 16 and Clang 21 are claimed in the
  README; only GCC 16 is installed in CI, because the reference configuration is
  the one the guarantees are stated for. The portable preset exercises the
  feature-detection paths, not the compilers.
* **The audit trail's capacity is not tuned.** 256 records is a number that
  makes the ring testable and the dump readable; what it should be in a
  deployment with a given event rate is a question this project has not
  answered.
