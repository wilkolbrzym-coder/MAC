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
| `compile_fail` | Sixteen programs stay ill-formed, for the documented reason | `tests/compile_fail/` |
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
* an unknown command-line flag asks for help rather than being ignored, because
  a CI job that passes `--filtr=...` and gets a full green run is a job that
  tested nothing.

## The compile-failure suite

`tests/compile_fail/` holds sixteen programs that must not compile, each with an
expectation file recording the fragment of the diagnostic that states the
reason. `cmake/MetaAuthCompileFail.cmake` compiles each one, requires the
compilation to fail, requires the diagnostic to contain the recorded fragment,
and — importantly — rejects an environmental failure, so a missing header
cannot make every negative test pass vacuously.

Adding one is a three-step ritual, and the ritual is the point:

1. write the program that should be rejected;
2. compile it by hand and read the diagnostic;
3. record the fragment that states the reason.

Deleting a line from an expectation file is how a reviewer acknowledges that a
previously rejected program became legal.

The suite runs in **both** configurations. `ctest --preset portable` compiles
the same sixteen programs without `-fcontracts` and without `-freflection`,
which is what makes "the guarantees do not depend on the optional dialect
features" a checked statement. Two cases behave differently there — the
`capability_construct` and revoked-session cases report "no matching function"
in both, but the deleted-overload messages that depend on contract diagnostics
are only present with contracts — and the expected fragments are chosen so that
each configuration asserts what it can.

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
for preset in dev portable asan tsan; do
    cmake --preset "$preset" && cmake --build --preset "$preset" \
        && ctest --preset "$preset" --output-on-failure || echo "$preset FAILED"
done
cmake --preset bench && cmake --build --preset bench && ./build/bench/bin/meta_auth_bench
```

That is what CI runs, in the same pinned container. If it passes locally and
fails in CI, the difference is the machine, and the first thing to look at is
the constant-time benchmark's spread — it is the only measurement in the suite
that depends on the hardware.

## Known gaps

Stated because a test suite that does not say what it misses invites the reader
to assume it misses nothing.

* **`-fno-exceptions` is not exercised.** The library throws nothing, so it
  should compile with exceptions disabled, and no preset proves it. The claim is
  therefore not made in `SECURITY.md`.
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
