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
* **MSVC cannot build the library at all**, and that is a fact about the
  compiler rather than about the test setup: MSVC 19.51 does not implement
  P2573, so `__cpp_deleted_function` is absent and `config.hpp` refuses every
  translation unit in one sentence. The `windows/msvc` job asserts that
  refusal — it passes while the library is correctly rejected and fails when
  MSVC ships the feature — so the claim "MSVC cannot build this" is checked
  rather than assumed. An earlier README claimed "MSVC 19.40+ implements it",
  which was never measured and is not true.
* **AppleClang has not been run on the machine this was developed on.** GCC 15,
  GCC 16, Clang 19 and Clang 21 have: `ctest` is green on all four in the
  portable configuration, 43/43, negative suite included, and GCC 15 was the
  configuration in which the `fixed_string::contains` and `-Werror=noexcept`
  defects were found. Clang 19 is the floor the README states, so that floor is
  measured rather than argued, and CI's `linux/clang` job measures Clang 21.
  AppleClang is covered by the `macos/portable` job, which runs Homebrew LLVM
  instead — Apple's clang predates P2573 — and which is green as of the run that
  replaced the framework's `__COUNTER__` with `__LINE__`. What that job had to
  get past first is the reason the job exists: the hardening probe accepted
  `-fstack-clash-protection` for arm64 darwin, where clang reports the flag as
  unused — a *warning*, which a probe reading exit status takes for acceptance,
  and which the probe never even compiled because every flag shared one result
  variable and CMake skips a probe whose result is already defined. Homebrew's
  LLVM is version 23 today, tracking upstream rather than a release, and it
  reports `__COUNTER__` as a C2y extension under `-Wpedantic`.
* **The audit trail can lose a record, not merely overwrite one.** The bound
  used to be stated as "up to `capacity` concurrent writers", on the reasoning
  that two writers share a slot only when their sequences differ by 256, which
  would need 256 appends in flight. That reasoning is wrong: what it takes is
  one writer *stalled* by 256 appends, whose late write lands on a newer
  record's slot and leaves a stamp matching neither sequence, so a reader skips
  it. `sandbox.concurrent_records_all_land` failed that way in the first ASan
  run (sequences 1419 and 1421 adjacent, 1420 absent, of 1600 appends), and
  twelve local runs did not reproduce it, so the mechanism is the explanation
  most consistent with the failure rather than a measured one. `dropped()` does
  not count such a loss. `sandbox/audit.hpp` states the bound as the code
  behaves; closing it needs the slot to be claimed with a compare-exchange
  rather than inferred from the sequence.
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
* **The compiler matrix covers the floors unevenly.** CI installs GCC 15, GCC 16
  and Clang 21 — the reference container's own compilers — so Clang's stated
  floor (19) is not what CI measures; it is measured on the machine this was
  developed on instead. MSVC's floor (19.40) is the one that has only been
  argued: the job runs whatever the runner image ships, and nothing asserts the
  version it found.
* **The audit trail's capacity is not tuned.** 256 records is a number that
  makes the ring testable and the dump readable; what it should be in a
  deployment with a given event rate is a question this project has not
  answered.
