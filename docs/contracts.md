# Contracts, and the compiler limitations found while building this

## The distinction the library makes

Two kinds of failure, kept strictly apart:

| | Domain error | Broken invariant |
| --- | --- | --- |
| Examples | wrong credential, failed attestation, revoked capability | an impossible state, a descriptor that does not fit its buffer |
| Representation | `result<T> = std::expected<T, auth_error>` | a contract assertion |
| Caller's obligation | handle it | none: it cannot happen |
| Behaviour | returned as a value | reported, then `abort()` |

Mixing them is how security code ends up swallowing a failure it cannot handle.
A caller that ignores a `result` gets a compiler warning (`[[nodiscard]]`); a
caller that ignores a broken invariant does not exist, because the process is
already gone.

The rule for choosing, stated so that it does not have to be re-derived: **if
the caller could plausibly do something useful, it is a domain error. If the
only correct response is to stop, it is a contract.**

## The two forms, and why both are needed

```cpp
// Declarator form: P2900 contracts, empty on a compiler without them.
[[nodiscard]] constexpr auto checked_ratio(int numerator, int denominator) -> double
    META_AUTH_PRE(denominator != 0)
    META_AUTH_POST(result: result >= 0.0)
{
    META_AUTH_PRE_FALLBACK(denominator != 0);   // a no-op when the declarator was emitted
    const double result = static_cast<double>(numerator) / static_cast<double>(denominator);
    META_AUTH_POST_FALLBACK(result >= 0.0);
    return result;
}
```

* `META_AUTH_PRE` / `META_AUTH_POST` live in the declarator, where they document
  the interface and are enforced by the compiler. They expand to nothing when
  the compiler has no contract support.
* `META_AUTH_PRE_FALLBACK` / `META_AUTH_POST_FALLBACK` are the portable twins.
  They expand to **nothing when the declarator was emitted** and to a check
  otherwise, so the fact is checked exactly once in either build.
* `META_AUTH_EXPECTS`, `META_AUTH_ENSURES` and `META_AUTH_ASSERT` are statement
  contracts, always active, and are what most of the library uses.

The pairing rule is the part that needs discipline: a function that writes
`META_AUTH_PRE(x)` writes `META_AUTH_PRE_FALLBACK(x)` as the first statement of
its body. If both fired, a violating call would be reported twice and the
sequence numbers in the audit trail would lie about how many violations
occurred — which is why `tests/core/test_contract.cpp` asserts that the
sequence advances by one per violation.

`ctest --preset portable` runs the same fail-stop tests as `ctest --preset
dev`, which is what makes "the portable build is not a weaker build" a checked
statement rather than a hopeful one. The only difference is the classification:
the portable path can only produce P2900's statement form, so a violated
`pre`/`post` is reported as an `assertion`. The condition, the file, the line,
the function and the abort are identical, and the expected diagnostics in
`tests/core/CMakeLists.txt` record the difference per configuration.

## The violation handler

P2900 leaves `handle_contract_violation` to the program. This library provides
one, which gives a consumer three things: a structured report, a redirectable
stream, and an observer hook for routing a violation into an audit trail before
the process dies.

```cpp
void set_violation_observer(violation_observer observer, void* user) noexcept;
void set_violation_stream(std::FILE* stream) noexcept;
```

The report is formatted into a caller-provided buffer and is allocation-free:
the path that ends the process must not be able to fail on an allocation.
Truncation is marked (`...[truncated]`) rather than silent, because a report cut
in half without saying so invites the reader to conclude the missing part did
not exist.

A program that wants its own handler defines
`META_AUTH_CONFIG_INSTALL_VIOLATION_HANDLER=0` and provides one; the library's
definition is weak, so a strong definition in the program wins.

## Compiler limitations, with reproductions

Four things were found while building this against **GCC 16.0.1
(16-20260322-1ubuntu1)**. Each is recorded here with the smallest reproduction
that shows it, and each is designed around rather than worked around silently.

### 1. `-fcontracts` is required on the link line, not only the compile line

Without it the object file compiles cleanly and the link fails:

```
undefined reference to `handle_contract_violation(std::contracts::contract_violation const&)'
```

`cmake/MetaAuthDialect.cmake` adds it to both. The library's own weak handler
also satisfies the symbol, which is a second reason a consumer does not hit
this.

### 2. `__cpp_contracts` is defined even when `-fcontracts` is not passed

GCC 16 defines the language macro in C++26 mode regardless of the flag, so the
macro describes the *dialect* and not the *build*. `include/meta_auth/config.hpp`
therefore lets the build system override the macro-based guess with
`META_AUTH_CONFIG_USE_CONTRACTS`, and the probe that sets it compiles and links
a program rather than inspecting a macro.

### 3. A named-result postcondition makes a scalar `constexpr` variable ill-formed

```cpp
constexpr auto ratio(int a, int b) -> double
    post(r: r >= 0.0) { return static_cast<double>(a) / b; }

static_assert(ratio(1, 2) == 0.5);      // accepted
constexpr double value = ratio(1, 2);   // error: contract condition is not constant
```

`static_assert`, aggregate initialisation and run-time calls are all accepted;
only the scalar `constexpr` variable initialiser is rejected, and the same
rejection appears when `const auto&` binds the result.

**The rule this project follows as a result:** named-result postconditions go on
functions that are verified by `static_assert`, and in-body `META_AUTH_ENSURES`
is used where a `constexpr` variable initialiser has to work. The test harness
also *copies* the operands of `CHECK_EQ` rather than binding references, which is
better report semantics anyway and sidesteps the same limitation.

### 4. `if consteval` is constant-folded into a `const` initialiser, discarding the run-time branch

The most dangerous of the four, because the program compiles cleanly and is
wrong:

```cpp
constexpr std::uint64_t next() {
    if consteval { return 0; }
    else { return counter().fetch_add(1, std::memory_order_relaxed) + 1; }
}

auto       a = next();   // 1, the counter advanced
const auto b = next();   // 0, and the counter did NOT advance
```

Initialising a `const` integral variable makes the compiler constant-fold the
call. During that fold `if consteval` is true, so the compile-time branch is
taken and the **run-time side effect is discarded** — even though a function
performing an atomic operation is not a constant expression, and folding it
should have failed.

An implementation of `authority::mint` written the obvious way therefore
numbers every capability from zero whenever the caller writes `const auto`, and
the resulting audit trail has every record claiming the same capability.

**The rule:** a function whose run-time behaviour has a side effect does not get
an `if consteval` branch. The two contexts are separate functions —
`mint` has no compile-time path, `mint_consteval` is `consteval` so a run-time
call to it is ill-formed — and misusing them is a diagnostic rather than a wrong
value. `tests/capability/test_capability.cpp` has a regression test that fails
if the two are ever merged again.

### 5. A call to a constrained function is a hard error inside a requires-expression

```cpp
template <typename T> struct Box { void h() requires (sizeof(T) > 100); };

static_assert(!requires(Box<int> b) { b.h(); });   // error, not false
```

The standard says an invalid expression inside a `requires`-expression is a
substitution failure that yields `false`. GCC 16 diagnoses it as a hard error,
which means `static_assert(!requires(...))` cannot be used to assert the
*absence* of a constrained member.

**The rule:** the negative half of the type-state and of the capability API is
asserted by `tests/compile_fail/`, which compiles the offending program and
inspects the diagnostic. That is exact, it checks the message as well as the
rejection, and it does not depend on a compiler quirk.

### 6. A constrained friend declaration of the enclosing class template is rejected

```cpp
template <principal_type Principal, session_state State> class session {
    template <principal_type OtherPrincipal, session_state OtherState>
    friend class session;   // error: template parameter 'Principal' redeclared
};                          // here as '... OtherPrincipal'
```

Two instantiations of one class template therefore cannot reach each other's
private constructors on this compiler.

**The rule:** the session states share their identity through a
`detail::session_core` value that a transition hands to the next state. The
bypass of the state machine is expressible only by naming `detail`, which is
where a reviewer will see it.

### 7. Two false out-of-bounds reports in the optimised build

At `-O3`, with SHA-256 inlined through HMAC, GCC reports an access 225 bytes
into a 32-byte digest, and a subscript 64 into a 64-byte array whose loop
condition excludes it. Both are wrong.

**The rule:** the suppression is a `#pragma` scoped to `sha256.hpp` and to
optimized builds (`__OPTIMIZE__`), with the reasoning and the evidence written
in the header. `-Warray-bounds` also drops from level 2 to the default, because
level 2 is documented as producing false positives under aggressive inlining.
What backs the code instead is stronger than the warning would be: the FIPS
vectors are `static_assert`s, the padding boundaries are tested explicitly, and
the suite runs under AddressSanitizer and UndefinedBehaviorSanitizer in CI,
where a real out-of-bounds access is a hard failure rather than a diagnostic.

## Checklist for adding a contract

1. Is the condition a *domain* question? Then it is a `result<T>` and not a
   contract.
2. Does the condition mention the return value? Then it is a postcondition, and
   the rule from limitation 3 applies.
3. Will a `constexpr` variable ever be initialised from this call? Then use
   `META_AUTH_ENSURES` in the body rather than a declarator postcondition.
4. Write the declarator contract *and* its fallback, or neither. Never one
   without the other.
5. If the contract can fire, add a fail-stop test to `tests/core/CMakeLists.txt`
   with an expected diagnostic. A contract nobody has seen fire is a contract
   whose report has never been read.
