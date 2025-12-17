# Header Stripping: Hexagonal Architecture & Property-Based Testing Analysis

## Executive Summary

Property-based testing for header stripping provides **systematic verification of security invariants** in the adapter layer of our hexagonal architecture. It complements example-based tests by exploring the entire input space, catching edge cases that manual tests might miss. While probabilistic concurrency testing is less critical for this feature (each HTTP request is handled by a single goroutine), property-based testing is essential for maintaining security guarantees.

## What Property-Based Testing Does for Hexagonal Architecture

### 1. **Tests Adapter Layer Independently**

Header stripping lives in the **adapter layer** (`internal/adapters/driving/caddy/plugin.go`), which adapts domain data (`domain.Session`) to HTTP protocol concerns (`http.Request.Header`). Property-based testing:

- **Verifies adapter correctness**: Ensures the adapter correctly transforms domain data to HTTP headers
- **Tests HTTP-specific concerns**: Case-insensitivity, multiple values, prefix handling
- **Maintains separation**: Tests adapter behavior without requiring domain layer mocks

### 2. **Systematic Invariant Verification**

Property-based tests verify **security invariants** that must hold for all inputs:

1. **Spoofed headers always removed** (when strip enabled)
2. **Case-insensitive matching** (HTTP semantics)
3. **Multiple values removed** (all spoofed values eliminated)
4. **Prefix handling correct** (prefixed headers stripped correctly)
5. **Entitlement headers stripped** (even when lookup fails)

These invariants are **security-critical** - violations could allow header injection attacks.

### 3. **Explores Entire Input Space**

Unlike example-based tests that test specific cases, property-based tests:

- Generate **random header names** (all case variations)
- Generate **random values** (spoofed and authentic)
- Test **all combinations** (strip enabled/disabled, prefix present/absent)
- Discover **edge cases** automatically (empty values, special characters, etc.)

### 4. **Regression Prevention**

Property tests catch regressions automatically:

- If `Header.Del()` behavior changes
- If prefix logic is modified incorrectly
- If case-insensitivity assumptions break
- If new code paths bypass stripping

## Does Property-Based Testing Help? YES ✅

Property-based testing is **essential** for header stripping because:

1. **Security-critical feature**: Header injection is a real attack vector
2. **Large input space**: Header names, values, cases, prefixes create many combinations
3. **Edge cases matter**: Attackers exploit edge cases (case variations, special characters)
4. **Invariant verification**: Security properties must hold for ALL inputs, not just examples

### Example: Case-Insensitive Matching Bug

Without property-based testing, we might test:
- `X-Role` → stripped ✓
- `x-role` → stripped ✓

But property-based testing systematically tests:
- `X-Role`, `x-role`, `X-ROLE`, `x-Role`, `X-rOlE`, etc.

This catches edge cases like:
- Non-ASCII characters in header names
- Unicode normalization issues
- Mixed case variations not covered by `CanonicalHeaderKey()`

## Does Probabilistic Concurrency Testing Help? LESS CRITICAL ⚠️

Probabilistic concurrency testing is **less critical** for header stripping because:

1. **Single goroutine per request**: Each HTTP request is handled by a single goroutine
2. **No shared mutable state**: Headers are request-scoped, not shared between requests
3. **No locks**: Header manipulation doesn't use locks or synchronization primitives

However, concurrency testing could reveal:

- **Race conditions**: If middleware chains modify headers concurrently (unlikely but possible)
- **Memory visibility**: Stale reads of header values (unlikely with Go's memory model)
- **Future changes**: If locks are added later, concurrency testing becomes important

**Conclusion**: Property-based testing is essential; concurrency testing is less critical but could be valuable if middleware chains become more complex.

## Bugs Discovered Through Analysis

### Already Tracked (KNOWN_ISSUES.md)

1. **HEADER-001**: Race condition (unlikely but possible)
2. **HEADER-002**: Case sensitivity edge cases
3. **HEADER-003**: Default strip behavior inconsistency (single-SP vs multi-SP)

### New Bugs Identified

4. **HEADER-004**: Headers stripped but not replaced on mapping error
   - **Location**: `plugin.go:940-948`
   - **Issue**: If `MapAttributesToHeadersWithPrefix` fails after stripping, headers are stripped but never replaced
   - **Impact**: Security - legitimate headers removed, no replacement
   - **Likelihood**: Low (config errors should be caught at startup)

5. **HEADER-005**: Entitlement headers stripped before lookup
   - **Location**: `plugin.go:897-900,918-933`
   - **Issue**: Entitlement headers are stripped before lookup. If lookup fails (non-ErrEntitlementNotFound), headers are stripped but not replaced
   - **Impact**: Security - headers removed, no replacement if lookup fails
   - **Likelihood**: Medium (entitlement store failures are possible)

6. **HEADER-006**: Session nil after stripping
   - **Location**: `plugin.go:890-904`
   - **Issue**: If session becomes nil after stripping, headers are stripped but never replaced
   - **Impact**: Security - headers removed for unauthenticated requests
   - **Likelihood**: Low (correct behavior for unauthenticated requests, but could be bug if session becomes nil unexpectedly)

## How Property-Based Testing Surfaces These Bugs

### Bug HEADER-003 (Default Behavior Inconsistency)

Property-based testing would surface this by:
- Testing single-SP and multi-SP paths with identical inputs
- Discovering that default behavior differs
- Failing when strip defaults differ between paths

### Bug HEADER-004 (Headers Not Replaced on Error)

Property-based testing could surface this by:
- Generating inputs that cause `MapAttributesToHeadersWithPrefix` to fail
- Verifying that headers are still present after error
- Discovering that headers are stripped but not replaced

### Bug HEADER-005 (Entitlement Headers Stripped Before Lookup)

Property-based testing could surface this by:
- Testing scenarios where entitlement lookup fails
- Verifying that entitlement headers are present after lookup failure
- Discovering that headers are stripped but not replaced

## Recommendations

1. **Run property tests in CI**: Ensure they run on every commit
2. **Monitor for failures**: Property test failures indicate potential bugs
3. **Extend coverage**: Add property tests for multi-SP isolation (HEADER-003)
4. **Test error paths**: Add property tests for mapping errors (HEADER-004)
5. **Test entitlement failures**: Add property tests for entitlement lookup failures (HEADER-005)
6. **Document findings**: Track discovered bugs in `KNOWN_ISSUES.md` ✓ (done)

## Conclusion

Property-based testing is **essential** for header stripping in our hexagonal architecture:

- ✅ Tests adapter layer independently
- ✅ Verifies security invariants systematically
- ✅ Explores entire input space
- ✅ Prevents regressions
- ✅ Surfaces edge cases automatically

While probabilistic concurrency testing is less critical (single goroutine per request), property-based testing provides confidence that security-critical header stripping works correctly for all inputs.
