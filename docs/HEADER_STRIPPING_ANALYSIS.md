# Header Stripping: Hexagonal Architecture Analysis

## Overview

Header stripping is a security-critical feature that prevents header injection attacks by removing incoming spoofed headers before injecting SAML-derived attributes. This document analyzes how header stripping fits into the hexagonal architecture and what bugs property-based testing could surface.

## Hexagonal Architecture Context

### Location: Adapter Layer

Header stripping is implemented in the **adapter layer** (`internal/adapters/driving/caddy/plugin.go`), specifically in:
- `applyAttributeHeaders()` - Single-SP mode
- `applyAttributeHeadersForSP()` - Multi-SP mode

This is architecturally correct because:
1. **HTTP-specific**: Header manipulation is HTTP protocol-specific, not domain logic
2. **Caddy integration**: Uses `http.Request.Header` which is Caddy's HTTP abstraction
3. **Adapter responsibility**: Adapts domain session data to HTTP headers for downstream handlers

### Architecture Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Adapter Layer (Caddy)                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  applyAttributeHeaders()                            │   │
│  │  1. Strip incoming spoofed headers (HTTP-specific)  │   │
│  │  2. Look up session (domain.Session)                │   │
│  │  3. Map attributes to headers (pure function)      │   │
│  │  4. Inject headers into http.Request                │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Domain Layer (Pure Functions)                        │   │
│  │  - MapAttributesToHeaders()                          │   │
│  │  - sanitizeHeaderValue()                             │   │
│  │  - CombineAttributes()                               │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Separation of Concerns

- **Adapter (`plugin.go`)**: HTTP request manipulation, header stripping, header injection
- **Domain (`mapattributes.go`, `attributes.go`)**: Pure transformation functions, no I/O, no HTTP

This separation ensures:
- Domain logic is testable without HTTP mocks
- Adapter logic handles HTTP-specific concerns (case-insensitivity, multiple values)
- Security boundaries are clear (strip happens in adapter, sanitization in domain)

## Security Properties

### Property 1: Spoofed Headers Always Removed

**Invariant**: When `strip_attribute_headers` is enabled, any incoming header matching a configured attribute/entitlement header name must be removed before injection.

**Why critical**: Prevents attackers from injecting malicious header values that could override SAML-derived attributes.

**Implementation**: Uses `r.Header.Del()` before `r.Header.Set()`.

### Property 2: Case-Insensitive Matching

**Invariant**: Header stripping must work case-insensitively, matching HTTP header semantics (RFC 7230).

**Why critical**: HTTP headers are case-insensitive. An attacker could send `x-role` (lowercase) to bypass stripping if matching was case-sensitive.

**Implementation**: Relies on Go's `http.Header.Del()` which uses `CanonicalHeaderKey()` internally.

### Property 3: Multiple Values Removed

**Invariant**: If multiple values exist for the same header (via `Header.Add()`), all values must be removed.

**Why critical**: Prevents partial removal where some spoofed values persist.

**Implementation**: `Header.Del()` removes all values for a header name.

### Property 4: Prefix Handling

**Invariant**: When `header_prefix` is configured, stripping must use the prefixed header name.

**Why critical**: Without prefix handling, stripping would target the wrong header name.

**Implementation**: Uses `ApplyHeaderPrefix()` to construct header name before `Del()`.

### Property 5: Multi-SP Isolation

**Invariant**: Each SP config must strip headers independently. Headers for SP-A should not affect SP-B.

**Why critical**: Prevents cross-SP header leakage in multi-tenant deployments.

**Implementation**: Each SP config has its own `AttributeHeaders` and `EntitlementHeaders` lists.

## Potential Bugs Property-Based Testing Could Surface

### Bug Category 1: Case Sensitivity Edge Cases

**Potential Issue**: While Go's `http.Header.Del()` is case-insensitive, edge cases might exist:
- Non-ASCII characters in header names
- Mixed case variations not covered by `CanonicalHeaderKey()`
- Unicode normalization issues

**How property testing helps**: Generates random case variations and verifies all are stripped.

### Bug Category 2: Race Conditions

**Potential Issue**: Header stripping and injection are not atomic:
1. Thread A: `Del()` removes spoofed header
2. Thread B: Sets new spoofed header
3. Thread A: `Set()` injects attribute value
4. Result: Thread B's spoofed value might persist

**How property testing helps**: Concurrent property tests could reveal timing-dependent failures.

**Note**: In practice, each HTTP request is handled by a single goroutine, so this is less likely. However, if middleware chains modify headers concurrently, issues could arise.

### Bug Category 3: Prefix Logic Divergence

**Potential Issue**: `applyAttributeHeaders()` and `applyAttributeHeadersForSP()` use slightly different logic:
- Single-SP: Uses `s.shouldStripAttributeHeaders()` (defaults to true)
- Multi-SP: Uses `spConfig.StripAttributeHeaders != nil && *spConfig.StripAttributeHeaders` (defaults to false if nil)

**How property testing helps**: Tests both code paths with identical inputs to verify consistent behavior.

### Bug Category 4: Entitlement Header Stripping

**Potential Issue**: Entitlement headers are stripped in the same loop as attribute headers, but entitlement lookup happens later. If entitlement lookup fails, headers are already stripped but not replaced.

**How property testing helps**: Tests scenarios where entitlements are missing or lookup fails.

### Bug Category 5: Empty Header Names

**Potential Issue**: If header name is empty or invalid, `Del()` might not behave as expected.

**How property testing helps**: Generates edge case header names (empty, invalid characters, etc.) and verifies no panics or unexpected behavior.

## Property-Based Testing Benefits

### 1. Systematic Exploration

Property-based tests explore the entire state space:
- All case variations of header names
- All combinations of strip enabled/disabled, prefix present/absent
- All combinations of attribute values (empty, single, multiple)

### 2. Invariant Verification

Each property test verifies a security invariant:
- Spoofed headers are always removed (when strip enabled)
- Case-insensitive matching works
- Multiple values are all removed
- Prefix handling is correct

### 3. Regression Prevention

Property tests catch regressions automatically:
- If someone changes `Header.Del()` behavior
- If prefix logic is modified
- If case-insensitivity assumptions break

### 4. Documentation

Property tests serve as executable documentation:
- They clearly state what the code should do
- They demonstrate edge cases
- They show security properties

## Probabilistic Concurrency Testing

While property-based testing explores the input space, **probabilistic concurrency testing** could reveal:

1. **Race conditions**: Multiple goroutines modifying headers simultaneously
2. **Memory visibility**: Stale reads of header values
3. **Lock contention**: If locks are added in the future

However, for header stripping specifically:
- Each HTTP request is handled by a single goroutine
- No shared mutable state between requests
- Header manipulation is request-scoped

**Conclusion**: Concurrency testing is less critical for header stripping than for shared state (e.g., `InMemoryRequestStore`).

## Implementation Status

✅ **Property-based tests implemented**: `header_stripping_property_test.go`
- `TestHeaderStripping_Property_SpoofedHeadersAlwaysRemoved`
- `TestHeaderStripping_Property_CaseInsensitiveMatching`
- `TestHeaderStripping_Property_MultipleValuesRemoved`
- `TestHeaderStripping_Property_PrefixHandling`
- `TestHeaderStripping_Property_EntitlementHeadersStripped`

✅ **Integration tests exist**: `tests/integration/attribute_headers_test.go`
- `TestAttributeHeaders_StripsIncomingHeaders`
- `TestAttributeHeaders_HeaderPrefix_StripsIncomingHeaders`

## Recommendations

1. **Run property tests in CI**: Ensure they run on every commit
2. **Monitor for failures**: Property test failures indicate potential bugs
3. **Extend coverage**: Add property tests for multi-SP isolation
4. **Document findings**: Track discovered bugs in `KNOWN_ISSUES.md`

## Conclusion

Header stripping is correctly placed in the adapter layer, maintaining clean separation between HTTP concerns and domain logic. Property-based testing systematically verifies security-critical invariants, catching edge cases that example-based tests might miss. The implementation appears robust, but ongoing property testing will help maintain confidence as the codebase evolves.
