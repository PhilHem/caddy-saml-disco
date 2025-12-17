# HEADER-004: Header Rollback Verification and Property-Based Testing

## Current State Analysis

The code already implements rollback in `applyAttributeHeaders()` and `applyAttributeHeadersForSP()`:

- Lines 890-911: Store original headers before stripping
- Lines 952-957: Restore headers if attribute mapping fails
- Lines 974-979: Restore headers if entitlement mapping fails

However, `TestHeaderStripping_Property_MappingErrorHandling` doesn't verify rollback works correctly.

## Red-Green-Refactor Plan

### Phase 1: RED - Write Failing Tests

1. **Fix existing test** (`TestHeaderStripping_Property_MappingErrorHandling`):

- Create a scenario where header name matches what's being stripped
- Verify that headers are restored (not left empty) when mapping fails
- Test both single-SP and multi-SP modes

2. **Add property-based test** for rollback correctness:

- Generate random valid header names, prefixes, and attribute mappings
- Property: If mapping fails after stripping, original headers must be restored
- Test edge cases: empty headers, multiple values, case variations

3. **Add test for entitlement mapping errors** (HEADER-009):

- Test that entitlement headers are restored when `MapEntitlementsToHeaders` fails
- Test both single-SP and multi-SP modes

4. **Add concurrency test**:

- Verify rollback works correctly under concurrent requests
- Test config immutability during request handling

### Phase 2: GREEN - Fix Any Bugs Found

If tests reveal bugs:

1. Fix rollback mechanism if it doesn't work correctly
2. Ensure consistent behavior between single-SP and multi-SP modes
3. Fix entitlement header rollback if needed

### Phase 3: REFACTOR - Clean Up

1. Extract common rollback logic if duplicated
2. Ensure consistent error handling patterns
3. Update KNOWN_ISSUES.md with findings

## Files to Modify

- `internal/adapters/driving/caddy/header_stripping_property_test.go`: Add/fix tests
- `internal/adapters/driving/caddy/plugin.go`: Fix rollback if bugs found
- `KNOWN_ISSUES.md`: Update HEADER-004 and HEADER-009 status

## Test Strategy

1. **Unit tests**: Verify rollback works for attribute mapping errors
2. **Property-based tests**: Surface edge cases with random valid inputs
3. **Concurrency tests**: Verify no race conditions in rollback logic
4. **Integration tests**: Test end-to-end behavior

## Expected Outcomes

- HEADER-004: Verify rollback works correctly or fix if broken
- HEADER-009: Verify entitlement rollback works correctly
- Property-based tests surface any edge cases
- All tests pass with proper rollback behavior verified