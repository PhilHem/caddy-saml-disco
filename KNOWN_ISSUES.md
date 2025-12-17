# Known Issues

This document tracks bugs discovered through various analysis methods including property-based testing, concurrency testing, and hexagonal architecture analysis.

## Unconfirmed Issues

| ID       | Complexity | Status      | Source       | Description                                                                    | Location                                                                          | Timestamp  |
| -------- | ---------- | ----------- | ------------ | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- | ---------- |
| TEST-001 | MED        | unconfirmed | roadmap-update | Test files reference functions moved to adapter during hexagonal architecture refactoring, causing build failures | `attributes_test.go`, `attributes_fuzz_test.go`, test files referencing moved functions | 2024-12-17 |
| ATTR-001 | MED        | unconfirmed | property-test | Missing roundtrip property test for ResolveAttributeName: resolving OID→friendly→OID should be idempotent | `internal/core/domain/attributes.go`, `ResolveAttributeName` function | 2025-12-17 |
| ATTR-002 | MED        | unconfirmed | property-test | Missing property test for MapAttributesToHeaders prefix application: prefix application should be consistent regardless of mapping order | `internal/adapters/driving/caddy/mapattributes.go`, `MapAttributesToHeadersWithPrefix` | 2025-12-17 |
| ATTR-004 | MED        | unconfirmed | differential-test | Potential behavioral differences between old and new attribute mapping implementations after hexagonal refactoring | `internal/adapters/driving/caddy/mapattributes.go`, `attributes_test.go` (old tests) | 2025-12-17 |

## Confirmed Issues

| ID        | Complexity | Status    | Source        | Description | Location | Timestamp  |
| --------- | ---------- | --------- | ------------- | ----------- | -------- | ---------- |
| ARCH-001  | HARD       | confirmed | hex-analysis  | Pure domain functions (MapAttributesToHeaders, sanitizeHeaderValue, MapAttributesToHeadersWithPrefix, ApplyHeaderPrefix) are in adapter layer instead of domain layer - violates hexagonal architecture principle that pure logic without I/O should be in domain | `internal/adapters/driving/caddy/mapattributes.go`, `internal/adapters/driving/caddy/attributes.go`, `internal/adapters/driving/caddy/config.go` | 2025-12-17 |
| ARCH-002  | MED        | confirmed | hex-analysis  | Tests in root package directly call adapter functions instead of testing through ports/interfaces or domain functions - violates hexagonal architecture testing principles | `attributes_test.go`, `attributes_fuzz_test.go` (root package) calling `internal/adapters/driving/caddy` functions | 2025-12-17 |

## Resolved Issues

| ID        | Complexity | Status | Source    | Description | Location | Timestamp  |
| --------- | ---------- | ------ | --------- | ----------- | -------- | ---------- |
| ECAT-001  | MED        | fixed  | hex-analysis | EntityAttributes (R&S, SIRTFI) present in metadata but not parsed into IdPInfo | `internal/adapters/driven/metadata/parser.go`, `internal/core/domain/metadata.go` | 2024-12-17 |
| TEST-002  | MED        | fixed  | roadmap-update | Multi-SP handler isolation incomplete: ForSP handlers delegate to instance-level handlers instead of SP config stores | `internal/adapters/driving/caddy/plugin.go` (handleACSForSP, handleLogoutForSP, handleSLOForSP, handleSelectIdPForSP, handleSessionInfoForSP, handleDiscoveryUIForSP) | 2024-12-17 |
| TEST-003  | MED        | fixed  | roadmap-update | Missing property-based test for session isolation between SP configs | `internal/adapters/driving/caddy/isolation_property_test.go` with `TestSAMLDisco_MultiSP_Property_SessionIsolation` | 2024-12-17 |
| TEST-004  | MED        | fixed  | roadmap-update | Missing integration tests for end-to-end multi-SP flow | `tests/integration/multisp_test.go` with `TestMultiSP_EndToEndFlow` and `TestMultiSP_SessionIsolation` | 2024-12-17 |
| ATTR-003  | EASY       | fixed  | property-test | Missing property test for empty separator handling in MapAttributesToHeaders: empty separator should default to ";" | `internal/adapters/driving/caddy/mapattributes.go`, separator handling logic, `attributes_test.go` `TestMapAttributesToHeaders_Property_EmptySeparatorDefaults` | 2025-12-17 |
| ATTR-005  | MED        | fixed  | unit-test | Separator that sanitizes to empty string doesn't re-default to ";": after sanitization, if separator becomes empty (e.g., contains only control characters), values are concatenated without separator instead of using default ";" | `internal/adapters/driving/caddy/mapattributes.go` lines 64-70, separator sanitization logic | 2025-12-17 |
| ATTR-006  | MED        | fixed  | unit-test | Same separator sanitization bug in MapEntitlementsToHeaders: separator that sanitizes to empty doesn't re-default to ";" | `internal/adapters/driving/caddy/entitlements.go` lines 26-30, separator handling logic | 2025-12-17 |

## Status Legend

- **unconfirmed**: Potential issue identified but not yet verified
- **confirmed**: Issue verified and reproducible
- **fixed**: Issue has been resolved
- **wontfix**: Issue acknowledged but will not be fixed (with justification)

## Source Legend

- **hex-analysis**: Discovered through hexagonal architecture analysis
- **property-test**: Discovered through property-based testing
- **concurrency-test**: Discovered through concurrent access testing
- **differential-test**: Discovered through differential testing (comparing implementations)
- **roadmap-update**: Discovered during roadmap planning or tech debt tracking
- **manual**: Discovered through manual testing or code review
