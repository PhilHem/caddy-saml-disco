# Roadmap

Development phases for caddy-saml-disco.

## Phase 1: Foundation (v0.1.0) ✅

**Goal:** Minimal working plugin that can authenticate via a single IdP.

- [x] Project setup (go.mod, dependencies)
- [x] Caddy module registration (`plugin.go`)
- [x] Configuration struct with JSON tags (`config.go`)
- [x] Basic Caddyfile parsing (`caddyfile.go`)
- [x] Test IdP fixture (`testfixtures/idp/`) using `crewjam/saml/samlidp`
- [x] Single IdP metadata loading (file only)
- [x] Session management with JWT cookies (`session.go`)
- [x] SAML SP logic: AuthnRequest, ACS (`saml.go`)
- [x] SP metadata endpoint
- [x] Integration test validating full SAML flow against test IdP
- [x] Session checking middleware for protected routes
- [x] Redirect unauthenticated users to IdP (`redirectToIdP`)
- [x] Use configured `SessionDuration` in handleACS (currently hardcoded)
- [x] Set session cookie `MaxAge` to match `SessionDuration`
- [x] Add `session_duration` to example Caddyfile
- [x] Test session expiry behavior in integration tests
- [x] Unit test for expired JWT tokens in middleware (real tokens, not hardcoded strings)
- [x] Validate RelayState is relative path before redirect (prevent open redirect)
- [x] E2E test for full auth redirect flow (protected → IdP → ACS → original)
- [x] Session logout endpoint (`/saml/logout`) - clear cookie, redirect
- [x] Use `return_to` after successful ACS for post-login redirect (via RelayState)

**Outcome:** Can protect a route with SAML auth using a single configured IdP.

---

## Phase 2: Multi-IdP & Discovery (v0.2.0) ✅

**Goal:** Support metadata aggregates and IdP discovery.

- [x] Metadata aggregate parsing (multiple IdPs from one XML)
- [x] Test nested EntitiesDescriptor parsing
- [x] Test aggregate metadata refresh (file changes)
- [x] URL-based metadata loading with caching
- [x] TTL-based metadata refresh
- [x] User-Agent header for metadata requests (`caddy-saml-disco/<version>`)
- [x] IdP filtering by pattern
- [x] Discovery Service JSON API (`/saml/api/idps`, `/saml/api/select`)
- [x] Default discovery UI (embedded HTML template)
- [x] Auto-redirect for single IdP scenarios
- [x] Search/filter IdPs in API
- [x] Parse mdui:UIInfo extensions (DisplayName, Description, Logo URLs)
- [x] Add `Description`, `LogoURL`, `InformationURL` fields to `IdPInfo` struct
- [x] Prefer mdui:DisplayName over Organization/OrganizationDisplayName
- [x] Create realistic test metadata with mdui extensions (dfn-aai-sample.xml)
- [x] Session info endpoint (`/saml/api/session`) - returns JSON with subject, attributes
- [x] Integration tests for discovery flow (`tests/integration/discovery_test.go`)

**Outcome:** Can load federation metadata and present IdP selection to users.

---

## Phase 3: Customization (v0.3.0) ✅

**Goal:** Enable custom frontends and UI customization.

- [x] Template override via `templates_dir` config
- [x] Wire up error template to HTTP error handlers (ACS errors, metadata errors)
- [x] `login_redirect` for fully custom UIs
- [x] Custom frontend example in `examples/` (demonstrates `login_redirect` + JSON API)
- [x] Remember last-used IdP cookie
- [x] FeLS-style discovery UI (autocomplete search, "Remember me" checkbox, alternative login methods section)
- [x] CORS headers for SPA frontends (optional)
- [x] Multi-language display name support (prefer user's Accept-Language locale)
- [x] Configurable default language fallback (`default_language` config option)
- [x] Search across all language variants (match "München" even when Accept-Language is "en")
- [x] Logo proxy/caching endpoint (avoid hotlinking federation logos)

**Outcome:** Users can build custom discovery UIs consuming the JSON API.

---

## Phase 4: Single-IdP Release (v1.0.0) ✅

**Goal:** Production-ready release for single-IdP deployments with distributable binaries.

### Completed (from previous hardening work)
- [x] Structured logging via Caddy's logger
- [x] Comprehensive error pages
- [x] Request ID tracking
- [x] Security review (cookie flags, CSRF, etc.)
- [x] **Metadata signature verification** (critical for federation trust)
- [x] Parse `mdrpi:RegistrationInfo` for trust chain validation
- [x] Expose registration info in `/saml/api/idps` JSON response
- [x] Validate metadata `validUntil` attribute (reject expired metadata)
- [x] Graceful handling of metadata fetch failures (serve stale if fresh unavailable)
- [x] Health check endpoint (`/saml/api/health`) exposing `MetadataHealth` status
- [x] Periodic background metadata refresh (using `time.NewTicker`)
- [x] Wire up background refresh in plugin `Provision()` (`background_refresh` config option)
- [x] Add logging for background refresh events (success/failure in `refreshLoop()`)

### Distribution & Documentation
- [x] GitHub Actions workflow for release binaries (linux/amd64, linux/arm64, darwin/arm64, windows/amd64)
- [x] Add SHA256 checksums file to releases
- [x] Mark pre-release tags (`-rc`, `-beta`, `-alpha`) as pre-releases in GitHub
- [x] Inject version info into binaries via `-ldflags`
- [x] Expose version info in `/saml/api/health` endpoint (version, git_commit, build_time)
- [x] Document version querying via CLI (`caddy version`)
- [x] Docker image with automated builds (`ghcr.io/philhem/caddy-saml-disco`)
- [x] README expansion with single-IdP deployment guide
- [x] Example: minimal single-IdP Caddyfile

### Bug Fixes
- [x] Fix integration tests expecting 302 from `/saml/api/select` (now returns JSON with `redirect_url`)

**Outcome:** Users can download pre-built binaries or Docker image and deploy with a single IdP.

---

## Phase 5: Federation Hardening (v1.1.0) ✅

**Goal:** Production-ready for large federation environments with multiple IdPs.

### Observability
- [x] Metrics exposure (Prometheus-compatible, optional)
- [x] Signature verification logging (algorithm, cert subject/expiry on success)
- [x] Log metadata expiry rejections (structured logging for `validUntil` failures)
- [x] Expose `validUntil` in health endpoint (`MetadataValidUntil` field for monitoring)
- [x] Instrument metadata refresh with metrics (call `RecordMetadataRefresh` from MetadataStore)

### Federation Features
- [x] Sign SP metadata with SP private key (`sign_metadata` config option)
- [x] Add signing KeyDescriptor to SP metadata (set `SignatureMethod` to emit both encryption and signing)
- [x] Filter IdPs by registration authority (`registration_authority_filter` config option)
- [x] Performance testing with large metadata files (1000+ IdPs)
  - Benchmark tests for parsing, search, and lookup operations
  - Fixture generator for synthetic metadata (100-5000 IdPs)
  - Memory usage estimation tests

### Test Infrastructure
- [x] Harden time-based refresh tests (use synchronization instead of `time.Sleep` margins)
  - Added `WithOnRefresh`, `WithOnCleanup` callback hooks and `Clock` interface for deterministic testing
  - Note: JWT expiration tests retain short sleeps due to external library dependency
- [x] Test fixture: signed metadata generator (runtime signing for integration tests)
  - `testfixtures/metadata/` package with `Signer` type and convenience methods
  - Full integration with `XMLDsigVerifier` for end-to-end testing
- [x] Test fixture: pre-signed metadata for unit tests (static signed XML matching `testdata/sp-cert.pem`)
  - `testdata/cmd/sign-metadata/main.go` generator tool and `testdata/signed/` directory
  - Unit tests in `signature_test.go` (Cycle 2.9)
- [x] Consolidate duplicate `mockMetricsRecorder` implementations
  - Moved to `test_helpers_test.go` with thread-safe `MockMetricsRecorder`

**Outcome:** Ready for production use in large federation environments (e.g., eduGAIN, InCommon).

---

## Phase 6: Advanced Features (v2.0.0)

**Goal:** Feature-complete release with advanced SAML capabilities.

### Attribute Handling (Shibboleth-style)

Propagate SAML attributes to backend applications via HTTP headers, following the pattern established by Shibboleth SP.

#### Completed:
- [x] Attribute-to-header mapping configuration
- [x] Built-in OID → friendly name mapping for common attributes (eduPerson, SCHAC)
- [x] Multi-valued attribute handling (per-mapping `separator` config, default `;`)
- [x] Integration test for attribute-to-header flow (verify headers reach downstream handlers)
- [x] Optional header prefix (`header_prefix "X-Saml-"`)
- [x] Strip incoming headers with mapped names before injection (prevent spoofing, default enabled)
- [x] Scope-based attribute validation (shibmd:Scope)

### Authentication Options
- [x] Single Logout (SLO) support
- [x] Forced re-authentication (`forceAuthn` parameter for sensitive routes)
- [x] Authentication context class requests (request MFA/specific auth strength)

### Security & Multi-tenancy
- [x] Encrypted assertions
  - crewjam/saml library automatically handles encrypted assertion decryption
  - SP metadata includes encryption KeyDescriptor
  - Property-based tests verify security invariants
  - Fuzz tests verify error handling for malformed encrypted data
- [x] Multiple SP configurations per instance
  - Hostname-based routing for multiple SP configs in single instance
  - Complete isolation between SP configs (per-SP stores/services)
  - Caddyfile syntax: nested `sp` blocks
  - Property-based tests for routing correctness and config validation
  - Backward compatible with single-SP mode
- [x] Certificate rotation handling (multiple signing certs per IdP)
  - All certificates from IdP metadata are included in SAML service configuration
  - crewjam/saml automatically uses all certificates for assertion signature verification
  - Property-based tests verify certificate selection, order independence, and expiry handling
  - Integration tests verify end-to-end flow with multiple certificates
  - Fuzz tests verify robust error handling for malformed certificate data
  - Metadata refresh correctly updates certificates (metadata is source of truth)

### Federation Metadata
- [x] TASK-ECAT-001 - Parse `mdattr:EntityAttributes` for entity categories (R&S, SIRTFI) (fixes ECAT-001)
- [x] TASK-ECAT-002 - Filter IdPs by entity category or assurance level

### Quality
- [ ] TASK-TEST-001 - Test files need updates after hexagonal architecture refactoring (see TEST-001)
- [x] TASK-TEST-002 - Multi-SP handler isolation incomplete (see TEST-002)
- [x] TASK-TEST-003 - Missing property-based test for session isolation (see TEST-003)
- [x] TASK-TEST-004 - Missing integration tests for multi-SP feature (see TEST-004)

**Outcome:** Full-featured SAML SP plugin for Caddy.

---

## Phase 7: Fuzz Testing & Robustness (v2.1.0)

**Goal:** Improve security and robustness through property-based and fuzz testing.

### Priority 1: Security-Critical Targets

#### Completed:
- [x] `FuzzValidateRelayState` - Open redirect prevention (`plugin.go:857`)
  - URL encoding bypasses, protocol-relative URLs, newline injection
- [x] `FuzzCookieSessionGet` - JWT token parsing (`session.go:102`)
  - Malformed base64, truncated tokens, signature bypass attempts
- [x] `FuzzXMLDsigVerify` - XML signature verification (`signature.go:112`)
  - Signature wrapping attacks, multiple signatures, malformed DSig

### Priority 2: High-Value Parsing

#### Completed:
- [x] `FuzzParseMetadata` - Federation metadata XML (`metadata.go:489`)
  - XML bombs, deeply nested structures, invalid UTF-8, memory exhaustion
- [x] `FuzzExtractAndValidateExpiry` - Timestamp validation (`metadata.go:517`)
  - Malformed RFC3339, timezone edge cases, far future/past dates
- [x] `FuzzExtractIdPInfo` - IdP info extraction (`metadata.go:732`)
  - Missing required elements, malformed localized values

### Priority 3: Input Validation

#### Completed:
- [x] `FuzzParseAcceptLanguage` - HTTP header parsing (`internal/adapters/driving/caddy/plugin.go:1314`)
  - Invalid quality values, malformed language tags
- [x] `FuzzMatchesEntityIDPattern` - Glob pattern matching (`metadata.go:112`)
  - ReDoS potential, unexpected matches
- [x] `FuzzParseDuration` - Duration parsing with "d" suffix (`internal/adapters/driving/caddy/plugin.go:1070`)
  - Integer overflow on large day values (fixed with bounds check: max 106751 days)
- [x] `FuzzSelectBestLogo` - Logo size selection (`metadata.go:301`)
  - Integer overflow on height × width calculation (fixed: use int64 for area calculation)

### Priority 4: State & Temporal Logic

#### Completed:
- [x] Property-based test for `InMemoryRequestStore` (`request.go:114`)
  - Single-use enforcement, expiry validation, replay attack prevention
  - Tests: Cycles 9-13 covering single-use, expiry, replay prevention, GetAll consistency, and concurrent access invariants
  - Helper functions extracted: `checkSingleUseInvariant`, `checkExpiryInvariant`, `checkReplayPreventionInvariant`, `checkGetAllConsistencyInvariant`
  - Bugs found: None - implementation correctly enforces single-use through exclusive locking

### Priority 5: Attribute Header Injection

#### Completed:
- [x] `FuzzAttributeHeaderInjection` - Header name/value sanitization
  - Newline injection in header values (HTTP response splitting)
  - Invalid characters in header names
  - Oversized attribute values
- [x] Property-based test for multi-value handling
  - Separator injection attacks (`;` in attribute values)
  - Round-trip consistency (inject → parse → same values)
  - Empty separator defaulting property test (ATTR-003)
  - Separator sanitization edge case fixes (ATTR-005, ATTR-006): separators that sanitize to empty now re-default to `;`
- [x] Property-based test for header stripping
  - Incoming spoofed headers always removed before injection
  - Case-insensitive header matching
  - Multiple header values removed
  - Prefix handling verified
  - Entitlement headers stripped
  - Non-ASCII character handling (Unicode, emoji, normalization forms)
  - Concurrency testing (race condition verification)
  - Default behavior consistency (single-SP vs multi-SP)
- [x] Rollback verification for header mapping errors (HEADER-004, HEADER-009)
  - Rollback mechanism verified: original headers restored when mapping fails
  - Property-based test for rollback invariant
  - Concurrency test for rollback correctness
  - Entitlement header rollback tests (single-SP and multi-SP modes)
  - Fixed inconsistency: multi-SP mode now uses `restoreHeaderState()` consistently
- [x] Rollback verification for entitlement lookup errors (HEADER-012)
  - Fixed inconsistent rollback behavior: lookup errors now restore headers (consistent with mapping errors)
  - Differential test comparing lookup vs mapping error behavior: `TestHeaderStripping_Property_DifferentialLookupVsMappingErrors`
  - Property-based test verifies consistent rollback across all error types
  - Both single-SP and multi-SP modes updated consistently
- [x] Config mutation concurrency fix (HEADER-010)
  - Fixed data races when `HeaderPrefix` or `AttributeHeaders` mutate concurrently with `applyAttributeHeaders()`
  - Added config snapshots during `Provision()` to prevent mutation between validation and runtime
  - Concurrency test: `TestHeaderStripping_Concurrency_ConfigMutationInvariant` verifies header names match validation-time expectations
  - Applied to both single-SP and multi-SP modes
- [x] Header restoration bug fixes (HEADER-015, HEADER-016)
  - Fixed HEADER-015: SAML attributes now always applied even when entitlement lookup fails (removed early return)
  - Fixed HEADER-016: Header value accumulation prevented by deleting headers before restoring in `restoreHeaderState()`
  - Property-based tests: `TestHeaderStripping_Property_SAMLNotSkippedOnEntitlementError`, `TestHeaderStripping_Property_RestoreDoesNotAccumulate`
  - Updated differential test to reflect new behavior: SAML attributes applied regardless of entitlement lookup outcome

### Infrastructure

- [ ] TASK-FUZZ-001 - Create `*_fuzz_test.go` files with Go 1.18+ native fuzzing
- [ ] TASK-FUZZ-002 - Add fuzz corpus directories (`testdata/fuzz/`)
- [ ] TASK-FUZZ-003 - GitHub Actions workflow for nightly fuzzing campaigns
- [ ] TASK-FUZZ-004 - XML bomb protection (max entity expansion limit)
- [ ] TASK-FUZZ-005 - Metadata size limits configuration

**Outcome:** No crashes in 24-hour fuzzing runs, improved confidence in security-critical code paths.

---

## Phase 8: Local Entitlements (v2.2.0)

**Goal:** Lightweight file-based authorization for small internal services without external infrastructure.

### Core Features

- [x] File-based entitlements store (JSON/YAML)
- [x] User lookup by SAML subject (exact match)
- [x] Pattern/scope matching (`*@example.edu`, `staff@*`)
- [x] Hot-reload on file change (like metadata refresh)
- [x] Inject local entitlements as HTTP header

### Access Control

- [x] `default_action deny` - reject users not in entitlements file (allowlist mode)
- [x] `default_action allow` - permit all authenticated users (blocklist mode)
- [x] Custom deny page/redirect for unauthorized users
- [x] Require specific entitlement for route access (`require_entitlement admin`)

### Integration

- [x] Combine with SAML attributes (local entitlements supplement IdP-provided ones)
- [x] Example: `examples/local-entitlements/` with Caddyfile and sample JSON
- [ ] TASK-DOC-001 - Documentation: when to use local entitlements vs external authz

### Testing

- [x] Unit tests for pattern matching
- [x] Integration tests for file reload
- [x] Fuzz test for pattern matching (ReDoS prevention)
- [x] Property-based test for allowlist/blocklist consistency

**Outcome:** Small deployments can manage access control without external authorization infrastructure.

---

## Future (post-v2)

- Redis/database session storage for HA
- IdP-initiated SSO support
- SCIM provisioning integration
- Admin API for runtime IdP management
- Submit to Caddy plugin directory (caddyserver.com/download)
