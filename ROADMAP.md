# Roadmap

Development phases for caddy-saml-disco.

## Phase 1: Foundation (v0.1.0)

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

## Phase 2: Multi-IdP & Discovery (v0.2.0)

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

## Phase 3: Customization (v0.3.0)

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

## Phase 4: Single-IdP Release (v1.0.0)

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

## Phase 5: Federation Hardening (v1.1.0)

**Goal:** Production-ready for large federation environments with multiple IdPs.

### Observability
- [x] Metrics exposure (Prometheus-compatible, optional)
- [x] Signature verification logging (algorithm, cert subject/expiry on success)
- [x] Log metadata expiry rejections (structured logging for `validUntil` failures)
- [x] Expose `validUntil` in health endpoint (`MetadataValidUntil` field for monitoring)
- [x] Instrument metadata refresh with metrics (call `RecordMetadataRefresh` from MetadataStore)

### Federation Features
- [x] Sign SP metadata with SP private key (`sign_metadata` config option)
- [ ] Add signing KeyDescriptor to SP metadata (currently only encryption KeyDescriptor is emitted)
- [x] Filter IdPs by registration authority (`registration_authority_filter` config option)
- [x] Performance testing with large metadata files (1000+ IdPs)
  - Benchmark tests for parsing, search, and lookup operations
  - Fixture generator for synthetic metadata (100-5000 IdPs)
  - Memory usage estimation tests

### Test Infrastructure
- [x] Harden time-based refresh tests (use synchronization instead of `time.Sleep` margins)
  - Added `WithOnRefresh` callback hook for background refresh synchronization
  - Added `WithOnCleanup` callback hook for cleanup goroutine synchronization
  - Added `Clock` interface with `WithClock` option for cache TTL testing without sleep
  - Note: JWT expiration tests retain short sleeps due to external library dependency
- [x] Test fixture: signed metadata generator (runtime signing for integration tests)
  - `testfixtures/metadata/` package with `Signer` type
  - `Sign()` method for signing arbitrary metadata XML
  - `GenerateIdPMetadata()` and `GenerateAggregateMetadata()` convenience methods
  - Full integration with `XMLDsigVerifier` for end-to-end testing
- [x] Test fixture: pre-signed metadata for unit tests (static signed XML matching `testdata/sp-cert.pem`)
  - `testdata/cmd/sign-metadata/main.go` generator tool
  - `testdata/signed/` directory with signed IdP, aggregate, and nested metadata
  - Unit tests in `signature_test.go` (Cycle 2.9)
- [ ] Consolidate duplicate `mockMetricsRecorder` implementations (metrics_test.go and metadata_test.go)

**Outcome:** Ready for production use in large federation environments (e.g., eduGAIN, InCommon).

---

## Phase 6: Advanced Features (v2.0.0)

**Goal:** Feature-complete release with advanced SAML capabilities.

### Attribute Handling (Shibboleth-style)

Propagate SAML attributes to backend applications via HTTP headers, following the pattern established by Shibboleth SP.

- [ ] Attribute-to-header mapping configuration
  ```caddyfile
  attribute_headers {
      urn:oid:1.3.6.1.4.1.5923.1.1.1.6  X-Remote-User      # eduPersonPrincipalName
      urn:oid:1.3.6.1.4.1.5923.1.1.1.7  X-Entitlements     # eduPersonEntitlement
      urn:oid:0.9.2342.19200300.100.1.3 X-Mail             # mail
  }
  ```
- [ ] Built-in OID → friendly name mapping for common attributes (eduPerson, SCHAC)
- [ ] Multi-valued attribute handling (`multi_value_separator` config, default `;`)
- [ ] Optional header prefix (`header_prefix "X-Saml-"`)
- [ ] Strip incoming headers with mapped names before injection (prevent spoofing, default enabled)
- [ ] Scope-based attribute validation (shibmd:Scope)

### Authentication Options
- [ ] Single Logout (SLO) support
- [ ] Forced re-authentication (`forceAuthn` parameter for sensitive routes)
- [ ] Authentication context class requests (request MFA/specific auth strength)

### Security & Multi-tenancy
- [ ] Encrypted assertions
- [ ] Multiple SP configurations per instance
- [ ] Certificate rotation handling (multiple signing certs per IdP)

### Federation Metadata
- [ ] Parse `mdattr:EntityAttributes` for entity categories (R&S, SIRTFI)
- [ ] Filter IdPs by entity category or assurance level

### Quality
- [ ] Comprehensive test suite (unit, integration, e2e)

**Outcome:** Full-featured SAML SP plugin for Caddy.

---

## Phase 7: Fuzz Testing & Robustness (v2.1.0)

**Goal:** Improve security and robustness through property-based and fuzz testing.

### Priority 1: Security-Critical Targets

- [x] `FuzzValidateRelayState` - Open redirect prevention (`plugin.go:857`)
  - URL encoding bypasses, protocol-relative URLs, newline injection
- [x] `FuzzCookieSessionGet` - JWT token parsing (`session.go:102`)
  - Malformed base64, truncated tokens, signature bypass attempts
- [x] `FuzzXMLDsigVerify` - XML signature verification (`signature.go:112`)
  - Signature wrapping attacks, multiple signatures, malformed DSig

### Priority 2: High-Value Parsing

- [x] `FuzzParseMetadata` - Federation metadata XML (`metadata.go:489`)
  - XML bombs, deeply nested structures, invalid UTF-8, memory exhaustion
- [x] `FuzzExtractAndValidateExpiry` - Timestamp validation (`metadata.go:517`)
  - Malformed RFC3339, timezone edge cases, far future/past dates
- [x] `FuzzExtractIdPInfo` - IdP info extraction (`metadata.go:732`)
  - Missing required elements, malformed localized values

### Priority 3: Input Validation

- [ ] `FuzzParseAcceptLanguage` - HTTP header parsing (`plugin.go:1082`)
  - Invalid quality values, malformed language tags
- [ ] `FuzzMatchesEntityIDPattern` - Glob pattern matching (`metadata.go:112`)
  - ReDoS potential, unexpected matches
- [ ] `FuzzParseDuration` - Duration parsing with "d" suffix (`plugin.go:839`)
  - Integer overflow on large day values
- [ ] `FuzzSelectBestLogo` - Logo size selection (`metadata.go:964`)
  - Integer overflow on height × width calculation

### Priority 4: State & Temporal Logic

- [ ] Property-based test for `InMemoryRequestStore` (`request.go:114`)
  - Single-use enforcement, expiry validation, replay attack prevention

### Priority 5: Attribute Header Injection

- [ ] `FuzzAttributeHeaderInjection` - Header name/value sanitization
  - Newline injection in header values (HTTP response splitting)
  - Invalid characters in header names
  - Oversized attribute values
- [ ] Property-based test for header stripping
  - Incoming spoofed headers always removed before injection
  - Case-insensitive header matching
- [ ] Property-based test for multi-value handling
  - Separator injection attacks (`;` in attribute values)
  - Round-trip consistency (inject → parse → same values)

### Infrastructure

- [ ] Create `*_fuzz_test.go` files with Go 1.18+ native fuzzing
- [ ] Add fuzz corpus directories (`testdata/fuzz/`)
- [ ] GitHub Actions workflow for nightly fuzzing campaigns
- [ ] XML bomb protection (max entity expansion limit)
- [ ] Metadata size limits configuration

**Outcome:** No crashes in 24-hour fuzzing runs, improved confidence in security-critical code paths.

---

## Phase 8: Local Entitlements (v2.2.0)

**Goal:** Lightweight file-based authorization for small internal services without external infrastructure.

### Core Features

- [ ] File-based entitlements store (JSON/YAML)
  ```caddyfile
  local_entitlements {
      file /etc/caddy/entitlements.json
      default_action deny   # or "allow"
      header X-Local-Entitlements
  }
  ```
- [ ] User lookup by SAML subject (exact match)
- [ ] Pattern/scope matching (`*@example.edu`, `staff@*`)
- [ ] Hot-reload on file change (like metadata refresh)
- [ ] Inject local entitlements as HTTP header

### Entitlements File Format

```json
{
  "users": {
    "user@example.edu": ["admin", "editor"],
    "other@uni.edu": ["viewer"]
  },
  "patterns": {
    "*@example.edu": ["internal"],
    "admin-*@uni.edu": ["admin"]
  }
}
```

### Access Control

- [ ] `default_action deny` - reject users not in entitlements file (allowlist mode)
- [ ] `default_action allow` - permit all authenticated users (blocklist mode)
- [ ] Custom deny page/redirect for unauthorized users
- [ ] Require specific entitlement for route access (`require_entitlement admin`)

### Integration

- [ ] Combine with SAML attributes (local entitlements supplement IdP-provided ones)
- [ ] Example: `examples/local-entitlements/` with Caddyfile and sample JSON
- [ ] Documentation: when to use local entitlements vs external authz

### Testing

- [ ] Unit tests for pattern matching
- [ ] Integration tests for file reload
- [ ] Fuzz test for pattern matching (ReDoS prevention)
- [ ] Property-based test for allowlist/blocklist consistency

**Outcome:** Small deployments can manage access control without external authorization infrastructure.

---

## Future (post-v2)

- Redis/database session storage for HA
- IdP-initiated SSO support
- SCIM provisioning integration
- Admin API for runtime IdP management
- Submit to Caddy plugin directory (caddyserver.com/download)
