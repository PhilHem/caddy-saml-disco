# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.20.0] - 2026-06-10

### Added
- A `guest_passcode` directive gates the guest-access and bypass-IdP entries: when set, `/saml/api/select` creates a guest or bypass session only if the request carries the matching passcode, compared in constant time.
- The discovery page reveals a passcode field on the gated entries and reports a wrong code inline without leaving the page.

### Changed
- The single-IdP auto-bypass shortcut renders the discovery page instead of creating a bypass session when a passcode is configured.
- An empty `guest_passcode` value is refused at config load.

## [0.19.11] - 2026-06-10

### Fixed
- Caddyfile-configured `metadata_url`/`metadata_file` sources are loaded again: the provisioner now builds a store from `metadata_sources`, restoring a regressed code path that left such instances with no IdP metadata.
- A failed initial metadata load (expired aggregate, unreachable upstream, HTTP error) no longer aborts provisioning. The store starts with an empty IdP list and logs a structured ERROR; all other routes, including non-SAML reverse proxies, continue to serve. Expired metadata is still rejected by the parser, so degradation means an empty IdP list, never serving expired entity descriptors.

### Added
- URL-backed metadata stores that fail their initial load are promoted to background refresh and self-heal once the upstream serves fresh metadata, without requiring a restart. `URLMetadataStore.StartBackgroundRefresh` is idempotent; `CompositeMetadataStore` propagates `StartBackgroundRefresh` and `Close` to its children so background workers are stopped on config reload.

## [0.19.10] - 2026-04-02

### Added
- Background goroutines (metadata refresh, request cleanup, entitlement refresh) now recover from panics and restart automatically ([#80](https://github.com/PhilHem/caddy-saml-disco/issues/80), [#81](https://github.com/PhilHem/caddy-saml-disco/issues/81), [#82](https://github.com/PhilHem/caddy-saml-disco/issues/82), [#83](https://github.com/PhilHem/caddy-saml-disco/issues/83))
- Logo cache is now bounded with LRU eviction, preventing unbounded memory growth ([#84](https://github.com/PhilHem/caddy-saml-disco/issues/84), [#85](https://github.com/PhilHem/caddy-saml-disco/issues/85))
- SLO LogoutResponse is now validated: base64 decode, XML parse, Issuer match, and StatusCode check ([#51](https://github.com/PhilHem/caddy-saml-disco/issues/51), [#86](https://github.com/PhilHem/caddy-saml-disco/issues/86))
- Expired metadata is detected at serve time with structured warning logs, not just at parse time ([#87](https://github.com/PhilHem/caddy-saml-disco/issues/87))
- JWT sessions include a schema version claim; tokens from older schemas force re-authentication instead of silent degradation ([#88](https://github.com/PhilHem/caddy-saml-disco/issues/88))

## [0.19.9] - 2026-04-01

### Changed
- Single-SP and multi-SP modes unified into one codepath; single-SP is now a wildcard entry in the SP registry ([#64](https://github.com/PhilHem/caddy-saml-disco/issues/64), [#65](https://github.com/PhilHem/caddy-saml-disco/issues/65))
- Entitlement header rollback is now always strict: on entitlement lookup failure, no partial headers reach downstream ([#66](https://github.com/PhilHem/caddy-saml-disco/issues/66))
- SP configuration extracted to `internal/config/` package, decoupled from Caddy types ([#69](https://github.com/PhilHem/caddy-saml-disco/issues/69), [#71](https://github.com/PhilHem/caddy-saml-disco/issues/71))
- Authentication and discovery slices now own their HTTP lifecycle via adapters ([#72](https://github.com/PhilHem/caddy-saml-disco/issues/72), [#74](https://github.com/PhilHem/caddy-saml-disco/issues/74))
- Shared request store isolated behind `internal/caddy/internal/sharedstate/` ([#70](https://github.com/PhilHem/caddy-saml-disco/issues/70))
- SAML service accepts request store via constructor instead of creating its own
- Caddyfile parser decomposed into grouped sub-parsers (auth, metadata, session, headers, entitlements, UI, metrics)

### Removed
- All re-export shims and type aliases from caddy/ ([#44](https://github.com/PhilHem/caddy-saml-disco/issues/44), [#59](https://github.com/PhilHem/caddy-saml-disco/issues/59), [#61](https://github.com/PhilHem/caddy-saml-disco/issues/61), [#62](https://github.com/PhilHem/caddy-saml-disco/issues/62))
- Duplicate ForSP method variants and snapshot fallback pattern ([#67](https://github.com/PhilHem/caddy-saml-disco/issues/67))
- Duplicate template sources (caddy/templates/ deleted; discovery/ is the single source) ([#45](https://github.com/PhilHem/caddy-saml-disco/issues/45))

## [0.19.8] - 2026-03-31

### Changed
- Root package reduced to a single file (plugin.go). All re-exports eliminated; tests import internal packages directly.

## [0.19.7] - 2026-03-31

### Fixed
- SAML replay protection: ACS handler now rejects duplicate concurrent submissions by checking request ID consumption ([#1](https://github.com/PhilHem/caddy-saml-disco/issues/1))
- Entitlement bypass: denied users no longer receive a session cookie ([#12](https://github.com/PhilHem/caddy-saml-disco/issues/12))
- SLO handler now parses the Issuer from the LogoutRequest instead of using the first IdP from the metadata list ([#18](https://github.com/PhilHem/caddy-saml-disco/issues/18))

### Added
- `request_ttl` Caddyfile directive to configure SAML request ID lifetime, default 10m ([#20](https://github.com/PhilHem/caddy-saml-disco/issues/20))
- ACS fallback: stores IdP entity ID with each request so authentication survives metadata refreshes ([#22](https://github.com/PhilHem/caddy-saml-disco/issues/22))
- In-flight SAML flows now survive Caddy config reloads via shared request store ([#24](https://github.com/PhilHem/caddy-saml-disco/issues/24))
- 13 simulation tests covering concurrency fault injection and cross-component interactions

### Changed
- All metadata and logo store reads are now lock-free via atomic.Pointer snapshots ([#8](https://github.com/PhilHem/caddy-saml-disco/issues/8), [#9](https://github.com/PhilHem/caddy-saml-disco/issues/9), [#11](https://github.com/PhilHem/caddy-saml-disco/issues/11))
- Package layout flattened from hexagonal nesting to vertical slices: `internal/metadata/`, `internal/session/`, `internal/saml/`, etc.

## [0.19.6] - 2026-03-30

### Changed
- Root package reduced to 6 files: module registration, re-exports, test constructor, and architectural guards. All test files moved to the internal packages they actually test.

## [0.19.5] - 2026-03-30

### Changed
- Root package public API trimmed to only the types and functions used by external consumers, reducing surface area from ~120 re-exports to 23.
- Adapter and domain tests relocated from root package to their internal packages.

## [0.19.4] - 2026-02-25

### Fixed
- Guest access entry now appears at the bottom of the discovery list instead of at the top with pinned IdPs.

## [0.19.3] - 2026-02-25

### Fixed
- Discovery page cards use CSS grid layout so text aligns consistently even when logo is absent (e.g., guest entry).

## [0.19.2] - 2026-02-25

### Fixed
- Pinned IdPs now render with the same card style as regular IdPs in the default discovery template.

## [0.19.1] - 2026-02-25

### Fixed
- Pinned IdPs now appear in the default discovery template.

## [0.19.0] - 2026-02-25

### Added
- **`guest_access` directive**: Add a virtual guest entry to the discovery page that creates a guest session without any SAML authentication or IdP metadata. Unlike `bypass_idp`, no real IdP backing is required. Usage: `guest_access "Extern"`.

## [0.18.2] - 2026-02-06

### Added
- **`bypass_idp` directive**: Skip SAML authentication for specific IdPs. When a user selects a bypassed IdP in the discovery page, a guest session is created immediately without redirecting to the IdP. Useful when an IdP hasn't yet registered the SP metadata.

## [0.17.0] - 2026-01-20

### Added
- **Comma-separated IdP filter patterns**: `idp_filter` now supports comma-separated patterns with OR logic. Use exact entity IDs as a whitelist (e.g., `"https://idp1.example.edu, https://idp2.example.org"`) or mix patterns and exact matches.

### Breaking Changes
- **Remember IdP cookie**: The `/saml/api/select` endpoint now only sets the remember-IdP cookie when `remember: true` is explicitly passed in the request body. Previously, the cookie was always set on IdP selection.

### Changed
- **Error types relocated**: `JSONErrorResponse` and `JSONErrorDetail` types moved from `internal/core/domain/` to `internal/adapters/driving/caddy/` as they are Caddy adapter-specific (HTTP response format). Backward compatibility maintained via root package re-exports in `errors.go`.
- **Architecture refactoring**: Various code organization improvements addressing architecture review findings.

## [0.16.1] - 2026-01-09

### Fixed
- **ACS Issuer validation**: ACS handler now validates SAML response against the Issuer IdP instead of always using the first IdP in the metadata store. This fixes multi-IdP scenarios where responses from non-first IdPs would fail validation.

### Changed
- **Plugin code organization**: Refactored `plugin.go` god file (2787→1659 lines) by extracting:
  - `rendering.go` - HTML/JSON response rendering
  - `headers.go` - SAML attribute to HTTP header mapping
  - `handlers_sp.go` - Multi-SP endpoint handlers
  - `cookies.go` - Session cookie management
  - `urls.go` - SAML callback URL resolution

## [0.16.0] - 2026-01-09

### Added
- **Configuration schema validation**: Validate plugin configuration at startup with clear error messages
- **SAMLDisco factory with functional options**: Cleaner initialization API for the SAMLDisco service
- **BDD testing improvements**:
  - Step definitions for discovery feature tests
  - Step definitions for IdP filter failure scenarios
  - Feature file for IdP filtering behavior
- **Enhanced observability**: WARN logging and improved error messages for filter failures
- **Domain helpers**: `ExtractEntityIDs` and `FormatEntityIDList` utility functions

### Fixed
- **Discovery redirect**: Correctly redirect to discovery page when multiple IdPs are configured
- **Architectural improvements**: Addressed test config smells and improved domain layer cohesion
- **Test infrastructure**: Decoupled test infrastructure and extracted domain logic

### Changed
- **Refactored scope functions**: Consolidated into single domain file for better organization
- **Caddyfile parsing**: Extracted shared `parseConfigDirective` function to reduce duplication

## [0.15.1] - 2026-01-08

### Fixed
- **SAML ACS response parsing**: Call `ParseForm()` before processing SAML response.
  The `crewjam/saml` library uses `req.PostForm.Get("SAMLResponse")` but doesn't call
  `ParseForm()` itself. Without this, `PostForm` is nil and returns empty string,
  causing "invalid xml: no root" errors.

## [0.15.0] - 2026-01-08

### Added
- **SAML auth error observability**:
  - Prometheus metrics for authentication failures (`saml_disco_auth_failures_total` counter)
  - Labels for error category (`reason`) and IdP entity ID (`idp`)
  - Structured error logging with categories: `signature_verification`, `decryption_failed`, `time_constraint`, `idp_status`, `unknown`
  - Time context in logs for time constraint failures
  - IdP status code extraction from SAML responses
- **BDD testing with godog**:
  - Feature file for SAML auth error observability scenarios
  - Step definitions using `zaptest/observer` and Prometheus testutil
  - New `test-bdd` Makefile target
- **Test Responsibility Anchors (TRA)**:
  - Testing infrastructure for architectural test discipline
  - Pre-commit hooks for TRA validation
  - `tra.Require()` markers for test responsibility tracking
- **Enhanced attribute testing**:
  - Property-based tests for attribute mapping
  - Concurrency tests for thread safety

### Changed
- Codebase reformatted with gofmt

## [0.14.0] - 2026-01-07

### Added
- Internal improvements and refactoring

## [0.13.0] - 2025-12-16

### Added
- **Single Logout (SLO) support**:
  - SP-initiated logout flow (`/saml/logout` redirects to IdP SLO when supported)
  - IdP-initiated logout flow (`/saml/slo` endpoint handles LogoutRequest/Response)
  - Session clearing on successful logout
  - Support for `NameIDFormat` and `SessionIndex` in sessions (required for SLO)
- **Forced re-authentication** (`force_authn_paths` config option):
  - Request fresh authentication from IdP for sensitive routes
  - Configurable path patterns for routes requiring re-authentication
  - `ForceAuthn` flag in SAML AuthnRequest
- **Authentication context class requests** (`authn_context` config option):
  - Request specific authentication methods from IdP (e.g., MFA, X.509)
  - Configurable `RequestedAuthnContext` and `AuthnContextComparison` in AuthnRequest
  - Support for SAML 2.0 authentication context classes
- **Encrypted assertions support**:
  - Automatic decryption of encrypted SAML assertions
  - SP metadata includes encryption KeyDescriptor
  - Property-based and fuzz tests for security invariants
- **Certificate rotation handling**:
  - Support for multiple signing certificates per IdP
  - Automatic certificate updates on metadata refresh
  - Property-based tests for certificate selection and expiry handling
- **Multiple SP configurations per instance**:
  - Hostname-based routing for multiple SP configs in single Caddy instance
  - Complete isolation between SP configs (per-SP stores/services)
  - Caddyfile syntax: nested `sp` blocks
  - Backward compatible with single-SP mode
- **Hexagonal architecture refactoring**:
  - Core domain separated from adapters (`internal/core/domain/`, `internal/adapters/`)
  - Improved testability and maintainability
  - Clear separation of concerns
- **Enhanced testing**:
  - Property-based tests for `InMemoryRequestStore` (single-use enforcement, expiry validation)
  - Integration tests for encrypted assertions and certificate rotation
  - Expanded fuzz tests for parsing and validation functions
  - SAML service configuration tests

### Changed
- Significant progress on Phase 6 (Advanced Features)
- Internal architecture refactored to hexagonal pattern

## [0.12.2] - 2025-12-16

### Added
- **Optional header prefix** (`header_prefix` config option):
  - Prepend a prefix to all attribute header names (e.g., `header_prefix "X-Saml-"`)
  - When prefix is set, individual header names don't need the X- prefix
  - Final combined header name (prefix + configured name) must be valid
  - Header stripping logic updated to use prefixed names
  - Comprehensive test coverage (unit + integration)

## [0.12.1] - 2025-12-16

### Added
- **Signing KeyDescriptor in SP metadata**: SP metadata now includes both encryption and signing KeyDescriptor elements, enabling IdPs to properly verify signatures from this SP
- **Pre-signed metadata test fixtures** for deterministic unit tests:
  - `testdata/cmd/sign-metadata/main.go` generator tool using sp-key.pem/sp-cert.pem
  - `testdata/signed/` directory with IdP, aggregate, and nested metadata
  - Unit tests `TestXMLDsigVerifier_Verify_PreSigned*` in signature_test.go

## [0.12.0] - 2025-12-16

### Added
- **SP metadata signing** (`sign_metadata` config option):
  - Sign SP metadata XML output using the SP private key and certificate
  - Enables federations and IdPs to verify SP metadata authenticity
  - New `MetadataSigner` port interface with `XMLDsigSigner` adapter
  - Uses goxmldsig enveloped signatures
- **Additional fuzz testing** for security-critical XML parsing:
  - `FuzzExtractIdPInfo`: IdP info extraction from metadata XML
  - `FuzzValidateTimestamps`: Timestamp and expiry validation
  - `FuzzVerifySignature`: XML signature verification

## [0.11.0] - 2025-12-16

### Added
- **Fuzz testing suite** for security-critical parsing:
  - `FuzzValidateRelayState`: Open redirect prevention with 50+ seed corpus entries (URL encoding bypasses, protocol-relative URLs, header injection)
  - `FuzzCookieSessionGet`: JWT session token parsing (malformed base64, truncated tokens, signature bypass attempts)
  - `FuzzParseMetadata`: SAML metadata XML parsing (malformed XML, nested structures, edge cases)
  - Deterministic time-based tests using synchronization hooks instead of sleeps
- **Performance benchmarks** for large metadata files:
  - Benchmark tests for parsing, search, and lookup operations with 1000+ IdPs
  - Fixture generator for synthetic metadata (100-5000 IdPs)
  - Memory usage estimation tests
- **Registration authority filter** (`registration_authority_filter` config):
  - Filter IdPs by MDRPI registration authority
  - Useful for limiting discovery to specific federations within aggregates
- **Prometheus metrics exposure** (`metrics enabled` config):
  - `MetricsRecorder` port with `PrometheusMetricsRecorder` and `NoopMetricsRecorder` adapters
  - `saml_disco_auth_attempts_total` counter with `idp_entity_id` and `status` labels
  - `saml_disco_sessions_created_total` counter for new session creation
  - `saml_disco_session_validations_total` counter with `status` label (valid/invalid)
  - `saml_disco_metadata_refresh_total` counter with `source` and `status` labels
  - `saml_disco_metadata_idp_count` gauge for current IdP count
  - Metrics exposed via Caddy's admin API `/metrics` endpoint
- **Metadata refresh metrics instrumentation**: `RecordMetadataRefresh` called from `FileMetadataStore` and `URLMetadataStore` on refresh success/failure
- **Structured logging for metadata expiry rejections**: Log warnings with source path/URL when metadata is rejected due to expired `validUntil`
- **Signature verification logging**: Log algorithm, certificate subject, and expiry on successful metadata signature verification
- **Health endpoint `validUntil` field**: `/saml/api/health` now includes `MetadataValidUntil` for monitoring metadata expiry

## [0.10.1] - 2025-12-15

### Fixed
- **Release workflow**: Use `XCADDY_GO_BUILD_FLAGS` environment variable for ldflags injection instead of non-existent `--ldflags` flag

## [0.10.0] - 2025-12-15

### Added
- **Version info in health endpoint**: `/saml/api/health` now includes `version`, `git_commit`, and `build_time` fields for build identification

## [0.9.0] - 2025-12-14

### Added
- **Background metadata refresh** (`background_refresh` config):
  - Periodic refresh using `time.NewTicker` for reliable scheduling
  - Configurable via `background_refresh` boolean option
  - Logging for refresh success/failure events
- **Metadata `validUntil` validation**:
  - Reject expired metadata based on `validUntil` attribute
  - Prevents use of stale federation metadata
- **Health check endpoint** (`GET /saml/api/health`):
  - Exposes `MetadataHealth` status for monitoring
  - Reports metadata freshness and error states
- **Graceful metadata fetch failure handling**:
  - Serve stale metadata when fresh fetch fails
  - Maintains availability during temporary network issues
- **`mdrpi:RegistrationInfo` parsing**:
  - Extract registration authority from SAML metadata
  - Expose registration info in `/saml/api/idps` JSON response
  - Foundation for trust chain validation

### Changed
- Significant progress on Phase 4 (Production Hardening)

## [0.8.0] - 2025-12-14

### Added
- **Metadata signature verification** (`signature_cert` config):
  - XML signature verification using `russellhaering/goxmldsig`
  - `SignatureVerifier` port with `XMLDsigVerifier` and `NoopVerifier` adapters
  - Reject unsigned or invalidly signed metadata when certificate configured
- **Structured error handling**:
  - `ErrorCode` enum and `AppError` type for consistent error responses
  - JSON error responses for API endpoints (`/saml/api/*`)
  - HTML error pages for browser requests
- **Logo proxy/caching endpoint** (`GET /saml/api/logo/{entityID}`):
  - `LogoStore` port with `InMemoryLogoStore` and `CachingLogoStore` adapters
  - Avoids hotlinking federation logos
  - Caches logos in memory with configurable TTL
- **Multi-language display name support**:
  - Parse all `xml:lang` variants from metadata
  - Select display name based on `Accept-Language` header
  - Configurable default language fallback (`default_language` config)
  - Search across all language variants (find "München" with `Accept-Language: en`)
- **Structured logging** via Caddy's zap logger
- **CORS support** for SPA frontends (`cors_origins` config)
- **FeLS-style discovery template** with autocomplete search
- **Custom frontend example** with Alpine.js in `examples/`
- **Remember last-used IdP** cookie for returning users
- **`login_redirect`** config option for custom UI integration

### Changed
- Phase 3 (Customization) complete
- Significant progress on Phase 4 (Production Hardening)

## [0.7.0] - 2025-12-13

### Added
- **Template override system** (`templates_dir` config):
  - Support for custom HTML templates via `templates_dir` configuration
  - Embedded default templates for discovery UI and error pages
  - Automatic fallback to embedded templates when custom files are missing
  - XSS protection via `html/template` escaping
- Default `disco.html` template (extracted from hardcoded HTML)
- Default `error.html` template for error page rendering
- `TemplateRenderer` with `RenderDisco()` and `RenderError()` methods
- `SetTemplateRenderer()` method for testing
- Integration tests for custom template loading

### Changed
- Discovery UI now rendered via Go templates instead of hardcoded HTML
- Phase 3 (Customization) started - template override is first feature complete

## [0.6.0] - 2025-12-12

### Added
- **Discovery Service JSON API**:
  - `GET /saml/api/idps` - List IdPs with optional `?q=` search filtering
  - `POST /saml/api/select` - Select IdP and start SAML authentication
  - `GET /saml/api/session` - Return current session info (authenticated, subject, attributes)
  - `GET /saml/disco` - Default discovery UI with search and IdP selection
- **Auto-redirect for single IdP**: Skip discovery page when only one IdP is configured
- **mdui:UIInfo metadata parsing**:
  - Parse DisplayName, Description, Logo, InformationURL from SAML metadata
  - Prefer English localized values (falls back to first available)
  - Select largest logo by area when multiple logos exist
- `Description`, `LogoURL`, `InformationURL` fields added to `IdPInfo` struct
- IdP filtering by pattern via `idp_filter` config option (glob-like: `*substring*`, `prefix*`, `*suffix`)
- URL-based metadata loading with caching (`metadata_url` config)
- TTL-based metadata refresh (`metadata_refresh_interval` config)
- User-Agent header for metadata HTTP requests (`caddy-saml-disco/<version>`)
- Integration tests for discovery flow

### Changed
- Phase 2 complete - plugin now supports multi-IdP discovery with JSON API and default UI

## [0.5.0] - 2025-12-12

### Added
- Session logout endpoint (`/saml/logout`) with `return_to` parameter support
- Open redirect protection via `validateRelayState()` for RelayState and return_to parameters
- E2E test suite covering full authentication redirect flow
- Unit test for expired JWT tokens using real tokens (not hardcoded strings)

### Security
- RelayState validation blocks absolute URLs, protocol-relative URLs, dangerous schemes (javascript:, data:), and header injection attempts

### Changed
- Phase 1 complete - plugin can now protect routes with SAML auth using a single IdP

## [0.4.1] - 2025-12-12

### Changed
- Session cookie now sets `MaxAge` to match configured `SessionDuration`

## [0.4.0] - 2025-12-12

### Changed
- Session expiry now uses configured `SessionDuration` instead of hardcoded 8 hours

## [0.3.0] - 2025-12-12

### Added
- Direct IdP redirect for unauthenticated users (single IdP flow)
- RelayState support for post-login redirect to original URL
- Error handling for missing metadata store, SAML service, or IdPs

### Changed
- Replaced discovery redirect with direct IdP redirect for Phase 1

## [0.2.0] - 2025-12-12

### Added
- Caddy plugin skeleton with module registration
- Configuration struct with JSON tags and Caddyfile parsing
- Test IdP fixture using crewjam/saml/samlidp
- Single IdP metadata loading from file
- JWT cookie session management with RSA signing
- SAML SP logic: AuthnRequest generation and ACS handling
- SP metadata endpoint
- Session checking middleware for protected routes
- Session context storage for downstream handler access
- Support for custom login redirect URL
- Preserve original URL in return_to parameter for post-login redirect

## [0.1.0] - 2025-12-12

### Added
- Initial project structure
- CLAUDE.md with architectural guidance
- ROADMAP.md with development phases
