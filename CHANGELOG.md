# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
