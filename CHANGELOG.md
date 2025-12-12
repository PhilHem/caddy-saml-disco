# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
