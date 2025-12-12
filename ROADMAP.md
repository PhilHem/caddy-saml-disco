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

- [ ] Metadata aggregate parsing (multiple IdPs from one XML)
- [ ] URL-based metadata loading with caching
- [ ] TTL-based metadata refresh
- [ ] IdP filtering by pattern
- [ ] Discovery Service JSON API (`/saml/api/idps`, `/saml/api/select`)
- [ ] Default discovery UI (embedded HTML template)
- [ ] Auto-redirect for single IdP scenarios
- [ ] Search/filter IdPs in API

**Outcome:** Can load federation metadata and present IdP selection to users.

---

## Phase 3: Customization (v0.3.0)

**Goal:** Enable custom frontends and UI customization.

- [ ] Session info endpoint (`/saml/api/session`) - returns JSON with subject, attributes, expiry
- [ ] Template override via `templates_dir` config
- [ ] `login_redirect` for fully custom UIs
- [ ] Remember last-used IdP cookie
- [ ] Custom frontend example in `examples/`
- [ ] CORS headers for SPA frontends (optional)

**Outcome:** Users can build custom discovery UIs consuming the JSON API.

---

## Phase 4: Production Hardening (v0.4.0)

**Goal:** Production-ready with proper error handling and logging.

- [ ] Structured logging via Caddy's logger
- [ ] Comprehensive error pages
- [ ] Request ID tracking
- [ ] Metrics exposure (optional)
- [ ] Security review (cookie flags, CSRF, etc.)
- [ ] Documentation site or README expansion
- [ ] Performance testing with large metadata files

**Outcome:** Ready for production use in federation environments.

---

## Phase 5: Advanced Features (v1.0.0)

**Goal:** Feature-complete v1 release.

- [ ] Single Logout (SLO) support
- [ ] Encrypted assertions
- [ ] Attribute mapping configuration
- [ ] Header injection customization
- [ ] Multiple SP configurations per instance
- [ ] Comprehensive test suite (unit, integration, e2e)

**Outcome:** Full-featured SAML SP plugin for Caddy.

---

## Future (post-v1)

- Redis/database session storage for HA
- IdP-initiated SSO support
- SCIM provisioning integration
- Admin API for runtime IdP management
