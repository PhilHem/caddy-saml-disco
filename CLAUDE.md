# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A **Caddy v2 plugin** providing SAML Service Provider authentication with Discovery Service:

- Hexagonal architecture (pure core, ports, adapters)
- SAML SP protecting reverse proxy routes
- Dynamic metadata aggregate loading (XML with many IdPs)
- JSON API for custom frontends + default HTML UI
- Cookie-based JWT sessions

## Build Commands

```bash
# Install dependencies
go mod download

# Run all tests
go test ./...

# Run single test
go test -v -run TestMetadataLoading ./metadata_test.go

# Run tests with race detection
go test -race ./...

# Build Caddy with plugin (using xcaddy)
xcaddy build --with github.com/yourusername/caddy-saml-disco=.

# Lint
golangci-lint run

# Format
gofmt -w .
```

### Dependency Management

Use standard Go modules:

```bash
go get github.com/crewjam/saml@latest   # Add/update dependency
go mod tidy                              # Clean up go.mod/go.sum
```

### Version Bumping

Update version constant in `plugin.go` and tag the release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

### Releasing

Releases are automated via GitHub Actions on version tags:

```bash
git tag v0.9.1
git push origin v0.9.1
```

The workflow cross-compiles all platforms (linux/amd64, linux/arm64, darwin/arm64, windows/amd64) from a single ubuntu-latest runner using `CGO_ENABLED=0`. This is intentional - pure Go with no CGO produces identical binaries regardless of build platform, making cross-compilation both cheaper and simpler than native builds.

Use pre-release tags (e.g., `v0.9.1-rc1`) to test the release workflow without creating an official release.

### Release Tracking Files

This project uses `CHANGELOG.md` and `ROADMAP.md` to track changes:

- **CHANGELOG.md** - Version history with changes per release
- **ROADMAP.md** - Development phases and progress

Before releasing, check if these files need updates based on commits since last tag.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Caddy Server                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              caddy-saml-disco plugin                     ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  ││
│  │  │   SAML SP    │  │  Discovery   │  │   Session     │  ││
│  │  │   Handler    │  │  Service     │  │   Manager     │  ││
│  │  └──────────────┘  └──────────────┘  └───────────────┘  ││
│  │  ┌──────────────────────────────────────────────────┐   ││
│  │  │         Metadata Store (cached)                  │   ││
│  │  │  - Load from URL or file                         │   ││
│  │  │  - Parse aggregate XML                           │   ││
│  │  │  - TTL-based refresh                             │   ││
│  │  └──────────────────────────────────────────────────┘   ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### Core Domain

- **Pure Go only** - no Caddy imports, no HTTP, no I/O
- Contains: data models, interfaces (ports), domain logic
- Models: `Session`, `IdPInfo`, `SAMLConfig`, `ErrorCode`, `AppError`

### Ports (Interfaces)

```go
type MetadataStore interface {
    GetIdP(entityID string) (*IdPInfo, error)
    ListIdPs(filter string) ([]IdPInfo, error)
    Refresh(ctx context.Context) error
}

type SessionStore interface {
    Create(session *Session) (string, error)
    Get(token string) (*Session, error)
    Delete(token string) error
}

type LogoStore interface {
    Get(entityID string) (*CachedLogo, error)
}

type RequestStore interface {
    Store(requestID string, expiry time.Time) error
    Valid(requestID string) bool
    GetAll() []string
}

type SignatureVerifier interface {
    Verify(data []byte) ([]byte, error)
}
```

### Adapters

- **Metadata**: `url_metadata.go` (HTTP fetch), `file_metadata.go` (local file)
- **Session**: `cookie_session.go` (JWT in cookies)
- **Logo**: `logo.go` (InMemoryLogoStore, CachingLogoStore)
- **Signature**: `signature.go` (XMLDsigVerifier using goxmldsig, NoopVerifier for testing)
- **Caddy**: `plugin.go` (module registration), `caddyfile.go` (config parsing)

## Folder Structure

```
caddy-saml-disco/
├── go.mod
├── go.sum
├── plugin.go           # Caddy module registration, ServeHTTP
├── config.go           # Configuration struct & validation
├── caddyfile.go        # Caddyfile directive parsing
├── metadata.go         # Metadata aggregate loading & caching
├── logo.go             # Logo proxy/caching (LogoStore port + adapters)
├── request.go          # SAML request ID tracking (RequestStore port + adapters)
├── saml.go             # SAML SP logic (AuthnRequest, ACS)
├── discovery.go        # Discovery Service JSON API & default UI
├── session.go          # Cookie-based JWT session management
├── errors.go           # Structured error types (ErrorCode, AppError)
├── signature.go        # XML signature verification (SignatureVerifier port + adapters)
├── templates/
│   ├── disco.html      # Default IdP selection page (embedded)
│   └── error.html      # Default error page (embedded)
├── examples/
│   └── Caddyfile       # Example configuration
├── testfixtures/
│   └── idp/
│       └── idp.go          # Test IdP using crewjam/saml/samlidp
└── tests/
    ├── metadata_test.go
    ├── session_test.go
    ├── saml_test.go
    └── integration/
        └── flow_test.go
```

## Key Constraints

1. Core domain logic must never import `caddyserver/caddy`
2. Adapters implement port interfaces
3. Plugin exposes SAML endpoints (`/saml/acs`, `/saml/metadata`, `/saml/api/*`)
4. Sessions are JWT-signed cookies using SP private key

## Security Notes

### Cookie Security (Reviewed)

All session cookies use: `HttpOnly`, `Secure` (when TLS), `SameSite=Lax`. This provides CSRF protection without explicit tokens.

### X-Forwarded-Proto Trust Model

The ACS URL resolution (`plugin.go:resolveAcsURL`) trusts `X-Forwarded-Proto` when `r.TLS == nil`. This is intentional for reverse proxy deployments but has implications:

- **Behind trusted proxy (Caddy, nginx)**: Works correctly - proxy sets header
- **Behind untrusted proxy**: Header could be spoofed, affecting ACS URL computation
- **Recommendation**: Configure explicit `acs_url` in Caddyfile when deployment topology is complex

The cookie `Secure` flag correctly uses `r.TLS != nil` (does not trust the header).

### Remaining Security Work

Metadata signature verification and `validUntil` validation are not yet implemented - see ROADMAP.md Phase 4. These are critical for production federation deployments.

## Balancing Abstraction vs Coupling

Hexagonal architecture can lead to over-engineering. Use these indicators:

### Signs of unnecessary indirection

- An interface with only one implementation that will never have another
- Wrapper structs that just delegate to another struct
- Interfaces with a single method that could be a function
- "Manager", "Handler", "Processor" types that don't manage state
- More than 3 layers between HTTP request and response

### Signs of problematic coupling

- Core importing from Caddy packages
- Session adapter importing SAML logic
- Tests requiring a running Caddy server
- Changing a model requires updating more than 3 files

### Rules of thumb

- **No interface without 2+ implementations** (or clear intent for future implementations)
- **Prefer functions over methods** for stateless operations
- **Adapters should be thin** - convert types and delegate, not implement logic
- **If unsure, start concrete** - extract interface when the second use case appears

## Development Workflow (TDD)

This architecture is designed for test-driven development. Always write tests first:

1. **Define the interface** (port)
2. **Write failing tests** against the interface using in-memory implementations
3. **Implement core logic** until tests pass
4. **Add real adapters** that satisfy the same interface

The in-memory implementations are not test doubles - they're production-ready. Unit tests use them directly, keeping tests fast and deterministic.

### Planning Review

After completing any significant implementation, review for roadmap opportunities:

1. **Read ROADMAP.md first** to understand current phases, existing items, and future directions - suggestions must NOT duplicate anything already listed

2. **Identify 3 quick wins** that:
   - Build directly on what was just implemented
   - Are small in scope (1-2 TDD cycles)
   - Complete a natural workflow or fill an obvious gap
   - Are NOT already in the roadmap (check all phases including Future)

3. **Present to user** before adding to `ROADMAP.md`

4. **Use `/update-roadmap`** command to trigger this review

This keeps the roadmap fresh with achievable next steps that leverage recent work.

### Test Organization

- **Unit tests** (`*_test.go`): Core only, use in-memory stores, no I/O
- **Integration tests** (`tests/integration/`): Test with real HTTP, real metadata files
- **E2E tests**: Full Caddy server with plugin, test against test IdP fixture

### Test IdP Fixture

Integration and E2E tests use a test IdP built on `crewjam/saml/samlidp`. This provides:

- In-process IdP server (no external dependencies)
- Programmatic user/SP management
- Full SAML flow support (AuthnRequest → Response)

Location: `testfixtures/idp/`

```go
// Usage in tests
idp := testfixtures.NewTestIdP(t)
defer idp.Close()

// Register SP and create test user
idp.AddServiceProvider(spMetadataURL)
idp.AddUser("testuser", "password")

// Get IdP metadata URL for SP configuration
idpMetadataURL := idp.MetadataURL()
```

The test IdP:
- Runs on `httptest.Server` (random port)
- Uses `samlidp.MemoryStore` (no persistence)
- Auto-generates certificates for signing
- Provides endpoints: `/metadata`, `/sso`, `/login`

### Test Tags & CI

Tests are tagged by component for selective CI runs:

```go
//go:build unit

//go:build integration

//go:build e2e
```

Run specific components:

```bash
go test -tags=unit ./...
go test -tags=integration ./...
go test -tags=e2e ./...
```

CI runs each tag as a separate job for clear failure isolation.

### CI Parity

**CI must use identical commands to local development.** No separate CI-specific scripts or logic. The GitHub Actions workflow uses `go test` and `golangci-lint` exactly as developers do locally. This ensures:

- What passes locally passes in CI
- No "works on my machine" issues
- Single source of truth for how to run tests

### Pre-commit Hooks

Pre-commit hooks mirror the CI pipeline to catch issues before they reach CI. The hooks run:

1. `gofmt` - Format verification
2. `go vet` - Static analysis
3. `golangci-lint` - Linting
4. `go test -tags=unit` - Unit tests

Install hooks with:

```bash
pre-commit install
```

Run manually:

```bash
pre-commit run --all-files
```

The hooks use the same commands as CI, maintaining parity between local development, pre-commit, and CI.

## Extending the System

### Adding a Metadata Source

1. Implement `MetadataStore` interface
2. Add constructor in `metadata.go`
3. Wire up in `Provision()` based on config
4. Write integration tests

### Adding a Session Backend

1. Implement `SessionStore` interface
2. Add constructor (e.g., `NewRedisSessionStore`)
3. Wire up in `Provision()` based on config
4. Write integration tests

### Adding Discovery UI Customization

1. Templates in `templates/` are embedded via `//go:embed`
2. Users override via `templates_dir` config option
3. JSON API (`/saml/api/*`) enables fully custom frontends

## API Endpoints

```
GET  /saml/metadata          # SP metadata XML
POST /saml/acs               # Assertion Consumer Service
GET  /saml/disco             # Default discovery UI (HTML)
GET  /saml/api/idps          # List IdPs (JSON)
GET  /saml/api/idps?q=term   # Search IdPs (JSON)
POST /saml/api/select        # Select IdP, start SAML flow
GET  /saml/api/session       # Current session info (JSON)
GET  /saml/api/logo/{id}     # Proxied/cached IdP logo
```

## Goals & Non-Goals

### Goals

- Protect Caddy reverse proxy routes with SAML authentication
- Support federation metadata aggregates (many IdPs)
- Provide IdP discovery for users
- Simple cookie-based sessions
- JSON API for custom frontends

### Non-Goals

- Not a full SAML IdP implementation
- Not a replacement for dedicated identity platforms
- No distributed session storage (initially)
- No Single Logout (SLO) in v1

## Future Directions

- Single Logout (SLO) support
- Encrypted assertions
- Redis/database session storage for HA
- Attribute mapping configuration
- Multiple SP configurations per Caddy instance
