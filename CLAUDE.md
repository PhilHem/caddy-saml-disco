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

### Releasing

Releases are automated via GitHub Actions on version tags:

```bash
git tag v0.9.1
git push origin v0.9.1
```

- Version injected via `-ldflags` (`Version`, `GitCommit`, `BuildTime`)
- Local builds default to `Version="dev"`
- Cross-compiles all platforms with `CGO_ENABLED=0`
- Use pre-release tags (e.g., `v0.9.1-rc1`) to test workflow

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

Core interfaces: `MetadataStore`, `SessionStore`, `LogoStore`, `RequestStore`, `SignatureVerifier`, `MetricsRecorder`. See individual `.go` files for definitions.

### Adapters

- **Metadata**: `url_metadata.go` (HTTP fetch), `file_metadata.go` (local file)
- **Session**: `cookie_session.go` (JWT in cookies)
- **Logo**: `logo.go` (InMemoryLogoStore, CachingLogoStore)
- **Signature**: `signature.go` (XMLDsigVerifier using goxmldsig, NoopVerifier for testing)
- **Metrics**: `metrics.go` (PrometheusMetricsRecorder, NoopMetricsRecorder)
- **Caddy**: `plugin.go` (module registration), `caddyfile.go` (config parsing)

## Key Constraints

1. Core domain logic must never import `caddyserver/caddy`
2. Adapters implement port interfaces
3. Plugin exposes SAML endpoints (`/saml/acs`, `/saml/metadata`, `/saml/api/*`)
4. Sessions are JWT-signed cookies using SP private key

## Security Notes

- **Cookies**: `HttpOnly`, `Secure` (TLS), `SameSite=Lax` ✓
- **X-Forwarded-Proto**: Trusted when `r.TLS == nil` → use explicit `acs_url` in complex deployments
- **Cookie Secure flag**: Uses `r.TLS != nil` (does not trust header)
- **Metadata signature verification**: Enabled via `verify_metadata_signature` + `metadata_signing_cert` config
- **Metadata validUntil**: Automatically validated; expired metadata is rejected with structured logging

## Development Workflow (TDD)

In-memory implementations are production-ready (not test doubles). Unit tests use them directly for fast, deterministic tests.

### Test Organization

- **Unit tests** (`*_test.go`): Core only, use in-memory stores, no I/O
- **Integration tests** (`tests/integration/`): Test with real HTTP, real metadata files
- **E2E tests**: Full Caddy server with plugin, test against test IdP fixture

### Test IdP Fixture

Test IdP in `testfixtures/idp/` using `crewjam/saml/samlidp`:
- Runs on `httptest.Server` (random port, no persistence)
- Auto-generates certificates
- Endpoints: `/metadata`, `/sso`, `/login`

### Test Tags & CI

```bash
go test -tags=unit ./...         # Unit tests only
go test -tags=integration ./...  # Integration tests
go test -tags=e2e ./...          # E2E tests
```

CI runs each tag as a separate job.

### Testing Structured Logging

Use `zaptest/observer` to capture and assert on log output:

```go
core, logs := observer.New(zap.WarnLevel)
logger := zap.New(core)

// ... use logger in test subject ...

warnLogs := logs.FilterMessage("metadata expired")
if warnLogs.Len() == 0 {
    t.Error("expected warning log")
}
fields := warnLogs.All()[0].ContextMap()
if _, ok := fields["source"]; !ok {
    t.Error("expected source field")
}
```

See `metadata_test.go` for examples (search for `observer.New`).

### Testing Time-Based Behavior

For deterministic tests of background refresh, cache TTL, and cleanup cycles, use synchronization hooks instead of `time.Sleep`:

- **Background refresh**: Use `WithOnRefresh(func(error))` callback with a channel
- **Cleanup cycles**: Use `WithOnCleanup(func())` callback with a channel
- **Cache TTL expiration**: Use `WithClock(clock)` with `FakeClock` (defined in `metadata_test.go`)

See `metadata_test.go` for `FakeClock` implementation and usage examples.

**Note**: JWT expiration tests still use short sleeps (10ms) because token validation is handled by the external `crewjam/saml` library.

### Fuzz Testing

Two-tier approach for fuzz tests:

- **Local development** (`plugin_fuzz_test.go`): Minimal seed corpus (~10 entries), fast iteration
- **CI extended** (`plugin_fuzz_ci_test.go`): Full seed corpus (50+ entries), behind `fuzz_extended` build tag

```bash
# Local (fast, ~5s)
go test -fuzz=FuzzValidateRelayState -fuzztime=5s .

# CI (thorough, ~60s)
go test -tags=fuzz_extended -fuzz=FuzzValidateRelayStateExtended -fuzztime=60s .
```

Pattern: Define `checkXxxInvariants()` helper for reuse across both minimal and extended fuzz tests.

### CI Parity & Pre-commit

CI and pre-commit use identical commands to local development:
- `gofmt`, `go vet`, `golangci-lint`, `go test -tags=unit`

Install hooks: `pre-commit install`

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
