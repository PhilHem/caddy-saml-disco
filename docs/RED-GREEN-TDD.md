# Red-Green TDD Implementation Plan for Hexagonal Architecture

This document describes the TDD workflow for implementing new features in caddy-saml-disco following hexagonal architecture principles.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      The Hexagonal Pattern                       │
│                                                                  │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│   │   Adapters   │────▶│    Ports     │◀────│   Adapters   │    │
│   │   (Inbound)  │     │ (Interfaces) │     │  (Outbound)  │    │
│   │              │     │              │     │              │    │
│   │  - HTTP      │     │              │     │  - File I/O  │    │
│   │  - Caddy     │     │   ┌──────┐   │     │  - HTTP      │    │
│   │              │     │   │ Core │   │     │  - Database  │    │
│   └──────────────┘     │   │Domain│   │     └──────────────┘    │
│                        │   └──────┘   │                         │
│                        │              │                         │
│                        │  Pure Logic  │                         │
│                        │  No I/O      │                         │
│                        │  No Caddy    │                         │
│                        └──────────────┘                         │
└─────────────────────────────────────────────────────────────────┘
```

## The Red-Green Cycle

### Phase 1: RED - Write Failing Tests

**Goal**: Define the expected behavior through tests before any implementation.

#### Step 1.1: Define the Port (Interface)

Start by defining what the component needs to do, not how.

```go
// request.go - Port definition

// RequestStore tracks SAML AuthnRequest IDs to prevent replay attacks.
// Implementations must be safe for concurrent use.
type RequestStore interface {
    // Store saves a request ID with its expiry time.
    Store(requestID string, expiry time.Time) error

    // Valid checks if a request ID exists and is not expired.
    // Returns true only once per ID (single-use).
    Valid(requestID string) bool

    // GetAll returns all non-expired request IDs.
    GetAll() []string
}
```

**Key principles:**
- Interface describes WHAT, not HOW
- Methods are behavior-focused
- No implementation details leak through
- Document threading requirements in comments

#### Step 1.2: Write Unit Tests Against the Interface

Test the expected behavior using the interface:

```go
// request_test.go

func TestRequestStore_StoreAndValidate(t *testing.T) {
    store := NewInMemoryRequestStore()

    // Store a request with future expiry
    err := store.Store("req-123", time.Now().Add(time.Hour))
    if err != nil {
        t.Fatalf("Store failed: %v", err)
    }

    // Valid should return true first time
    if !store.Valid("req-123") {
        t.Error("Expected Valid to return true for stored request")
    }

    // Valid should return false second time (single-use)
    if store.Valid("req-123") {
        t.Error("Expected Valid to return false on second call")
    }
}

func TestRequestStore_ExpiredRequest(t *testing.T) {
    store := NewInMemoryRequestStore()

    // Store a request with past expiry
    err := store.Store("req-expired", time.Now().Add(-time.Hour))
    if err != nil {
        t.Fatalf("Store failed: %v", err)
    }

    // Valid should return false for expired request
    if store.Valid("req-expired") {
        t.Error("Expected Valid to return false for expired request")
    }
}
```

**At this point, tests should FAIL** - there's no implementation yet.

### Phase 2: GREEN - Minimal Implementation

**Goal**: Make tests pass with the simplest possible implementation.

#### Step 2.1: Implement In-Memory Adapter First

The in-memory implementation serves multiple purposes:
- Fast unit tests (no I/O)
- Development/testing environments
- Reference implementation for the interface

```go
// request.go - In-memory adapter

type InMemoryRequestStore struct {
    mu      sync.RWMutex
    entries map[string]time.Time
}

func NewInMemoryRequestStore() *InMemoryRequestStore {
    return &InMemoryRequestStore{
        entries: make(map[string]time.Time),
    }
}

func (s *InMemoryRequestStore) Store(requestID string, expiry time.Time) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.entries[requestID] = expiry
    return nil
}

func (s *InMemoryRequestStore) Valid(requestID string) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    expiry, ok := s.entries[requestID]
    if !ok {
        return false
    }
    if time.Now().After(expiry) {
        delete(s.entries, requestID)
        return false
    }
    delete(s.entries, requestID) // Single-use
    return true
}

func (s *InMemoryRequestStore) GetAll() []string {
    s.mu.RLock()
    defer s.mu.RUnlock()
    now := time.Now()
    var ids []string
    for id, expiry := range s.entries {
        if now.Before(expiry) {
            ids = append(ids, id)
        }
    }
    return ids
}
```

**Run tests** - they should now pass.

### Phase 3: REFACTOR - Improve Without Changing Behavior

**Goal**: Clean up code while keeping tests green.

Common refactoring patterns:
- Extract helper functions
- Improve naming
- Add missing error handling
- Optimize performance (if needed)

```go
// Add background cleanup for long-running processes
func NewInMemoryRequestStoreWithCleanup(cleanupInterval time.Duration) *InMemoryRequestStore {
    s := &InMemoryRequestStore{
        entries: make(map[string]time.Time),
        stopCh:  make(chan struct{}),
    }
    go s.cleanupLoop(cleanupInterval)
    return s
}
```

### Phase 4: Add Real Adapters

Once the interface is proven via in-memory tests, add production adapters.

#### Example: URL-based Metadata Store

```go
// metadata.go - Port
type MetadataStore interface {
    GetIdP(entityID string) (*IdPInfo, error)
    ListIdPs(filter string) ([]IdPInfo, error)
    Refresh(ctx context.Context) error
    Health() MetadataHealth
}

// In-memory adapter (already tested)
type InMemoryMetadataStore struct { ... }

// File adapter
type FileMetadataStore struct { ... }

// URL adapter (production)
type URLMetadataStore struct { ... }
```

**Key insight**: All adapters implement the same interface, so:
- Unit tests use `InMemoryMetadataStore`
- Integration tests use `FileMetadataStore`
- Production uses `URLMetadataStore`

---

## Complete Example: Adding a New Feature

### Feature: Logo Caching

Let's walk through adding logo caching to the discovery service.

#### Step 1: Define the Port

```go
// logo.go

// LogoStore provides access to cached IdP logos.
type LogoStore interface {
    // Get retrieves a logo by entity ID.
    // Returns cached content if available, fetches if not.
    Get(entityID string) (*CachedLogo, error)
}

// CachedLogo contains logo data and metadata.
type CachedLogo struct {
    ContentType string
    Data        []byte
    FetchedAt   time.Time
}
```

#### Step 2: Write Failing Tests

```go
// logo_test.go

func TestLogoStore_CachesLogos(t *testing.T) {
    // Create store with test metadata containing logo URLs
    idps := []IdPInfo{{
        EntityID: "https://idp.example.com",
        LogoURL:  "https://idp.example.com/logo.png",
    }}
    metadataStore := NewInMemoryMetadataStore(idps)

    // Mock HTTP client that tracks calls
    var fetchCount int
    mockFetcher := func(url string) (*CachedLogo, error) {
        fetchCount++
        return &CachedLogo{
            ContentType: "image/png",
            Data:        []byte("fake-png-data"),
        }, nil
    }

    store := NewCachingLogoStore(metadataStore, mockFetcher)

    // First fetch
    logo1, err := store.Get("https://idp.example.com")
    if err != nil {
        t.Fatalf("Get failed: %v", err)
    }
    if fetchCount != 1 {
        t.Errorf("Expected 1 fetch, got %d", fetchCount)
    }

    // Second fetch should use cache
    logo2, err := store.Get("https://idp.example.com")
    if err != nil {
        t.Fatalf("Get failed: %v", err)
    }
    if fetchCount != 1 {
        t.Errorf("Expected still 1 fetch (cached), got %d", fetchCount)
    }

    if !bytes.Equal(logo1.Data, logo2.Data) {
        t.Error("Cached logo data should match")
    }
}
```

#### Step 3: Implement to Make Tests Pass

```go
// logo.go

type InMemoryLogoStore struct {
    metadataStore MetadataStore
    cache         map[string]*CachedLogo
    mu            sync.RWMutex
}

func NewInMemoryLogoStore(metadataStore MetadataStore) *InMemoryLogoStore {
    return &InMemoryLogoStore{
        metadataStore: metadataStore,
        cache:         make(map[string]*CachedLogo),
    }
}

func (s *InMemoryLogoStore) Get(entityID string) (*CachedLogo, error) {
    // Check cache first
    s.mu.RLock()
    if logo, ok := s.cache[entityID]; ok {
        s.mu.RUnlock()
        return logo, nil
    }
    s.mu.RUnlock()

    // Get IdP to find logo URL
    idp, err := s.metadataStore.GetIdP(entityID)
    if err != nil {
        return nil, err
    }
    if idp.LogoURL == "" {
        return nil, ErrLogoNotFound
    }

    // Fetch and cache
    logo, err := s.fetch(idp.LogoURL)
    if err != nil {
        return nil, err
    }

    s.mu.Lock()
    s.cache[entityID] = logo
    s.mu.Unlock()

    return logo, nil
}
```

#### Step 4: Add Production Adapter

```go
// CachingLogoStore wraps fetching with TTL-based caching
type CachingLogoStore struct {
    metadataStore MetadataStore
    httpClient    *http.Client
    cacheTTL      time.Duration
    cache         map[string]*cachedEntry
    mu            sync.RWMutex
}

type cachedEntry struct {
    logo      *CachedLogo
    expiresAt time.Time
}
```

---

## File Organization

```
caddy-saml-disco/
├── errors.go           # Core: ErrorCode, AppError (no deps)
├── metadata.go         # Port + Adapters: MetadataStore interface + implementations
├── session.go          # Port + Adapter: SessionStore interface + CookieSessionStore
├── request.go          # Port + Adapter: RequestStore interface + InMemoryRequestStore
├── signature.go        # Port + Adapters: SignatureVerifier + XMLDsigVerifier
├── logo.go             # Port + Adapters: LogoStore interface + implementations
│
├── plugin.go           # Caddy adapter: module registration, HTTP routing
├── config.go           # Configuration parsing
├── caddyfile.go        # Caddyfile directive parsing
│
├── *_test.go           # Unit tests (use in-memory adapters)
└── tests/
    ├── integration/    # Integration tests (real files, HTTP)
    └── e2e/            # End-to-end tests (full Caddy server)
```

---

## Testing Strategy

### Unit Tests (Fast, No I/O)

```go
//go:build unit

func TestMetadataStore_ListIdPs(t *testing.T) {
    store := NewInMemoryMetadataStore([]IdPInfo{
        {EntityID: "https://a.example.com", DisplayName: "University A"},
        {EntityID: "https://b.example.com", DisplayName: "University B"},
    })

    idps, err := store.ListIdPs("University")
    // ...
}
```

### Integration Tests (Real Files/HTTP)

```go
//go:build integration

func TestFileMetadataStore_LoadsRealFile(t *testing.T) {
    store := NewFileMetadataStore("testdata/metadata.xml")
    err := store.Load()
    // ...
}
```

### E2E Tests (Full Stack)

```go
//go:build e2e

func TestFullSAMLFlow(t *testing.T) {
    // Start test IdP
    idp := testfixtures.NewTestIdP(t)
    defer idp.Close()

    // Start Caddy with plugin
    // ...

    // Test complete auth flow
    // ...
}
```

---

## Checklist for New Features

- [ ] Define the port (interface) first
- [ ] Write failing unit tests against the interface
- [ ] Implement in-memory adapter to pass tests
- [ ] Refactor while keeping tests green
- [ ] Add production adapter if needed (file, URL, database)
- [ ] Add integration tests for production adapter
- [ ] Wire into plugin.go if HTTP endpoints needed
- [ ] Update ROADMAP.md if part of a planned feature

---

## Anti-Patterns to Avoid

### ❌ Testing Implementation Details

```go
// Bad: Tests internal state
func TestBad(t *testing.T) {
    store := NewInMemoryRequestStore()
    store.Store("req-1", time.Now().Add(time.Hour))

    // Don't test internal map directly
    if len(store.entries) != 1 {  // ❌ Coupling to implementation
        t.Error("expected 1 entry")
    }
}
```

### ✅ Testing Behavior Through Interface

```go
// Good: Tests observable behavior
func TestGood(t *testing.T) {
    store := NewInMemoryRequestStore()
    store.Store("req-1", time.Now().Add(time.Hour))

    // Test through interface method
    if !store.Valid("req-1") {  // ✅ Tests behavior
        t.Error("expected request to be valid")
    }
}
```

### ❌ Interfaces Without Multiple Implementations

```go
// Bad: Interface with single implementation that will never change
type ConfigLoader interface {
    Load() (*Config, error)
}

type JSONConfigLoader struct{}  // Only implementation ever
```

### ✅ Concrete Types When Appropriate

```go
// Good: Use concrete type when there's only one implementation
func LoadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    // ...
}
```

---

## Domain Models

Keep domain models pure (no external dependencies):

```go
// session.go - Pure domain model

// Session holds authenticated user information.
// This is the core domain model - it has no external dependencies.
type Session struct {
    Subject     string
    Attributes  map[string]string
    IdPEntityID string
    IssuedAt    time.Time
    ExpiresAt   time.Time
}
```

```go
// metadata.go - Pure domain model

// IdPInfo contains information about an Identity Provider.
// This is the core domain model - it has no external dependencies.
type IdPInfo struct {
    EntityID    string
    DisplayName string
    SSOURL      string
    SSOBinding  string
    // ...
}
```

---

## Summary

1. **RED**: Write failing tests that define expected behavior
2. **GREEN**: Implement the simplest code to pass tests
3. **REFACTOR**: Clean up while keeping tests green
4. **Ports**: Define interfaces for what you need (behavior)
5. **Adapters**: Implement interfaces for how you do it (I/O, frameworks)
6. **In-Memory First**: Production-ready in-memory adapters enable fast tests
7. **Pure Core**: Domain models have no external dependencies
