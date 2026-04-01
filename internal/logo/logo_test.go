//go:build unit

package logo

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/quick"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/metadata"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// Cycle 1: Test that LogoStore interface exists and ErrLogoNotFound is defined

func TestLogoStore_Interface(t *testing.T) {
	// Verify interface can be implemented
	var _ ports.LogoStore = (*mockLogoStore)(nil)
}

func TestErrLogoNotFound(t *testing.T) {
	if ErrLogoNotFound == nil {
		t.Fatal("ErrLogoNotFound should not be nil")
	}
	if !errors.Is(ErrLogoNotFound, ErrLogoNotFound) {
		t.Error("errors.Is should match ErrLogoNotFound")
	}
}

// Mock implementation for interface verification
type mockLogoStore struct{}

func (m *mockLogoStore) Get(entityID string) (*ports.CachedLogo, error) {
	return nil, ErrLogoNotFound
}

// Cycle 2: Test InMemoryLogoStore returns cached logo

func TestInMemoryLogoStore_Get_Found(t *testing.T) {
	logo := &ports.CachedLogo{
		Data:        []byte("fake-png-data"),
		ContentType: "image/png",
	}
	store := NewInMemoryLogoStore()
	store.Set("https://idp.example.com", logo)

	result, err := store.Get("https://idp.example.com")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if result.ContentType != "image/png" {
		t.Errorf("ContentType = %q, want %q", result.ContentType, "image/png")
	}
	if !bytes.Equal(result.Data, logo.Data) {
		t.Error("Data mismatch")
	}
}

// Cycle 3: Test InMemoryLogoStore returns ErrLogoNotFound for missing

func TestInMemoryLogoStore_Get_NotFound(t *testing.T) {
	store := NewInMemoryLogoStore()

	_, err := store.Get("https://unknown.example.com")
	if !errors.Is(err, ErrLogoNotFound) {
		t.Errorf("Get() error = %v, want ErrLogoNotFound", err)
	}
}

// Cycle 4: Test CachingLogoStore fetches and caches

func TestCachingLogoStore_FetchesAndCaches(t *testing.T) {
	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("fake-png-data"))
	}))
	defer server.Close()

	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{
		EntityID: "https://idp.example.com",
		LogoURL:  server.URL + "/logo.png",
	}})

	store := NewCachingLogoStore(metadataStore, nil)

	// First call - should fetch
	logo, err := store.Get("https://idp.example.com")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if logo.ContentType != "image/png" {
		t.Errorf("ContentType = %q, want image/png", logo.ContentType)
	}
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d, want 1", fetchCount)
	}

	// Second call - should use cache
	_, err = store.Get("https://idp.example.com")
	if err != nil {
		t.Fatalf("Get() second call failed: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d, want 1 (cached)", fetchCount)
	}
}

// Cycle 5: Test CachingLogoStore returns ErrLogoNotFound for unknown IdP

func TestCachingLogoStore_IdPNotFound(t *testing.T) {
	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{})
	store := NewCachingLogoStore(metadataStore, nil)

	_, err := store.Get("https://unknown.example.com")
	if !errors.Is(err, ErrLogoNotFound) {
		t.Errorf("Get() error = %v, want ErrLogoNotFound", err)
	}
}

// Cycle 6: Test CachingLogoStore returns ErrLogoNotFound when IdP has no logo

func TestCachingLogoStore_NoLogoURL(t *testing.T) {
	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{
		EntityID: "https://idp.example.com",
		LogoURL:  "", // No logo
	}})
	store := NewCachingLogoStore(metadataStore, nil)

	_, err := store.Get("https://idp.example.com")
	if !errors.Is(err, ErrLogoNotFound) {
		t.Errorf("Get() error = %v, want ErrLogoNotFound", err)
	}
}

// Cycle 7: Test CachingLogoStore handles HTTP errors

func TestCachingLogoStore_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{
		EntityID: "https://idp.example.com",
		LogoURL:  server.URL + "/logo.png",
	}})
	store := NewCachingLogoStore(metadataStore, nil)

	_, err := store.Get("https://idp.example.com")
	if !errors.Is(err, ErrLogoFetchFailed) {
		t.Errorf("Get() error = %v, want ErrLogoFetchFailed", err)
	}
}

// Cycle 8: Test CachingLogoStore rejects invalid content types

func TestCachingLogoStore_InvalidContentType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>Not an image</html>"))
	}))
	defer server.Close()

	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{
		EntityID: "https://idp.example.com",
		LogoURL:  server.URL + "/logo.png",
	}})
	store := NewCachingLogoStore(metadataStore, nil)

	_, err := store.Get("https://idp.example.com")
	if !errors.Is(err, ErrInvalidContentType) {
		t.Errorf("Get() error = %v, want ErrInvalidContentType", err)
	}
}

// Cycle 9: Test CachingLogoStore rejects oversized logos

func TestCachingLogoStore_SizeLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		// Write 2MB of data
		w.Write(make([]byte, 2*1024*1024))
	}))
	defer server.Close()

	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{
		EntityID: "https://idp.example.com",
		LogoURL:  server.URL + "/logo.png",
	}})
	store := NewCachingLogoStore(metadataStore, nil, WithLogoMaxSize(1*1024*1024)) // 1MB limit

	_, err := store.Get("https://idp.example.com")
	if err == nil {
		t.Error("Get() should fail for oversized logo")
	}
}

// Cycle 13: Test CachingLogoStore concurrent access - CONC-001
// This test verifies that multiple concurrent Gets for the same uncached logo
// trigger only one HTTP fetch (not multiple due to TOCTOU race).

func TestCachingLogoStore_Concurrency_SingleFetch(t *testing.T) {
	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("fake-png-data"))
	}))
	defer server.Close()

	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{
		EntityID: "https://idp.example.com",
		LogoURL:  server.URL + "/logo.png",
	}})

	store := NewCachingLogoStore(metadataStore, nil)

	const numGoroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, numGoroutines)

	// Start all goroutines at once to maximize race condition probability
	start := make(chan struct{})
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // Wait for signal to start
			_, err := store.Get("https://idp.example.com")
			if err != nil {
				errs <- err
			}
		}()
	}

	// Start all goroutines simultaneously
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("Get() returned error: %v", err)
	}

	// IMPORTANT: With proper fetch serialization, we should have exactly 1 fetch.
	// Without serialization (TOCTOU race), we'll have multiple fetches.
	count := int(fetchCount.Load())
	if count != 1 {
		t.Errorf("fetchCount = %d, want 1 (CONC-001: TOCTOU race detected - multiple concurrent fetches)", count)
	}
}

// Cycle 14: Test CachingLogoStore concurrent Get returns consistent data - CONC-002
// This test verifies that all concurrent Gets receive the same cached data.

func TestCachingLogoStore_Property_CacheConsistency(t *testing.T) {
	f := func(logoData []byte) bool {
		if len(logoData) == 0 || len(logoData) > 1024 {
			return true // Skip edge cases
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			w.Write(logoData)
		}))
		defer server.Close()

		metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{
			EntityID: "https://idp.example.com",
			LogoURL:  server.URL + "/logo.png",
		}})

		store := NewCachingLogoStore(metadataStore, nil)

		const numGoroutines = 20
		var wg sync.WaitGroup
		results := make(chan []byte, numGoroutines)
		errs := make(chan error, numGoroutines)

		start := make(chan struct{})
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				logo, err := store.Get("https://idp.example.com")
				if err != nil {
					errs <- err
					return
				}
				results <- logo.Data
			}()
		}

		close(start)
		wg.Wait()
		close(results)
		close(errs)

		for err := range errs {
			t.Logf("error: %v", err)
			return false
		}

		// All results should be identical
		var first []byte
		for data := range results {
			if first == nil {
				first = data
			} else if !bytes.Equal(first, data) {
				return false // Inconsistent data
			}
		}

		// Data should match original
		return bytes.Equal(first, logoData)
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 10}); err != nil {
		t.Error(err)
	}
}

// Cycle 10: Test InMemoryLogoStore evicts the oldest entry when capacity is exceeded

func TestInMemoryLogoStore_Eviction(t *testing.T) {
	tra.RequireLegacy(t)

	store := NewInMemoryLogoStoreWithCapacity(DefaultLogoCapacity)

	logo := &ports.CachedLogo{Data: []byte("data"), ContentType: "image/png"}

	// Fill to capacity
	for i := 0; i < DefaultLogoCapacity; i++ {
		store.Set(fmt.Sprintf("https://idp%d.example.com", i), logo)
	}

	// Insert one more entry — should evict the first (LRU)
	store.Set("https://idp-new.example.com", logo)

	_, err := store.Get("https://idp0.example.com")
	if !errors.Is(err, ErrLogoNotFound) {
		t.Errorf("expected ErrLogoNotFound for evicted entry, got %v", err)
	}

	// The new entry must be present
	_, err = store.Get("https://idp-new.example.com")
	if err != nil {
		t.Errorf("Get() for new entry failed: %v", err)
	}
}

// Cycle 15: Test InMemoryLogoStore concurrent access is thread-safe

func TestInMemoryLogoStore_Concurrency_ThreadSafe(t *testing.T) {
	store := NewInMemoryLogoStore()

	const numGoroutines = 100
	const numOpsPerGoroutine = 10

	var wg sync.WaitGroup
	errs := make(chan error, numGoroutines*numOpsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			entityID := "https://idp.example.com"
			logo := &ports.CachedLogo{
				Data:        []byte("test-data"),
				ContentType: "image/png",
			}

			for j := 0; j < numOpsPerGoroutine; j++ {
				// Alternate between Set and Get
				if j%2 == 0 {
					store.Set(entityID, logo)
				} else {
					_, _ = store.Get(entityID) // Ignore errors, testing thread-safety not correctness
				}
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent operation error: %v", err)
	}
}
