//go:build unit

package logo

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

const simEntityID = "https://idp.sim.example.com"

// minimalPNG is a 1x1 transparent PNG (valid image data).
var minimalPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
	0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR chunk length + type
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // width=1, height=1
	0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, // bit depth=8, color type=2 (RGB), crc
	0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, // IDAT chunk
	0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00, // compressed image data
	0x00, 0x00, 0x02, 0x00, 0x01, 0xe2, 0x21, 0xbc, // crc
	0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, // IEND chunk
	0x44, 0xae, 0x42, 0x60, 0x82, // IEND crc
}

// TestSimThunderingHerd_FailureCoalescing verifies that 100 concurrent Gets
// for the same uncached logo trigger exactly one HTTP request even when the
// server returns 500, and that all goroutines receive an error.
func TestSimThunderingHerd_FailureCoalescing(t *testing.T) {
	var requestCount atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{
		EntityID: simEntityID,
		LogoURL:  server.URL + "/logo.png",
	}})
	store := NewCachingLogoStore(metadataStore, nil)

	const numGoroutines = 100
	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines)

	// Barrier: all goroutines start at the same instant.
	start := make(chan struct{})
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.Get(simEntityID)
			errCh <- err
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	// Exactly one HTTP request must have been made.
	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 (thundering herd not coalesced)", got)
	}

	// All goroutines must have received an error (no spurious success).
	errCount := 0
	for err := range errCh {
		if err == nil {
			t.Error("Get() returned nil error on 500 response, want error")
		} else {
			errCount++
		}
	}
	if errCount != numGoroutines {
		t.Errorf("error count = %d, want %d", errCount, numGoroutines)
	}
}

// TestSimThunderingHerd_SuccessAfterFailure verifies that after a failed fetch
// the store retries on the next call (failure is not cached), and that a
// successful response is then served from cache on subsequent calls.
func TestSimThunderingHerd_SuccessAfterFailure(t *testing.T) {
	var requestCount atomic.Int64
	var serveSuccess atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if serveSuccess.Load() {
			w.Header().Set("Content-Type", "image/png")
			w.Write(minimalPNG)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{
		EntityID: simEntityID,
		LogoURL:  server.URL + "/logo.png",
	}})
	store := NewCachingLogoStore(metadataStore, nil)

	// First call: server returns 500 — expect error, request count 1.
	_, err := store.Get(simEntityID)
	if !errors.Is(err, ErrLogoFetchFailed) {
		t.Errorf("first Get() error = %v, want ErrLogoFetchFailed", err)
	}
	if got := requestCount.Load(); got != 1 {
		t.Errorf("after failure: request count = %d, want 1", got)
	}

	// Switch server to success mode.
	serveSuccess.Store(true)

	// Second call: server returns 200 — expect success, request count 2.
	logo, err := store.Get(simEntityID)
	if err != nil {
		t.Fatalf("second Get() failed: %v", err)
	}
	if !bytes.Equal(logo.Data, minimalPNG) {
		t.Error("second Get() returned unexpected logo data")
	}
	if got := requestCount.Load(); got != 2 {
		t.Errorf("after success: request count = %d, want 2", got)
	}

	// Third call: must be served from cache — request count stays at 2.
	logo2, err := store.Get(simEntityID)
	if err != nil {
		t.Fatalf("third Get() failed: %v", err)
	}
	if !bytes.Equal(logo2.Data, minimalPNG) {
		t.Error("third Get() returned unexpected logo data")
	}
	if got := requestCount.Load(); got != 2 {
		t.Errorf("after cache hit: request count = %d, want 2 (served from cache)", got)
	}
}

// TestSimThunderingHerd_SlowServerCoalescing verifies that 50 concurrent Gets
// against a slow server still produce exactly one HTTP request and all
// goroutines receive identical logo data.
func TestSimThunderingHerd_SlowServerCoalescing(t *testing.T) {
	var requestCount atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "image/png")
		w.Write(minimalPNG)
	}))
	defer server.Close()

	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{
		EntityID: simEntityID,
		LogoURL:  server.URL + "/logo.png",
	}})
	// Use a client with a generous timeout to accommodate the sleep.
	httpClient := &http.Client{Timeout: 5 * time.Second}
	store := NewCachingLogoStore(metadataStore, httpClient)

	const numGoroutines = 50
	var wg sync.WaitGroup
	type result struct {
		data []byte
		err  error
	}
	resultCh := make(chan result, numGoroutines)

	start := make(chan struct{})
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			logo, err := store.Get(simEntityID)
			if err != nil {
				resultCh <- result{err: err}
				return
			}
			resultCh <- result{data: logo.Data}
		}()
	}

	close(start)
	wg.Wait()
	close(resultCh)

	// Exactly one HTTP request must have been made.
	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 (slow-server thundering herd not coalesced)", got)
	}

	// All goroutines must have succeeded with identical data.
	successCount := 0
	for res := range resultCh {
		if res.err != nil {
			t.Errorf("Get() returned error: %v", res.err)
			continue
		}
		if !bytes.Equal(res.data, minimalPNG) {
			t.Error("Get() returned unexpected logo data")
		}
		successCount++
	}
	if successCount != numGoroutines {
		t.Errorf("success count = %d, want %d", successCount, numGoroutines)
	}
}
