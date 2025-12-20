package logo

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// ErrLogoNotFound is returned when a logo cannot be found for an IdP.
var ErrLogoNotFound = fmt.Errorf("logo not found")

// ErrLogoFetchFailed is returned when fetching a logo fails.
var ErrLogoFetchFailed = fmt.Errorf("logo fetch failed")

// ErrInvalidContentType is returned when the logo has an invalid content type.
var ErrInvalidContentType = fmt.Errorf("invalid content type")

// allowedLogoContentTypes are the content types we accept for logos.
var allowedLogoContentTypes = map[string]bool{
	"image/png":     true,
	"image/jpeg":    true,
	"image/gif":     true,
	"image/svg+xml": true,
	"image/webp":    true,
}

const defaultMaxLogoSize = 5 * 1024 * 1024 // 5MB

// LogoStoreOption is a functional option for configuring logo stores.
type LogoStoreOption func(*logoStoreOptions)

type logoStoreOptions struct {
	maxSize int64
}

// WithLogoMaxSize sets the maximum logo size in bytes.
func WithLogoMaxSize(size int64) LogoStoreOption {
	return func(o *logoStoreOptions) {
		o.maxSize = size
	}
}

// CachingLogoStore fetches logos from URLs and caches them.
// Thread-safe: uses fetchMu to serialize fetch operations per entityID,
// preventing multiple concurrent HTTP requests for the same uncached logo.
type CachingLogoStore struct {
	metadataStore ports.MetadataStore
	httpClient    *http.Client
	cache         *InMemoryLogoStore
	maxSize       int64

	// Concurrency control for fetch operations
	fetchMu   sync.Mutex           // Serializes access to fetching map
	fetching  map[string]chan struct{} // Tracks in-progress fetches by entityID
}

// NewCachingLogoStore creates a new caching logo store.
func NewCachingLogoStore(metadataStore ports.MetadataStore, httpClient *http.Client, opts ...LogoStoreOption) *CachingLogoStore {
	options := &logoStoreOptions{
		maxSize: defaultMaxLogoSize,
	}
	for _, opt := range opts {
		opt(options)
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &CachingLogoStore{
		metadataStore: metadataStore,
		httpClient:    httpClient,
		cache:         NewInMemoryLogoStore(),
		maxSize:       options.maxSize,
		fetching:      make(map[string]chan struct{}),
	}
}

// Get returns a logo for the given entity ID, fetching and caching if needed.
// Thread-safe: serializes concurrent fetches for the same entityID.
func (s *CachingLogoStore) Get(entityID string) (*ports.CachedLogo, error) {
	// Check cache first (fast path)
	if logo, err := s.cache.Get(entityID); err == nil {
		return logo, nil
	}

	// Acquire fetch lock to check/set in-progress state
	s.fetchMu.Lock()

	// Double-check cache while holding lock (may have been populated by another goroutine)
	if logo, err := s.cache.Get(entityID); err == nil {
		s.fetchMu.Unlock()
		return logo, nil
	}

	// Check if fetch is already in progress
	if wait, ok := s.fetching[entityID]; ok {
		s.fetchMu.Unlock()
		// Wait for the in-progress fetch to complete
		<-wait
		// Now the cache should be populated (or failed)
		return s.cache.Get(entityID)
	}

	// Start a new fetch - create wait channel
	wait := make(chan struct{})
	s.fetching[entityID] = wait
	s.fetchMu.Unlock()

	// Cleanup: remove from fetching map and signal waiters
	defer func() {
		s.fetchMu.Lock()
		delete(s.fetching, entityID)
		close(wait)
		s.fetchMu.Unlock()
	}()

	// Get IdP info to find LogoURL
	idp, err := s.metadataStore.GetIdP(entityID)
	if err != nil {
		return nil, ErrLogoNotFound
	}
	if idp.LogoURL == "" {
		return nil, ErrLogoNotFound
	}

	// Fetch logo (only one goroutine does this per entityID)
	logo, err := s.fetchLogo(idp.LogoURL)
	if err != nil {
		return nil, err
	}

	// Cache and return
	s.cache.Set(entityID, logo)
	return logo, nil
}

func (s *CachingLogoStore) fetchLogo(logoURL string) (*ports.CachedLogo, error) {
	resp, err := s.httpClient.Get(logoURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLogoFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrLogoFetchFailed, resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	// Handle Content-Type with charset (e.g., "image/png; charset=utf-8")
	if idx := len(contentType); idx > 0 {
		for i, c := range contentType {
			if c == ';' {
				contentType = contentType[:i]
				break
			}
		}
	}

	if !allowedLogoContentTypes[contentType] {
		return nil, fmt.Errorf("%w: %s", ErrInvalidContentType, contentType)
	}

	// Limit read size
	limitedReader := io.LimitReader(resp.Body, s.maxSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrLogoFetchFailed, err)
	}
	if int64(len(data)) > s.maxSize {
		return nil, fmt.Errorf("%w: logo exceeds max size %d bytes", ErrLogoFetchFailed, s.maxSize)
	}

	return &ports.CachedLogo{Data: data, ContentType: contentType}, nil
}

// Ensure CachingLogoStore implements ports.LogoStore
var _ ports.LogoStore = (*CachingLogoStore)(nil)






