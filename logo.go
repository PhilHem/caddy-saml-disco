package caddysamldisco

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
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

// CachedLogo represents a cached IdP logo with its binary data.
type CachedLogo struct {
	Data        []byte
	ContentType string
}

// LogoStore defines the interface for fetching and caching IdP logos.
type LogoStore interface {
	Get(entityID string) (*CachedLogo, error)
}

// InMemoryLogoStore stores logos in memory. Thread-safe.
type InMemoryLogoStore struct {
	mu    sync.RWMutex
	logos map[string]*CachedLogo
}

// NewInMemoryLogoStore creates a new in-memory logo store.
func NewInMemoryLogoStore() *InMemoryLogoStore {
	return &InMemoryLogoStore{logos: make(map[string]*CachedLogo)}
}

// Get returns a cached logo by entity ID.
func (s *InMemoryLogoStore) Get(entityID string) (*CachedLogo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if logo, ok := s.logos[entityID]; ok {
		return logo, nil
	}
	return nil, ErrLogoNotFound
}

// Set stores a logo for the given entity ID.
func (s *InMemoryLogoStore) Set(entityID string, logo *CachedLogo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logos[entityID] = logo
}

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
type CachingLogoStore struct {
	metadataStore MetadataStore
	httpClient    *http.Client
	cache         *InMemoryLogoStore
	maxSize       int64
}

// NewCachingLogoStore creates a new caching logo store.
func NewCachingLogoStore(metadataStore MetadataStore, httpClient *http.Client, opts ...LogoStoreOption) *CachingLogoStore {
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
	}
}

// Get returns a logo for the given entity ID, fetching and caching if needed.
func (s *CachingLogoStore) Get(entityID string) (*CachedLogo, error) {
	// Check cache first
	if logo, err := s.cache.Get(entityID); err == nil {
		return logo, nil
	}

	// Get IdP info to find LogoURL
	idp, err := s.metadataStore.GetIdP(entityID)
	if err != nil {
		return nil, ErrLogoNotFound
	}
	if idp.LogoURL == "" {
		return nil, ErrLogoNotFound
	}

	// Fetch logo
	logo, err := s.fetchLogo(idp.LogoURL)
	if err != nil {
		return nil, err
	}

	// Cache and return
	s.cache.Set(entityID, logo)
	return logo, nil
}

func (s *CachingLogoStore) fetchLogo(logoURL string) (*CachedLogo, error) {
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

	return &CachedLogo{Data: data, ContentType: contentType}, nil
}
