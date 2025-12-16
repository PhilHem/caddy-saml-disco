package metadata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// URLMetadataStore loads IdP metadata from a URL with caching.
type URLMetadataStore struct {
	url                         string
	httpClient                  *http.Client
	cacheTTL                    time.Duration
	idpFilter                   string
	registrationAuthorityFilter string
	signatureVerifier           ports.SignatureVerifier
	logger                      *zap.Logger
	metricsRecorder             ports.MetricsRecorder
	onRefresh                   func(error) // callback after background refresh (for testing)
	clock                       Clock       // for time operations (defaults to RealClock)

	mu              sync.RWMutex
	idps            []domain.IdPInfo
	lastFetch       time.Time
	etag            string
	lastModified    string
	isFresh         bool       // true if last refresh succeeded
	lastSuccessTime time.Time  // time of last successful refresh
	lastError       error      // error from last refresh (nil if success)
	validUntil      *time.Time // validUntil from metadata (nil if not present)

	// Background refresh goroutine management
	stopCh chan struct{}
	closed bool
}

// NewURLMetadataStore creates a new URLMetadataStore with passive refresh.
// Passive refresh means metadata is only fetched when Refresh() is called
// and the cache has expired (based on cacheTTL).
func NewURLMetadataStore(url string, cacheTTL time.Duration, opts ...MetadataOption) *URLMetadataStore {
	options := &metadataOptions{}
	for _, opt := range opts {
		opt(options)
	}
	clock := options.clock
	if clock == nil {
		clock = RealClock{}
	}
	return &URLMetadataStore{
		url:                         url,
		cacheTTL:                    cacheTTL,
		idpFilter:                   options.idpFilter,
		registrationAuthorityFilter: options.registrationAuthorityFilter,
		signatureVerifier:           options.signatureVerifier,
		logger:                      options.logger,
		metricsRecorder:             options.metricsRecorder,
		onRefresh:                   options.onRefresh,
		clock:                       clock,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewURLMetadataStoreWithRefresh creates a new URLMetadataStore with active
// background refresh. The store will periodically fetch metadata at the
// specified refreshInterval, regardless of cache TTL.
// Call Close() to stop the background goroutine.
func NewURLMetadataStoreWithRefresh(url string, refreshInterval time.Duration, opts ...MetadataOption) *URLMetadataStore {
	s := NewURLMetadataStore(url, refreshInterval, opts...)
	s.stopCh = make(chan struct{})
	go s.refreshLoop(refreshInterval)
	return s
}

// refreshLoop runs periodic metadata refresh in the background.
func (s *URLMetadataStore) refreshLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := s.doRefresh(context.Background(), true) // force=true bypasses cache TTL
			if s.logger != nil {
				if err != nil {
					s.logger.Warn("background metadata refresh failed",
						zap.Error(err))
				} else {
					s.mu.RLock()
					idpCount := len(s.idps)
					s.mu.RUnlock()
					s.logger.Info("background metadata refresh succeeded",
						zap.Int("idp_count", idpCount))
				}
			}
			if s.onRefresh != nil {
				s.onRefresh(err)
			}
		case <-s.stopCh:
			return
		}
	}
}

// Close stops the background refresh goroutine if running.
// Safe to call multiple times (idempotent).
// Safe to call on stores created without background refresh.
func (s *URLMetadataStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopCh != nil && !s.closed {
		close(s.stopCh)
		s.closed = true
	}
	return nil
}

// Load fetches and parses the metadata from the URL.
// This should be called during initialization.
func (s *URLMetadataStore) Load() error {
	return s.Refresh(context.Background())
}

// GetIdP returns the IdP if the entity ID matches.
func (s *URLMetadataStore) GetIdP(entityID string) (*domain.IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.idps {
		if s.idps[i].EntityID == entityID {
			idp := s.idps[i]
			return &idp, nil
		}
	}

	return nil, domain.ErrIdPNotFound
}

// ListIdPs returns all IdPs, optionally filtered by a search term.
// Searches across EntityID, DisplayName, and all DisplayNames language variants.
func (s *URLMetadataStore) ListIdPs(filter string) ([]domain.IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.idps) == 0 {
		return nil, nil
	}

	var result []domain.IdPInfo
	for _, idp := range s.idps {
		if domain.MatchesSearch(&idp, filter) {
			result = append(result, idp)
		}
	}

	return result, nil
}

// IsFresh returns true if the cached metadata is from a successful recent refresh.
// Returns false before any load, or after a failed refresh (stale data is still served).
func (s *URLMetadataStore) IsFresh() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isFresh
}

// LastError returns the error from the most recent failed refresh, or nil if
// the last refresh succeeded.
func (s *URLMetadataStore) LastError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastError
}

// Health returns comprehensive health status for monitoring.
func (s *URLMetadataStore) Health() domain.MetadataHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return domain.MetadataHealth{
		IsFresh:            s.isFresh,
		LastSuccessTime:    s.lastSuccessTime,
		LastError:          s.lastError,
		IdPCount:           len(s.idps),
		MetadataValidUntil: s.validUntil,
	}
}

// Refresh fetches metadata from the URL if cache has expired.
// On failure, existing cached data is preserved (graceful degradation) and
// IsFresh() returns false. The error is still returned for logging/monitoring.
func (s *URLMetadataStore) Refresh(ctx context.Context) error {
	return s.doRefresh(ctx, false)
}

// doRefresh fetches metadata from the URL.
// If force is false, respects cache TTL and returns early if cache is valid.
// If force is true, always fetches (used by background refresh).
func (s *URLMetadataStore) doRefresh(ctx context.Context, force bool) error {
	// Check if cache is still valid (unless forced)
	s.mu.RLock()
	if !force && !s.lastFetch.IsZero() && s.clock.Now().Sub(s.lastFetch) < s.cacheTTL {
		s.mu.RUnlock()
		return nil // Cache hit
	}
	etag := s.etag
	lastModified := s.lastModified
	s.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		refreshErr := fmt.Errorf("create request: %w", err)
		s.markRefreshFailed(refreshErr)
		return refreshErr
	}

	// Set User-Agent header for identification
	// Version will be injected by the caller if needed
	req.Header.Set("User-Agent", "caddy-saml-disco/unknown")

	// Add conditional request headers if we have cached values
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		refreshErr := fmt.Errorf("fetch metadata: %w", err)
		s.markRefreshFailed(refreshErr)
		return refreshErr
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified - data hasn't changed, still counts as success
	if resp.StatusCode == http.StatusNotModified {
		s.mu.Lock()
		s.lastFetch = s.clock.Now()
		s.isFresh = true
		s.lastError = nil
		// lastSuccessTime stays the same (data itself didn't change)
		s.mu.Unlock()
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		refreshErr := fmt.Errorf("fetch metadata: HTTP %d", resp.StatusCode)
		s.markRefreshFailed(refreshErr)
		return refreshErr
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		refreshErr := fmt.Errorf("read response: %w", err)
		s.markRefreshFailed(refreshErr)
		return refreshErr
	}

	// Verify signature if verifier is configured
	if s.signatureVerifier != nil {
		data, err = s.signatureVerifier.Verify(data)
		if err != nil {
			refreshErr := fmt.Errorf("verify metadata signature: %w", err)
			s.markRefreshFailed(refreshErr)
			return refreshErr
		}
	}

	idps, validUntil, err := ParseMetadata(data)
	if err != nil {
		// Log expiry rejections with structured fields
		if errors.Is(err, domain.ErrMetadataExpired) && s.logger != nil {
			s.logger.Warn("metadata expired",
				zap.String("source", s.url),
				zap.Error(err),
			)
		}
		refreshErr := fmt.Errorf("parse metadata: %w", err)
		s.markRefreshFailed(refreshErr)
		return refreshErr
	}

	// Apply IdP filter if configured
	if s.idpFilter != "" {
		idps = filterIdPs(idps, s.idpFilter)
		if len(idps) == 0 {
			refreshErr := fmt.Errorf("no IdPs match filter pattern %q", s.idpFilter)
			s.markRefreshFailed(refreshErr)
			return refreshErr
		}
	}

	// Apply registration authority filter if configured
	if s.registrationAuthorityFilter != "" {
		idps = filterIdPsByRegistrationAuthority(idps, s.registrationAuthorityFilter)
		if len(idps) == 0 {
			refreshErr := fmt.Errorf("no IdPs match registration authority filter %q", s.registrationAuthorityFilter)
			s.markRefreshFailed(refreshErr)
			return refreshErr
		}
	}

	// Success - update all state
	now := s.clock.Now()
	s.mu.Lock()
	s.idps = idps
	s.lastFetch = now
	s.etag = resp.Header.Get("ETag")
	s.lastModified = resp.Header.Get("Last-Modified")
	s.isFresh = true
	s.lastSuccessTime = now
	s.lastError = nil
	s.validUntil = validUntil
	s.mu.Unlock()

	if s.metricsRecorder != nil {
		s.metricsRecorder.RecordMetadataRefresh("url", true, len(idps))
	}

	return nil
}

// markRefreshFailed updates state when refresh fails, preserving existing data.
func (s *URLMetadataStore) markRefreshFailed(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isFresh = false
	s.lastError = err
	if s.metricsRecorder != nil {
		s.metricsRecorder.RecordMetadataRefresh("url", false, 0)
	}
	// idps, lastSuccessTime are preserved - serve stale data
}

// Ensure URLMetadataStore implements ports.MetadataStore
var _ ports.MetadataStore = (*URLMetadataStore)(nil)
