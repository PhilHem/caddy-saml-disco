package metadata

import (
	"context"
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
	url                          string
	httpClient                   *http.Client
	cacheTTL                     time.Duration
	idpFilter                    string
	registrationAuthorityFilter  string
	entityCategoryFilter         string
	assuranceCertificationFilter string
	signatureVerifier            ports.SignatureVerifier
	logger                       *zap.Logger
	metricsRecorder              ports.MetricsRecorder
	onRefresh                    func(error) // callback after background refresh (for testing)
	clock                        Clock       // for time operations (defaults to RealClock)
	version                      string      // version for User-Agent header

	mu              sync.RWMutex
	idps            []domain.IdPInfo
	lastFetch       time.Time
	etag            string
	lastModified    string
	isFresh         bool       // true if last refresh succeeded
	lastSuccessTime time.Time  // time of last successful refresh
	lastError       error      // error from last refresh (nil if success)
	validUntil      *time.Time // validUntil from metadata (nil if not present)

	// Refresh synchronization - prevents concurrent refreshes
	refreshMu  sync.Mutex
	refreshing bool // true when refresh is in progress

	// Background refresh goroutine management
	stopCh        chan struct{}
	refreshCtx    context.Context    // cancellable context for background refresh
	refreshCancel context.CancelFunc // cancel function for refreshCtx
	closed        bool
}

// NewURLMetadataStore creates a new URLMetadataStore with passive refresh.
// Passive refresh means metadata is only fetched when Refresh() is called
// and the cache has expired (based on cacheTTL).
func NewURLMetadataStore(url string, cacheTTL time.Duration, opts ...MetadataOption) *URLMetadataStore {
	options := processMetadataOptions(opts)
	return &URLMetadataStore{
		url:                          url,
		cacheTTL:                     cacheTTL,
		idpFilter:                    options.idpFilter,
		registrationAuthorityFilter:  options.registrationAuthorityFilter,
		entityCategoryFilter:         options.entityCategoryFilter,
		assuranceCertificationFilter: options.assuranceCertificationFilter,
		signatureVerifier:            options.signatureVerifier,
		logger:                       options.logger,
		metricsRecorder:              options.metricsRecorder,
		onRefresh:                    options.onRefresh,
		clock:                        options.clock,
		version:                      options.version,
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
	s.refreshCtx, s.refreshCancel = context.WithCancel(context.Background())
	if s.logger != nil {
		s.logger.Info("starting background metadata refresh",
			zap.Duration("interval", refreshInterval),
			zap.String("url", url))
	}
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
			// Use cancellable context for background refresh
			startTime := s.clock.Now()
			err := s.doRefresh(s.refreshCtx, true) // force=true bypasses cache TTL
			duration := s.clock.Now().Sub(startTime)
			if s.logger != nil {
				if err != nil {
					s.logger.Warn("background metadata refresh failed",
						zap.Error(err),
						zap.Duration("duration", duration))
				} else {
					s.mu.RLock()
					idpCount := len(s.idps)
					s.mu.RUnlock()
					s.logger.Info("background metadata refresh succeeded",
						zap.Int("idp_count", idpCount),
						zap.Duration("duration", duration))
				}
			}
			if s.onRefresh != nil {
				s.onRefresh(err)
			}
		case <-s.stopCh:
			return
		case <-s.refreshCtx.Done():
			// Context was cancelled (e.g., by Close())
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
		if s.logger != nil {
			s.logger.Info("stopping background metadata refresh")
		}
		close(s.stopCh)
		s.closed = true
		// Cancel refresh context to stop in-progress HTTP requests
		if s.refreshCancel != nil {
			s.refreshCancel()
		}
	}
	return nil
}

// Load fetches and parses the metadata from the URL.
// This should be called during initialization.
func (s *URLMetadataStore) Load() error {
	startTime := s.clock.Now()
	err := s.Refresh(context.Background())
	if err == nil && s.logger != nil {
		s.mu.RLock()
		idpCount := len(s.idps)
		s.mu.RUnlock()
		s.logger.Info("metadata loaded",
			zap.String("source", s.url),
			zap.Int("idp_count", idpCount),
			zap.Duration("duration", s.clock.Now().Sub(startTime)))
	}
	return err
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
	// Acquire refresh lock to prevent concurrent refreshes
	s.refreshMu.Lock()

	// Check if refresh is already in progress
	if s.refreshing {
		s.refreshMu.Unlock()
		// Another refresh is in progress, wait for it or return early
		// For simplicity, we return early - the in-progress refresh will update the cache
		return nil
	}

	// Check if cache is still valid (unless forced) - do this while holding refreshMu
	// to ensure atomic check with refresh state
	s.mu.RLock()
	now := s.clock.Now()
	cacheValid := !force && !s.lastFetch.IsZero() && now.Sub(s.lastFetch) < s.cacheTTL
	if cacheValid {
		ttlRemaining := s.cacheTTL - now.Sub(s.lastFetch)
		idpCount := len(s.idps)
		s.mu.RUnlock()
		s.refreshMu.Unlock()
		if s.logger != nil {
			s.logger.Debug("using cached metadata",
				zap.Duration("ttl_remaining", ttlRemaining),
				zap.Int("idp_count", idpCount))
		}
		return nil // Cache hit
	}
	// Read etag/lastModified while holding both locks to ensure consistency
	etag := s.etag
	lastModified := s.lastModified
	s.mu.RUnlock()

	// Mark refresh as in progress
	s.refreshing = true
	s.refreshMu.Unlock()

	// Log cache miss (fetching)
	if s.logger != nil {
		s.logger.Debug("fetching metadata",
			zap.String("url", s.url),
			zap.Bool("forced", force))
	}

	// Ensure we clear refreshing flag when done
	defer func() {
		s.refreshMu.Lock()
		s.refreshing = false
		s.refreshMu.Unlock()
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		refreshErr := fmt.Errorf("create request: %w", err)
		s.markRefreshFailed(refreshErr)
		return refreshErr
	}

	// Set User-Agent header for identification
	version := s.version
	if version == "" {
		version = "unknown"
	}
	req.Header.Set("User-Agent", "caddy-saml-disco/"+version)

	// Add conditional request headers if we have cached values
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	// Time the HTTP request
	httpStartTime := s.clock.Now()
	resp, err := s.httpClient.Do(req)
	responseTime := s.clock.Now().Sub(httpStartTime)
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
		if s.logger != nil {
			s.logger.Debug("metadata not modified (304)",
				zap.Duration("response_time", responseTime),
				zap.String("etag", etag))
		}
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

	// Use shared loader for verify -> parse -> filter pipeline
	result, err := LoadAndProcessMetadata(data, LoaderConfig{
		Source:                       s.url,
		SignatureVerifier:            s.signatureVerifier,
		Logger:                       s.logger,
		IdPFilter:                    s.idpFilter,
		RegistrationAuthorityFilter:  s.registrationAuthorityFilter,
		EntityCategoryFilter:         s.entityCategoryFilter,
		AssuranceCertificationFilter: s.assuranceCertificationFilter,
	})
	if err != nil {
		s.markRefreshFailed(err)
		return err
	}

	// Success - update all state
	successTime := s.clock.Now()
	newEtag := resp.Header.Get("ETag")
	s.mu.Lock()
	s.idps = result.IdPs
	s.lastFetch = successTime
	s.etag = newEtag
	s.lastModified = resp.Header.Get("Last-Modified")
	s.isFresh = true
	s.lastSuccessTime = successTime
	s.lastError = nil
	s.validUntil = result.ValidUntil
	s.mu.Unlock()

	if s.logger != nil {
		s.logger.Debug("metadata fetched (200 OK)",
			zap.Int("idp_count", len(result.IdPs)),
			zap.Duration("response_time", responseTime),
			zap.String("new_etag", newEtag))
	}

	if s.metricsRecorder != nil {
		s.metricsRecorder.RecordMetadataRefresh("url", true, len(result.IdPs))
	}

	return nil
}

// applyFiltersAndCollectFailures applies all configured filters and collects
// which filters would reduce the IdP set to zero. Returns filtered IdPs and
// a list of filter failure descriptions.
func (s *URLMetadataStore) applyFiltersAndCollectFailures(idps []domain.IdPInfo) ([]domain.IdPInfo, []string) {
	return applyFiltersAndCollectFailures(
		idps,
		s.idpFilter,
		s.registrationAuthorityFilter,
		s.entityCategoryFilter,
		s.assuranceCertificationFilter,
	)
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
