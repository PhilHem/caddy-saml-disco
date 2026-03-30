package metadata

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// urlSnapshot holds an immutable point-in-time view of all URL metadata store state
// that is accessed on the read path. Once created it is never mutated; the atomic
// pointer is swapped atomically on each successful or failed refresh.
type urlSnapshot struct {
	idps            []domain.IdPInfo
	byID            map[string]*domain.IdPInfo
	lastFetch       time.Time
	etag            string
	lastModified    string
	isFresh         bool
	lastSuccessTime time.Time
	lastError       error
	validUntil      *time.Time
}

// newURLSnapshot builds a urlSnapshot with a pre-computed entity-ID index.
func newURLSnapshot(idps []domain.IdPInfo, lastFetch time.Time, etag, lastModified string, isFresh bool, lastSuccessTime time.Time, lastError error, validUntil *time.Time) *urlSnapshot {
	// Copy the slice so the snapshot owns its data independently of the caller.
	copied := make([]domain.IdPInfo, len(idps))
	copy(copied, idps)
	byID := make(map[string]*domain.IdPInfo, len(copied))
	for i := range copied {
		byID[copied[i].EntityID] = &copied[i]
	}
	return &urlSnapshot{
		idps:            copied,
		byID:            byID,
		lastFetch:       lastFetch,
		etag:            etag,
		lastModified:    lastModified,
		isFresh:         isFresh,
		lastSuccessTime: lastSuccessTime,
		lastError:       lastError,
		validUntil:      validUntil,
	}
}

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

	// data holds the current immutable snapshot of all read-path state.
	// Readers call Load() with no locking; writers swap with Store() under refreshMu.
	data atomic.Pointer[urlSnapshot]

	// Refresh synchronization - prevents concurrent refreshes
	refreshMu  sync.Mutex
	refreshing bool // true when refresh is in progress; protected by refreshMu

	// closed is set to true by Close(); separate from data so it can be written
	// without constructing a new snapshot.
	closed atomic.Bool

	// Background refresh goroutine management (write-once lifecycle fields)
	stopCh        chan struct{}
	refreshCtx    context.Context    // cancellable context for background refresh
	refreshCancel context.CancelFunc // cancel function for refreshCtx
}

// NewURLMetadataStore creates a new URLMetadataStore with passive refresh.
// Passive refresh means metadata is only fetched when Refresh() is called
// and the cache has expired (based on cacheTTL).
func NewURLMetadataStore(url string, cacheTTL time.Duration, opts ...MetadataOption) *URLMetadataStore {
	options := processMetadataOptions(opts)
	s := &URLMetadataStore{
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
	// Install an empty initial snapshot so Load() always returns a non-nil pointer.
	s.data.Store(newURLSnapshot(nil, time.Time{}, "", "", false, time.Time{}, nil, nil))
	return s
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
					s.logger.Info("background metadata refresh succeeded",
						zap.Int("idp_count", len(s.data.Load().idps)),
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
	// CompareAndSwap ensures only one caller wins the race to close.
	if s.stopCh != nil && s.closed.CompareAndSwap(false, true) {
		if s.logger != nil {
			s.logger.Info("stopping background metadata refresh")
		}
		close(s.stopCh)
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
		s.logger.Info("metadata loaded",
			zap.String("source", s.url),
			zap.Int("idp_count", len(s.data.Load().idps)),
			zap.Duration("duration", s.clock.Now().Sub(startTime)))
	}
	return err
}

// GetIdP returns the IdP if the entity ID matches.
func (s *URLMetadataStore) GetIdP(entityID string) (*domain.IdPInfo, error) {
	snap := s.data.Load()
	if idp, ok := snap.byID[entityID]; ok {
		// Return a copy so callers cannot mutate snapshot internals.
		result := *idp
		return &result, nil
	}
	return nil, domain.ErrIdPNotFound
}

// ListIdPs returns all IdPs, optionally filtered by a search term.
// Searches across EntityID, DisplayName, and all DisplayNames language variants.
// Always returns an empty slice (not nil) when no IdPs match.
func (s *URLMetadataStore) ListIdPs(filter string) ([]domain.IdPInfo, error) {
	snap := s.data.Load()
	result := make([]domain.IdPInfo, 0)
	for _, idp := range snap.idps {
		idp := idp // local copy for pointer stability inside MatchesSearch
		if domain.MatchesSearch(&idp, filter) {
			result = append(result, idp)
		}
	}
	return result, nil
}

// IsFresh returns true if the cached metadata is from a successful recent refresh.
// Returns false before any load, or after a failed refresh (stale data is still served).
func (s *URLMetadataStore) IsFresh() bool {
	return s.data.Load().isFresh
}

// LastError returns the error from the most recent failed refresh, or nil if
// the last refresh succeeded.
func (s *URLMetadataStore) LastError() error {
	return s.data.Load().lastError
}

// Health returns comprehensive health status for monitoring.
func (s *URLMetadataStore) Health() domain.MetadataHealth {
	snap := s.data.Load()
	return domain.MetadataHealth{
		IsFresh:            snap.isFresh,
		LastSuccessTime:    snap.lastSuccessTime,
		LastError:          snap.lastError,
		IdPCount:           len(snap.idps),
		MetadataValidUntil: snap.validUntil,
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
	// to ensure atomic check with refresh state.
	// A single Load() gives us a consistent view of all read-path fields.
	snap := s.data.Load()
	now := s.clock.Now()
	cacheValid := !force && !snap.lastFetch.IsZero() && now.Sub(snap.lastFetch) < s.cacheTTL
	if cacheValid {
		ttlRemaining := s.cacheTTL - now.Sub(snap.lastFetch)
		idpCount := len(snap.idps)
		s.refreshMu.Unlock()
		if s.logger != nil {
			s.logger.Debug("using cached metadata",
				zap.Duration("ttl_remaining", ttlRemaining),
				zap.Int("idp_count", idpCount))
		}
		return nil // Cache hit
	}
	// Read etag/lastModified from the snapshot before marking refresh in progress.
	etag := snap.etag
	lastModified := snap.lastModified

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

	// Handle 304 Not Modified - data hasn't changed, still counts as success.
	// Build a new snapshot preserving all IdP data, just updating the freshness fields.
	if resp.StatusCode == http.StatusNotModified {
		prev := s.data.Load()
		s.data.Store(newURLSnapshot(
			prev.idps,
			s.clock.Now(), // updated lastFetch
			prev.etag,
			prev.lastModified,
			true,                 // isFresh
			prev.lastSuccessTime, // lastSuccessTime unchanged (data didn't change)
			nil,                  // lastError cleared
			prev.validUntil,
		))
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

	// Success - atomically install a new snapshot with all updated state.
	successTime := s.clock.Now()
	newEtag := resp.Header.Get("ETag")
	s.data.Store(newURLSnapshot(
		result.IdPs,
		successTime,
		newEtag,
		resp.Header.Get("Last-Modified"),
		true, // isFresh
		successTime,
		nil, // lastError cleared
		result.ValidUntil,
	))

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

// markRefreshFailed atomically installs a new snapshot with the error recorded
// and isFresh cleared, while preserving the existing IdP data (stale but served).
func (s *URLMetadataStore) markRefreshFailed(err error) {
	prev := s.data.Load()
	s.data.Store(newURLSnapshot(
		prev.idps,
		prev.lastFetch,
		prev.etag,
		prev.lastModified,
		false, // isFresh cleared
		prev.lastSuccessTime,
		err, // lastError set
		prev.validUntil,
	))
	if s.metricsRecorder != nil {
		s.metricsRecorder.RecordMetadataRefresh("url", false, 0)
	}
	// idps, lastSuccessTime are preserved - serve stale data
}

// Ensure URLMetadataStore implements ports.MetadataStore
var _ ports.MetadataStore = (*URLMetadataStore)(nil)
