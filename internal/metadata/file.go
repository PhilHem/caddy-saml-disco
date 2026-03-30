package metadata

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// FileMetadataStore loads IdP metadata from a local file.
// Supports both single EntityDescriptor and aggregate EntitiesDescriptor formats.
type FileMetadataStore struct {
	path                         string
	idpFilter                    string
	registrationAuthorityFilter  string
	entityCategoryFilter         string
	assuranceCertificationFilter string
	signatureVerifier            ports.SignatureVerifier
	logger                       *zap.Logger
	metricsRecorder              ports.MetricsRecorder
	clock                        Clock // for time operations (defaults to RealClock)

	mu         sync.RWMutex
	idps       []domain.IdPInfo // Supports multiple IdPs from aggregate metadata
	validUntil *time.Time       // validUntil from metadata (nil if not present)
}

// NewFileMetadataStore creates a new FileMetadataStore.
func NewFileMetadataStore(path string, opts ...MetadataOption) *FileMetadataStore {
	options := processMetadataOptions(opts)
	return &FileMetadataStore{
		path:                         path,
		idpFilter:                    options.idpFilter,
		registrationAuthorityFilter:  options.registrationAuthorityFilter,
		entityCategoryFilter:         options.entityCategoryFilter,
		assuranceCertificationFilter: options.assuranceCertificationFilter,
		signatureVerifier:            options.signatureVerifier,
		logger:                       options.logger,
		metricsRecorder:              options.metricsRecorder,
		clock:                        options.clock,
	}
}

// Load reads and parses the metadata file.
// This should be called during initialization.
func (s *FileMetadataStore) Load() error {
	startTime := s.clock.Now()
	err := s.Refresh(context.Background())
	if err == nil && s.logger != nil {
		s.mu.RLock()
		idpCount := len(s.idps)
		s.mu.RUnlock()
		s.logger.Info("metadata loaded",
			zap.String("source", s.path),
			zap.Int("idp_count", idpCount),
			zap.Duration("duration", s.clock.Now().Sub(startTime)))
	}
	return err
}

// GetIdP returns the IdP if the entity ID matches.
func (s *FileMetadataStore) GetIdP(entityID string) (*domain.IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.idps {
		if s.idps[i].EntityID == entityID {
			// Return a copy to prevent mutation
			idp := s.idps[i]
			return &idp, nil
		}
	}

	return nil, domain.ErrIdPNotFound
}

// ListIdPs returns all IdPs, optionally filtered by a search term.
// Searches across EntityID, DisplayName, and all DisplayNames language variants.
// Always returns an empty slice (not nil) when no IdPs match.
func (s *FileMetadataStore) ListIdPs(filter string) ([]domain.IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]domain.IdPInfo, 0)
	for _, idp := range s.idps {
		if domain.MatchesSearch(&idp, filter) {
			result = append(result, idp)
		}
	}

	return result, nil
}

// Refresh reloads metadata from the file.
func (s *FileMetadataStore) Refresh(ctx context.Context) error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if s.metricsRecorder != nil {
			s.metricsRecorder.RecordMetadataRefresh("file", false, 0)
		}
		return fmt.Errorf("read metadata file: %w", err)
	}

	// Use shared loader for verify -> parse -> filter pipeline
	result, err := LoadAndProcessMetadata(data, LoaderConfig{
		Source:                       s.path,
		SignatureVerifier:            s.signatureVerifier,
		Logger:                       s.logger,
		IdPFilter:                    s.idpFilter,
		RegistrationAuthorityFilter:  s.registrationAuthorityFilter,
		EntityCategoryFilter:         s.entityCategoryFilter,
		AssuranceCertificationFilter: s.assuranceCertificationFilter,
	})
	if err != nil {
		if s.metricsRecorder != nil {
			s.metricsRecorder.RecordMetadataRefresh("file", false, 0)
		}
		return err
	}

	s.mu.Lock()
	s.idps = result.IdPs
	s.validUntil = result.ValidUntil
	s.mu.Unlock()

	if s.metricsRecorder != nil {
		s.metricsRecorder.RecordMetadataRefresh("file", true, len(result.IdPs))
	}

	return nil
}

// applyFiltersAndCollectFailures applies all configured filters and collects
// which filters would reduce the IdP set to zero. Returns filtered IdPs and
// a list of filter failure descriptions.
func (s *FileMetadataStore) applyFiltersAndCollectFailures(idps []domain.IdPInfo) ([]domain.IdPInfo, []string) {
	return applyFiltersAndCollectFailures(
		idps,
		s.idpFilter,
		s.registrationAuthorityFilter,
		s.entityCategoryFilter,
		s.assuranceCertificationFilter,
	)
}

// ApplyFiltersAndCollectFailures applies all configured filters and collects
// which filters would reduce the IdP set to zero. Returns filtered IdPs
// and a list of filter failure descriptions.
//
// The logger parameter is used for structured logging of filter failures.
// If logger is nil, no logging is performed.
func ApplyFiltersAndCollectFailures(
	idps []domain.IdPInfo,
	idpFilter string,
	registrationAuthorityFilter string,
	entityCategoryFilter string,
	assuranceCertificationFilter string,
	logger *zap.Logger,
) ([]domain.IdPInfo, []string) {
	var failures []string
	idpsBeforeFilter := len(idps)
	// Capture original entity IDs for logging (before any filtering)
	originalEntityIDs := domain.ExtractEntityIDs(idps)

	// Apply IdP filter if configured
	if idpFilter != "" {
		filtered := filterIdPs(idps, idpFilter)
		if len(filtered) == 0 {
			failures = append(failures, fmt.Sprintf("filter pattern %q", idpFilter))
		} else {
			idps = filtered
		}
	}

	// Apply registration authority filter if configured
	if registrationAuthorityFilter != "" {
		filtered := FilterIdPsByRegistrationAuthority(idps, registrationAuthorityFilter)
		if len(filtered) == 0 {
			failures = append(failures, fmt.Sprintf("registration authority filter %q", registrationAuthorityFilter))
		} else {
			idps = filtered
		}
	}

	// Apply entity category filter if configured
	if entityCategoryFilter != "" {
		filtered := FilterIdPsByEntityCategory(idps, entityCategoryFilter)
		if len(filtered) == 0 {
			failures = append(failures, fmt.Sprintf("entity category filter %q", entityCategoryFilter))
		} else {
			idps = filtered
		}
	}

	// Apply assurance certification filter if configured
	if assuranceCertificationFilter != "" {
		filtered := FilterIdPsByAssuranceCertification(idps, assuranceCertificationFilter)
		if len(filtered) == 0 {
			failures = append(failures, fmt.Sprintf("assurance certification filter %q", assuranceCertificationFilter))
		} else {
			idps = filtered
		}
	}

	// Emit structured warning log if there are filter failures
	if len(failures) > 0 && logger != nil {
		// Truncate entity IDs to max 10 for structured logging
		logEntityIDs := originalEntityIDs
		if len(logEntityIDs) > 10 {
			logEntityIDs = logEntityIDs[:10]
		}
		logger.Warn("idp filter matched no IdPs",
			zap.Int("idps_before_filter", idpsBeforeFilter),
			zap.Int("filter_failures", len(failures)),
			zap.Strings("available_entity_ids", logEntityIDs),
		)
	}

	return idps, failures
}

// applyFiltersAndCollectFailures is an internal wrapper for backward compatibility.
func applyFiltersAndCollectFailures(
	idps []domain.IdPInfo,
	idpFilter string,
	registrationAuthorityFilter string,
	entityCategoryFilter string,
	assuranceCertificationFilter string,
) ([]domain.IdPInfo, []string) {
	return ApplyFiltersAndCollectFailures(idps, idpFilter, registrationAuthorityFilter, entityCategoryFilter, assuranceCertificationFilter, nil)
}

// Health returns the health status of the file metadata store.
func (s *FileMetadataStore) Health() domain.MetadataHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return domain.MetadataHealth{
		IsFresh:            len(s.idps) > 0,
		IdPCount:           len(s.idps),
		MetadataValidUntil: s.validUntil,
	}
}

// Ensure FileMetadataStore implements ports.MetadataStore
var _ ports.MetadataStore = (*FileMetadataStore)(nil)
