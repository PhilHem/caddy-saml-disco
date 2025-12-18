package metadata

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// FileMetadataStore loads IdP metadata from a local file.
// Supports both single EntityDescriptor and aggregate EntitiesDescriptor formats.
type FileMetadataStore struct {
	path                        string
	idpFilter                   string
	registrationAuthorityFilter string
	entityCategoryFilter        string
	assuranceCertificationFilter string
	signatureVerifier           ports.SignatureVerifier
	logger                      *zap.Logger
	metricsRecorder             ports.MetricsRecorder

	mu         sync.RWMutex
	idps       []domain.IdPInfo // Supports multiple IdPs from aggregate metadata
	validUntil *time.Time       // validUntil from metadata (nil if not present)
}

// NewFileMetadataStore creates a new FileMetadataStore.
func NewFileMetadataStore(path string, opts ...MetadataOption) *FileMetadataStore {
	options := &metadataOptions{}
	for _, opt := range opts {
		opt(options)
	}
	return &FileMetadataStore{
		path:                        path,
		idpFilter:                   options.idpFilter,
		registrationAuthorityFilter: options.registrationAuthorityFilter,
		entityCategoryFilter:        options.entityCategoryFilter,
		assuranceCertificationFilter: options.assuranceCertificationFilter,
		signatureVerifier:           options.signatureVerifier,
		logger:                      options.logger,
		metricsRecorder:             options.metricsRecorder,
	}
}

// Load reads and parses the metadata file.
// This should be called during initialization.
func (s *FileMetadataStore) Load() error {
	return s.Refresh(context.Background())
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
func (s *FileMetadataStore) ListIdPs(filter string) ([]domain.IdPInfo, error) {
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

// Refresh reloads metadata from the file.
func (s *FileMetadataStore) Refresh(ctx context.Context) error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if s.metricsRecorder != nil {
			s.metricsRecorder.RecordMetadataRefresh("file", false, 0)
		}
		return fmt.Errorf("read metadata file: %w", err)
	}

	// Verify signature if verifier is configured
	if s.signatureVerifier != nil {
		data, err = s.signatureVerifier.Verify(data)
		if err != nil {
			if s.metricsRecorder != nil {
				s.metricsRecorder.RecordMetadataRefresh("file", false, 0)
			}
			return fmt.Errorf("verify metadata signature: %w", err)
		}
	}

	idps, validUntil, err := ParseMetadata(data)
	if err != nil {
		// Log expiry rejections with structured fields
		if errors.Is(err, domain.ErrMetadataExpired) && s.logger != nil {
			s.logger.Warn("metadata expired",
				zap.String("source", s.path),
				zap.Error(err),
			)
		}
		if s.metricsRecorder != nil {
			s.metricsRecorder.RecordMetadataRefresh("file", false, 0)
		}
		return fmt.Errorf("parse metadata: %w", err)
	}

	// Apply all filters and collect failures
	idps, filterFailures := s.applyFiltersAndCollectFailures(idps)
	if len(filterFailures) > 0 {
		if s.metricsRecorder != nil {
			s.metricsRecorder.RecordMetadataRefresh("file", false, 0)
		}
		// Build comprehensive error message with all failing filters
		return fmt.Errorf("no IdPs match filters: %s", strings.Join(filterFailures, ", "))
	}

	s.mu.Lock()
	s.idps = idps
	s.validUntil = validUntil
	s.mu.Unlock()

	if s.metricsRecorder != nil {
		s.metricsRecorder.RecordMetadataRefresh("file", true, len(idps))
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

// applyFiltersAndCollectFailures is a shared helper that applies all configured filters
// and collects which filters would reduce the IdP set to zero. Returns filtered IdPs
// and a list of filter failure descriptions.
func applyFiltersAndCollectFailures(
	idps []domain.IdPInfo,
	idpFilter string,
	registrationAuthorityFilter string,
	entityCategoryFilter string,
	assuranceCertificationFilter string,
) ([]domain.IdPInfo, []string) {
	var failures []string

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

	return idps, failures
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

// filterEmptyStrings removes empty strings from a slice.
func filterEmptyStrings(ss []string) []string {
	var result []string
	for _, s := range ss {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

// filterIdPs returns only IdPs whose entity ID matches the pattern.
func filterIdPs(idps []domain.IdPInfo, pattern string) []domain.IdPInfo {
	if pattern == "" {
		return idps
	}
	var filtered []domain.IdPInfo
	for _, idp := range idps {
		if domain.MatchesEntityIDPattern(idp.EntityID, pattern) {
			filtered = append(filtered, idp)
		}
	}
	return filtered
}

// FilterIdPsByRegistrationAuthority returns only IdPs whose registration authority
// matches the pattern. Supports comma-separated patterns for multiple authorities.
// IdPs without a registration authority are excluded when a filter is active.
func FilterIdPsByRegistrationAuthority(idps []domain.IdPInfo, pattern string) []domain.IdPInfo {
	if pattern == "" {
		return idps
	}

	// Parse comma-separated patterns
	patterns := strings.Split(pattern, ",")
	for i := range patterns {
		patterns[i] = strings.TrimSpace(patterns[i])
	}

	// Filter out empty patterns (METADATA-012: empty pattern matches everything)
	patterns = filterEmptyStrings(patterns)

	var filtered []domain.IdPInfo
	for _, idp := range idps {
		// Skip IdPs without a registration authority
		if idp.RegistrationAuthority == "" {
			continue
		}
		// Check if registration authority matches any pattern
		for _, p := range patterns {
			if domain.MatchesEntityIDPattern(idp.RegistrationAuthority, p) {
				filtered = append(filtered, idp)
				break
			}
		}
	}
	return filtered
}

// FilterIdPsByEntityCategory returns only IdPs that have at least one of the specified entity categories.
// Supports comma-separated categories (OR logic - IdP must have at least one).
// IdPs without any entity categories are excluded when a filter is active.
func FilterIdPsByEntityCategory(idps []domain.IdPInfo, categories string) []domain.IdPInfo {
	if categories == "" {
		return idps
	}

	// Parse comma-separated categories
	categoryList := strings.Split(categories, ",")
	for i := range categoryList {
		categoryList[i] = strings.TrimSpace(categoryList[i])
	}

	// Filter out empty strings (METADATA-013: empty strings never match but are processed)
	categoryList = filterEmptyStrings(categoryList)

	var filtered []domain.IdPInfo
	for _, idp := range idps {
		// Skip IdPs without any categories
		if len(idp.EntityCategories) == 0 {
			continue
		}
		// Check if IdP has at least one of the required categories
		hasMatch := false
		for _, requiredCat := range categoryList {
			for _, idpCat := range idp.EntityCategories {
				if idpCat == requiredCat {
					hasMatch = true
					break
				}
			}
			if hasMatch {
				break
			}
		}
		if hasMatch {
			filtered = append(filtered, idp)
		}
	}
	return filtered
}

// FilterIdPsByAssuranceCertification returns only IdPs that have at least one of the specified assurance certifications.
// Supports comma-separated certifications (OR logic - IdP must have at least one).
// IdPs without any assurance certifications are excluded when a filter is active.
func FilterIdPsByAssuranceCertification(idps []domain.IdPInfo, certifications string) []domain.IdPInfo {
	if certifications == "" {
		return idps
	}

	// Parse comma-separated certifications
	certList := strings.Split(certifications, ",")
	for i := range certList {
		certList[i] = strings.TrimSpace(certList[i])
	}

	// Filter out empty strings (METADATA-013: empty strings never match but are processed)
	certList = filterEmptyStrings(certList)

	var filtered []domain.IdPInfo
	for _, idp := range idps {
		// Skip IdPs without any certifications
		if len(idp.AssuranceCertifications) == 0 {
			continue
		}
		// Check if IdP has at least one of the required certifications
		hasMatch := false
		for _, requiredCert := range certList {
			for _, idpCert := range idp.AssuranceCertifications {
				if idpCert == requiredCert {
					hasMatch = true
					break
				}
			}
			if hasMatch {
				break
			}
		}
		if hasMatch {
			filtered = append(filtered, idp)
		}
	}
	return filtered
}

// Ensure FileMetadataStore implements ports.MetadataStore
var _ ports.MetadataStore = (*FileMetadataStore)(nil)



