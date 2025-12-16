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

	// Apply IdP filter if configured
	if s.idpFilter != "" {
		idps = filterIdPs(idps, s.idpFilter)
		if len(idps) == 0 {
			if s.metricsRecorder != nil {
				s.metricsRecorder.RecordMetadataRefresh("file", false, 0)
			}
			return fmt.Errorf("no IdPs match filter pattern %q", s.idpFilter)
		}
	}

	// Apply registration authority filter if configured
	if s.registrationAuthorityFilter != "" {
		idps = filterIdPsByRegistrationAuthority(idps, s.registrationAuthorityFilter)
		if len(idps) == 0 {
			if s.metricsRecorder != nil {
				s.metricsRecorder.RecordMetadataRefresh("file", false, 0)
			}
			return fmt.Errorf("no IdPs match registration authority filter %q", s.registrationAuthorityFilter)
		}
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

// filterIdPsByRegistrationAuthority returns only IdPs whose registration authority
// matches the pattern. Supports comma-separated patterns for multiple authorities.
// IdPs without a registration authority are excluded when a filter is active.
func filterIdPsByRegistrationAuthority(idps []domain.IdPInfo, pattern string) []domain.IdPInfo {
	if pattern == "" {
		return idps
	}

	// Parse comma-separated patterns
	patterns := strings.Split(pattern, ",")
	for i := range patterns {
		patterns[i] = strings.TrimSpace(patterns[i])
	}

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

// Ensure FileMetadataStore implements ports.MetadataStore
var _ ports.MetadataStore = (*FileMetadataStore)(nil)
