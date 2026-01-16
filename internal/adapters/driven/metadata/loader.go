package metadata

import (
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// LoaderConfig contains configuration for LoadAndProcessMetadata.
type LoaderConfig struct {
	// Source is a human-readable identifier for logging (URL, file path, etc.)
	Source string

	// SignatureVerifier verifies metadata signature if set
	SignatureVerifier ports.SignatureVerifier

	// Logger for structured logging (optional)
	Logger *zap.Logger

	// Filter options
	IdPFilter                    string
	RegistrationAuthorityFilter  string
	EntityCategoryFilter         string
	AssuranceCertificationFilter string
}

// LoaderResult contains the result of LoadAndProcessMetadata.
type LoaderResult struct {
	// IdPs is the list of parsed and filtered IdPs
	IdPs []domain.IdPInfo

	// ValidUntil is the metadata validUntil timestamp if present
	ValidUntil *time.Time
}

// LoadAndProcessMetadata performs the shared metadata processing pipeline:
// 1. Verify signature (if verifier configured)
// 2. Parse metadata
// 3. Log expiry warning (if expired)
// 4. Apply filters
// 5. Return filtered IdPs or error with comprehensive filter failure info
//
// Test coverage: See loader_test.go - TestLoadAndProcessMetadata_* tests
func LoadAndProcessMetadata(data []byte, cfg LoaderConfig) (*LoaderResult, error) {
	var err error

	// Step 1: Verify signature if verifier is configured
	if cfg.SignatureVerifier != nil {
		data, err = cfg.SignatureVerifier.Verify(data)
		if err != nil {
			return nil, fmt.Errorf("verify metadata signature: %w", err)
		}
	}

	// Step 2: Parse metadata
	idps, validUntil, err := ParseMetadata(data)
	if err != nil {
		// Step 3: Log expiry warning with structured fields
		if errors.Is(err, domain.ErrMetadataExpired) && cfg.Logger != nil {
			cfg.Logger.Warn("metadata expired",
				zap.String("source", cfg.Source),
				zap.Error(err),
			)
		}
		return nil, err
	}

	// Step 4: Apply filters and collect failures
	originalEntityIDs := domain.ExtractEntityIDs(idps)
	idps, filterFailures := applyFiltersAndCollectFailures(
		idps,
		cfg.IdPFilter,
		cfg.RegistrationAuthorityFilter,
		cfg.EntityCategoryFilter,
		cfg.AssuranceCertificationFilter,
	)

	// Step 5: Return error with comprehensive filter failure info
	if len(filterFailures) > 0 {
		return nil, fmt.Errorf("%s", domain.FormatFilterError(filterFailures, originalEntityIDs))
	}

	return &LoaderResult{
		IdPs:       idps,
		ValidUntil: validUntil,
	}, nil
}
