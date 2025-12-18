package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
)

// Re-export domain types
type IdPInfo = domain.IdPInfo
type UIInfo = domain.UIInfo
type LocalizedValue = domain.LocalizedValue
type Logo = domain.Logo
type RegistrationInfo = domain.RegistrationInfo
type MetadataHealth = domain.MetadataHealth

// Re-export domain errors
var (
	ErrIdPNotFound    = domain.ErrIdPNotFound
	ErrMetadataExpired = domain.ErrMetadataExpired
)

// Re-export domain functions
var (
	IsMetadataExpired     = domain.IsMetadataExpired
	MatchesSearch         = domain.MatchesSearch
	LocalizeIdPInfo      = domain.LocalizeIdPInfo
	SelectLocalizedValue  = domain.SelectLocalizedValue
	SelectFromMap         = domain.SelectFromMap
	LocalizedValuesToMap  = domain.LocalizedValuesToMap
	SelectBestLogo        = domain.SelectBestLogo
	MatchesEntityIDPattern = domain.MatchesEntityIDPattern
)

// Re-export MetadataStore interface from ports
type MetadataStore = ports.MetadataStore

// Re-export metadata adapters and options
type MetadataOption = metadata.MetadataOption
type Clock = metadata.Clock
type RealClock = metadata.RealClock
type InMemoryMetadataStore = metadata.InMemoryMetadataStore
type FileMetadataStore = metadata.FileMetadataStore
type URLMetadataStore = metadata.URLMetadataStore

var (
	WithIdPFilter                   = metadata.WithIdPFilter
	WithRegistrationAuthorityFilter = metadata.WithRegistrationAuthorityFilter
	WithEntityCategoryFilter        = metadata.WithEntityCategoryFilter
	WithAssuranceCertificationFilter = metadata.WithAssuranceCertificationFilter
	WithSignatureVerifier           = metadata.WithSignatureVerifier
	WithLogger                      = metadata.WithLogger
	WithMetricsRecorder             = metadata.WithMetricsRecorder
	WithOnRefresh                   = metadata.WithOnRefresh
	WithClock                       = metadata.WithClock
	NewInMemoryMetadataStore        = metadata.NewInMemoryMetadataStore
	NewInMemoryMetadataStoreWithValidUntil = metadata.NewInMemoryMetadataStoreWithValidUntil
	NewFileMetadataStore            = metadata.NewFileMetadataStore
	NewURLMetadataStore             = metadata.NewURLMetadataStore
	NewURLMetadataStoreWithRefresh = metadata.NewURLMetadataStoreWithRefresh
	FilterIdPsByEntityCategory     = metadata.FilterIdPsByEntityCategory
	FilterIdPsByAssuranceCertification = metadata.FilterIdPsByAssuranceCertification
	FilterIdPsByRegistrationAuthority = metadata.FilterIdPsByRegistrationAuthority
)
