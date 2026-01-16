// Package caddysamldisco provides a Caddy v2 plugin for SAML Service Provider
// authentication with Discovery Service support.
//
// This file consolidates all function and constant re-exports from internal packages.
package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/logo"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metrics"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/request"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/session"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/signature"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// =============================================================================
// Domain Constants
// =============================================================================

// Error codes
const (
	ErrCodeConfigMissing    = domain.ErrCodeConfigMissing
	ErrCodeIdPNotFound      = domain.ErrCodeIdPNotFound
	ErrCodeAuthFailed       = domain.ErrCodeAuthFailed
	ErrCodeSessionInvalid   = domain.ErrCodeSessionInvalid
	ErrCodeServiceError     = domain.ErrCodeServiceError
	ErrCodeBadRequest       = domain.ErrCodeBadRequest
	ErrCodeSignatureInvalid = domain.ErrCodeSignatureInvalid
)

// Default actions for entitlements
const (
	DefaultActionDeny  = domain.DefaultActionDeny
	DefaultActionAllow = domain.DefaultActionAllow
)

// SAML error categories
const (
	SAMLErrSignatureVerification = domain.SAMLErrSignatureVerification
	SAMLErrDecryptionFailed      = domain.SAMLErrDecryptionFailed
	SAMLErrTimeConstraint        = domain.SAMLErrTimeConstraint
	SAMLErrIdPStatus             = domain.SAMLErrIdPStatus
	SAMLErrUnknown               = domain.SAMLErrUnknown
)

// Header constants
const (
	MaxHeaderValueLength = domain.MaxHeaderValueLength
)

// =============================================================================
// Domain Errors
// =============================================================================

var (
	// ErrIdPNotFound is returned when an IdP is not found.
	ErrIdPNotFound = domain.ErrIdPNotFound
	// ErrMetadataExpired is returned when metadata has expired.
	ErrMetadataExpired = domain.ErrMetadataExpired
	// ErrEntitlementNotFound is returned when an entitlement is not found.
	ErrEntitlementNotFound = domain.ErrEntitlementNotFound
	// ErrAccessDenied is returned when access is denied by entitlements.
	ErrAccessDenied = domain.ErrAccessDenied
)

// =============================================================================
// Port Errors
// =============================================================================

var (
	// ErrSessionNotFound is returned when a session is not found.
	ErrSessionNotFound = ports.ErrSessionNotFound
)

// =============================================================================
// Adapter Errors
// =============================================================================

var (
	// ErrLogoNotFound is returned when a logo is not found.
	ErrLogoNotFound = logo.ErrLogoNotFound
	// ErrLogoFetchFailed is returned when logo fetching fails.
	ErrLogoFetchFailed = logo.ErrLogoFetchFailed
	// ErrInvalidContentType is returned for invalid logo content types.
	ErrInvalidContentType = logo.ErrInvalidContentType
)

// =============================================================================
// Domain Functions - Errors
// =============================================================================

var (
	// ConfigError creates a configuration error.
	ConfigError = domain.ConfigError
	// IdPNotFoundError creates an IdP not found error.
	IdPNotFoundError = domain.IdPNotFoundError
	// BadRequestError creates a bad request error.
	BadRequestError = domain.BadRequestError
	// AuthError creates an authentication error.
	AuthError = domain.AuthError
	// ServiceError creates a service error.
	ServiceError = domain.ServiceError
)

// =============================================================================
// Domain Functions - Metadata
// =============================================================================

var (
	// IsMetadataExpired checks if metadata has expired.
	IsMetadataExpired = domain.IsMetadataExpired
	// MatchesSearch checks if an IdP matches a search query.
	MatchesSearch = domain.MatchesSearch
	// LocalizeIdPInfo localizes IdP information for a language.
	LocalizeIdPInfo = domain.LocalizeIdPInfo
	// SelectLocalizedValue selects a localized value for a language.
	SelectLocalizedValue = domain.SelectLocalizedValue
	// SelectFromMap selects a value from a localized map.
	SelectFromMap = domain.SelectFromMap
	// LocalizedValuesToMap converts localized values to a map.
	LocalizedValuesToMap = domain.LocalizedValuesToMap
	// SelectBestLogo selects the best logo from available options.
	SelectBestLogo = domain.SelectBestLogo
	// MatchesEntityIDPattern checks if an entity ID matches a pattern.
	MatchesEntityIDPattern = domain.MatchesEntityIDPattern
	// ExtractScope extracts scope from an entity ID.
	ExtractScope = domain.ExtractScope
	// ValidateScope validates a scope value.
	ValidateScope = domain.ValidateScope
	// IsScopedAttribute checks if an attribute is scoped.
	IsScopedAttribute = domain.IsScopedAttribute
	// ExtractEntityIDs extracts entity IDs from a list.
	ExtractEntityIDs = domain.ExtractEntityIDs
	// FormatEntityIDList formats entity IDs for display.
	FormatEntityIDList = domain.FormatEntityIDList
	// FormatFilterError formats a filter error message.
	FormatFilterError = domain.FormatFilterError
)

// =============================================================================
// Domain Functions - Attributes
// =============================================================================

var (
	// ResolveAttributeName resolves an attribute name to its canonical form.
	ResolveAttributeName = domain.ResolveAttributeName
	// IsValidHeaderName checks if a header name is valid.
	IsValidHeaderName = domain.IsValidHeaderName
	// ApplyHeaderPrefix applies a prefix to a header name.
	ApplyHeaderPrefix = domain.ApplyHeaderPrefix
	// MapAttributesToHeaders maps SAML attributes to HTTP headers.
	MapAttributesToHeaders = domain.MapAttributesToHeaders
	// MapAttributesToHeadersWithPrefix maps attributes with a prefix.
	MapAttributesToHeadersWithPrefix = domain.MapAttributesToHeadersWithPrefix
	// SanitizeHeaderValue sanitizes a value for use in HTTP headers.
	SanitizeHeaderValue = domain.SanitizeHeaderValue
)

// =============================================================================
// Domain Functions - Entitlements
// =============================================================================

var (
	// MatchesSubjectPattern checks if a subject matches an entitlement pattern.
	MatchesSubjectPattern = domain.MatchesSubjectPattern
)

// =============================================================================
// Domain Functions - SAML
// =============================================================================

var (
	// ValidateAuthnContextComparison validates an AuthnContext comparison.
	ValidateAuthnContextComparison = domain.ValidateAuthnContextComparison
	// DecodeSAMLRequest decodes a SAML request from base64.
	DecodeSAMLRequest = domain.DecodeSAMLRequest
)

// =============================================================================
// Caddy Adapter Functions
// =============================================================================

var (
	// ParseCaddyfile parses the Caddyfile configuration.
	ParseCaddyfile = caddy.ParseCaddyfile
	// NewCaddyAttributeMapper creates a new attribute mapper for Caddy.
	NewCaddyAttributeMapper = caddy.NewCaddyAttributeMapper
	// NewJSONErrorResponse creates a new JSON error response.
	NewJSONErrorResponse = caddy.NewJSONErrorResponse
	// NewSAMLService creates a new SAML service.
	NewSAMLService = caddy.NewSAMLService
	// NewSAMLServiceWithStore creates a SAML service with a custom store.
	NewSAMLServiceWithStore = caddy.NewSAMLServiceWithStore
	// NewTemplateRenderer creates a new template renderer.
	NewTemplateRenderer = caddy.NewTemplateRenderer
	// NewTemplateRendererWithTemplate creates a renderer with a custom template.
	NewTemplateRendererWithTemplate = caddy.NewTemplateRendererWithTemplate
	// NewTemplateRendererWithDir creates a renderer with a template directory.
	NewTemplateRendererWithDir = caddy.NewTemplateRendererWithDir
	// GetSession retrieves the current session from a request.
	GetSession = caddy.GetSession
	// ValidateDenyRedirect validates a deny redirect URL.
	ValidateDenyRedirect = caddy.ValidateDenyRedirect
	// ValidateRelayState validates a SAML relay state.
	ValidateRelayState = caddy.ValidateRelayState
	// ParseAcceptLanguage parses an Accept-Language header.
	ParseAcceptLanguage = caddy.ParseAcceptLanguage
	// ParseDuration parses a duration string.
	ParseDuration = caddy.ParseDuration
	// MatchesForceAuthnPath checks if a path requires forced authentication.
	MatchesForceAuthnPath = caddy.MatchesForceAuthnPath
	// SetVersionGetters sets the version getter functions.
	SetVersionGetters = caddy.SetVersionGetters
)

// =============================================================================
// Metadata Adapter Functions
// =============================================================================

var (
	// WithIdPFilter adds an IdP filter to the metadata store.
	WithIdPFilter = metadata.WithIdPFilter
	// WithRegistrationAuthorityFilter filters by registration authority.
	WithRegistrationAuthorityFilter = metadata.WithRegistrationAuthorityFilter
	// WithEntityCategoryFilter filters by entity category.
	WithEntityCategoryFilter = metadata.WithEntityCategoryFilter
	// WithAssuranceCertificationFilter filters by assurance certification.
	WithAssuranceCertificationFilter = metadata.WithAssuranceCertificationFilter
	// WithSignatureVerifier adds a signature verifier.
	WithSignatureVerifier = metadata.WithSignatureVerifier
	// WithLogger adds a logger to the metadata store.
	WithLogger = metadata.WithLogger
	// WithMetricsRecorder adds a metrics recorder.
	WithMetricsRecorder = metadata.WithMetricsRecorder
	// WithOnRefresh adds a refresh callback.
	WithOnRefresh = metadata.WithOnRefresh
	// WithClock sets the clock for the metadata store.
	WithClock = metadata.WithClock
	// WithVersion sets the version for the metadata store.
	WithVersion = metadata.WithVersion
	// NewInMemoryMetadataStore creates an in-memory metadata store.
	NewInMemoryMetadataStore = metadata.NewInMemoryMetadataStore
	// NewInMemoryMetadataStoreWithValidUntil creates a store with expiration.
	NewInMemoryMetadataStoreWithValidUntil = metadata.NewInMemoryMetadataStoreWithValidUntil
	// NewFileMetadataStore creates a file-based metadata store.
	NewFileMetadataStore = metadata.NewFileMetadataStore
	// NewURLMetadataStore creates a URL-based metadata store.
	NewURLMetadataStore = metadata.NewURLMetadataStore
	// NewURLMetadataStoreWithRefresh creates a URL store with auto-refresh.
	NewURLMetadataStoreWithRefresh = metadata.NewURLMetadataStoreWithRefresh
	// FilterIdPsByEntityCategory filters IdPs by entity category.
	FilterIdPsByEntityCategory = metadata.FilterIdPsByEntityCategory
	// FilterIdPsByAssuranceCertification filters IdPs by assurance.
	FilterIdPsByAssuranceCertification = metadata.FilterIdPsByAssuranceCertification
	// FilterIdPsByRegistrationAuthority filters IdPs by authority.
	FilterIdPsByRegistrationAuthority = metadata.FilterIdPsByRegistrationAuthority
	// ParseMetadata parses SAML metadata XML.
	ParseMetadata = metadata.ParseMetadata
)

// =============================================================================
// Session Adapter Functions
// =============================================================================

var (
	// NewCookieSessionStore creates a cookie-based session store.
	NewCookieSessionStore = session.NewCookieSessionStore
	// LoadPrivateKey loads a private key from a file.
	LoadPrivateKey = session.LoadPrivateKey
	// LoadCertificate loads a certificate from a file.
	LoadCertificate = session.LoadCertificate
)

// =============================================================================
// Request Adapter Functions
// =============================================================================

var (
	// NewInMemoryRequestStore creates an in-memory request store.
	NewInMemoryRequestStore = request.NewInMemoryRequestStore
	// NewInMemoryRequestStoreWithCleanup creates a store with cleanup.
	NewInMemoryRequestStoreWithCleanup = request.NewInMemoryRequestStoreWithCleanup
	// WithOnCleanup adds a cleanup callback.
	WithOnCleanup = request.WithOnCleanup
)

// =============================================================================
// Logo Adapter Functions
// =============================================================================

var (
	// NewInMemoryLogoStore creates an in-memory logo store.
	NewInMemoryLogoStore = logo.NewInMemoryLogoStore
	// NewCachingLogoStore creates a caching logo store.
	NewCachingLogoStore = logo.NewCachingLogoStore
	// WithLogoMaxSize sets the maximum logo size.
	WithLogoMaxSize = logo.WithLogoMaxSize
)

// =============================================================================
// Signature Adapter Functions
// =============================================================================

var (
	// NewNoopVerifier creates a no-op signature verifier.
	NewNoopVerifier = signature.NewNoopVerifier
	// NewNoopSigner creates a no-op metadata signer.
	NewNoopSigner = signature.NewNoopSigner
	// NewXMLDsigVerifier creates an XML signature verifier.
	NewXMLDsigVerifier = signature.NewXMLDsigVerifier
	// NewXMLDsigVerifierWithCerts creates a verifier with certificates.
	NewXMLDsigVerifierWithCerts = signature.NewXMLDsigVerifierWithCerts
	// NewXMLDsigVerifierWithLogger creates a verifier with a logger.
	NewXMLDsigVerifierWithLogger = signature.NewXMLDsigVerifierWithLogger
	// NewXMLDsigVerifierWithCertsAndLogger creates a verifier with both.
	NewXMLDsigVerifierWithCertsAndLogger = signature.NewXMLDsigVerifierWithCertsAndLogger
	// NewXMLDsigSigner creates an XML metadata signer.
	NewXMLDsigSigner = signature.NewXMLDsigSigner
	// LoadSigningCertificates loads signing certificates from a file.
	LoadSigningCertificates = signature.LoadSigningCertificates
)

// =============================================================================
// Metrics Adapter Functions
// =============================================================================

var (
	// NewNoopMetricsRecorder creates a no-op metrics recorder.
	NewNoopMetricsRecorder = metrics.NewNoopMetricsRecorder
	// NewPrometheusMetricsRecorder creates a Prometheus metrics recorder.
	NewPrometheusMetricsRecorder = metrics.NewPrometheusMetricsRecorder
	// NewPrometheusMetricsRecorderWithRegistry creates with a registry.
	NewPrometheusMetricsRecorderWithRegistry = metrics.NewPrometheusMetricsRecorderWithRegistry
)

// =============================================================================
// Entitlements Adapter Functions
// =============================================================================

var (
	// NewFileEntitlementStore creates a file-based entitlement store.
	NewFileEntitlementStore = entitlements.NewFileEntitlementStore
	// NewInMemoryEntitlementStore creates an in-memory entitlement store.
	NewInMemoryEntitlementStore = entitlements.NewInMemoryEntitlementStore
)
