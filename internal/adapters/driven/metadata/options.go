package metadata

import (
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// MetadataOption is a functional option for configuring metadata stores.
type MetadataOption func(*metadataOptions)

// Clock provides time functionality for testing.
type Clock interface {
	Now() time.Time
}

// RealClock uses the standard time package.
type RealClock struct{}

// Now returns the current time.
func (RealClock) Now() time.Time { return time.Now() }

type metadataOptions struct {
	idpFilter                   string
	registrationAuthorityFilter string
	entityCategoryFilter        string
	assuranceCertificationFilter string
	signatureVerifier           ports.SignatureVerifier
	logger                      *zap.Logger
	metricsRecorder             ports.MetricsRecorder
	onRefresh                   func(error)
	clock                       Clock
}

// WithIdPFilter returns an option that filters IdPs by entity ID pattern.
// Only IdPs whose entity ID matches the pattern will be loaded.
// Supports glob-like patterns: "*substring*", "prefix*", "*suffix".
func WithIdPFilter(pattern string) MetadataOption {
	return func(o *metadataOptions) {
		o.idpFilter = pattern
	}
}

// WithRegistrationAuthorityFilter returns an option that filters IdPs by registration authority.
// Only IdPs registered by matching federations will be loaded.
// Supports comma-separated patterns (e.g., "https://www.aai.dfn.de,https://incommon.org").
// Each pattern supports glob-like patterns: "*substring*", "prefix*", "*suffix".
func WithRegistrationAuthorityFilter(pattern string) MetadataOption {
	return func(o *metadataOptions) {
		o.registrationAuthorityFilter = pattern
	}
}

// WithEntityCategoryFilter returns an option that filters IdPs by entity category.
// Only IdPs that have at least one of the specified entity categories will be loaded.
// Supports comma-separated categories (OR logic - IdP must have at least one).
// Example: "http://refeds.org/category/research-and-scholarship,https://refeds.org/category/code-of-conduct/v2"
func WithEntityCategoryFilter(categories string) MetadataOption {
	return func(o *metadataOptions) {
		o.entityCategoryFilter = categories
	}
}

// WithAssuranceCertificationFilter returns an option that filters IdPs by assurance certification.
// Only IdPs that have at least one of the specified assurance certifications will be loaded.
// Supports comma-separated certifications (OR logic - IdP must have at least one).
// Example: "https://refeds.org/sirtfi"
func WithAssuranceCertificationFilter(certifications string) MetadataOption {
	return func(o *metadataOptions) {
		o.assuranceCertificationFilter = certifications
	}
}

// WithSignatureVerifier returns an option that enables signature verification.
// When set, metadata will be verified against the trusted certificates before parsing.
func WithSignatureVerifier(verifier ports.SignatureVerifier) MetadataOption {
	return func(o *metadataOptions) {
		o.signatureVerifier = verifier
	}
}

// WithLogger returns an option that sets the logger for the metadata store.
// When set, background refresh events (success/failure) will be logged.
func WithLogger(logger *zap.Logger) MetadataOption {
	return func(o *metadataOptions) {
		o.logger = logger
	}
}

// WithMetricsRecorder returns an option that sets the metrics recorder for the metadata store.
// When set, metadata refresh operations will be recorded as metrics.
func WithMetricsRecorder(recorder ports.MetricsRecorder) MetadataOption {
	return func(o *metadataOptions) {
		o.metricsRecorder = recorder
	}
}

// WithOnRefresh returns an option that sets a callback invoked after each background refresh.
// The callback receives the error (nil on success). Used for testing synchronization.
func WithOnRefresh(fn func(error)) MetadataOption {
	return func(o *metadataOptions) {
		o.onRefresh = fn
	}
}

// WithClock returns an option that sets a custom clock for time operations.
// Used for testing cache TTL expiration without time.Sleep.
func WithClock(clock Clock) MetadataOption {
	return func(o *metadataOptions) {
		o.clock = clock
	}
}






