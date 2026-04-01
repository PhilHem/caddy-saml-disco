//go:build unit || integration

package caddy

import (
	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/discovery"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	samlsvc "github.com/philiph/caddy-saml-disco/internal/saml"
)

// SAMLDiscoOption is a functional option for configuring SAMLDisco instances.
type SAMLDiscoOption func(*samlDiscoOptions)

// samlDiscoOptions holds the configuration applied via functional options.
type samlDiscoOptions struct {
	config           *Config
	metadataStore    ports.MetadataStore
	sessionStore     ports.SessionStore
	samlService      *samlsvc.SAMLService
	logoStore        ports.LogoStore
	entitlementStore ports.EntitlementStore
	metricsRecorder  ports.MetricsRecorder
	templateRenderer *discovery.TemplateRenderer
	logger           *zap.Logger
	pinnedIdPs       []string
}

// WithConfig sets the base configuration for the SAMLDisco instance.
func WithConfig(cfg Config) SAMLDiscoOption {
	return func(o *samlDiscoOptions) {
		o.config = &cfg
	}
}

// WithPinnedIdPs sets the pinned IdPs for the discovery UI.
// This is a convenience option that sets the PinnedIdPs field in the config.
func WithPinnedIdPs(entityIDs []string) SAMLDiscoOption {
	return func(o *samlDiscoOptions) {
		o.pinnedIdPs = entityIDs
	}
}

// WithMetadataStore sets the metadata store for the SAMLDisco instance.
// Use this for testing with custom metadata stores.
func WithMetadataStore(store ports.MetadataStore) SAMLDiscoOption {
	return func(o *samlDiscoOptions) {
		o.metadataStore = store
	}
}

// WithSessionStore sets the session store for the SAMLDisco instance.
// Use this for testing with custom session stores.
func WithSessionStore(store ports.SessionStore) SAMLDiscoOption {
	return func(o *samlDiscoOptions) {
		o.sessionStore = store
	}
}

// WithSAMLService sets the SAML service for the SAMLDisco instance.
// Use this for testing with custom SAML services.
func WithSAMLService(service *samlsvc.SAMLService) SAMLDiscoOption {
	return func(o *samlDiscoOptions) {
		o.samlService = service
	}
}

// WithLogoStore sets the logo store for the SAMLDisco instance.
// Use this for testing with custom logo stores.
func WithLogoStore(store ports.LogoStore) SAMLDiscoOption {
	return func(o *samlDiscoOptions) {
		o.logoStore = store
	}
}

// WithEntitlementStore sets the entitlement store for the SAMLDisco instance.
// Use this for testing with custom entitlement stores.
func WithEntitlementStore(store ports.EntitlementStore) SAMLDiscoOption {
	return func(o *samlDiscoOptions) {
		o.entitlementStore = store
	}
}

// WithMetricsRecorder sets the metrics recorder for the SAMLDisco instance.
// Use this for testing with custom metrics recorders.
func WithMetricsRecorder(recorder ports.MetricsRecorder) SAMLDiscoOption {
	return func(o *samlDiscoOptions) {
		o.metricsRecorder = recorder
	}
}

// WithTemplateRenderer sets the template renderer for the SAMLDisco instance.
// Use this for testing with custom template renderers.
func WithTemplateRenderer(renderer *discovery.TemplateRenderer) SAMLDiscoOption {
	return func(o *samlDiscoOptions) {
		o.templateRenderer = renderer
	}
}

// WithLogger sets the logger for the SAMLDisco instance.
// Use this for testing with custom loggers.
func WithLogger(logger *zap.Logger) SAMLDiscoOption {
	return func(o *samlDiscoOptions) {
		o.logger = logger
	}
}
