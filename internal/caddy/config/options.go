package config

import (
	"go.uber.org/zap"

	samlsp "github.com/philiph/caddy-saml-disco/internal/saml"
	"github.com/philiph/caddy-saml-disco/internal/caddy/rendering"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// SAMLDiscoOption is a functional option for configuring SAMLDisco instances.
type SAMLDiscoOption func(*SAMLDiscoOptions)

// SAMLDiscoOptions holds the configuration applied via functional options.
type SAMLDiscoOptions struct {
	Config           *Config
	MetadataStore    ports.MetadataStore
	SessionStore     ports.SessionStore
	SAMLService      *samlsp.SAMLService
	LogoStore        ports.LogoStore
	EntitlementStore ports.EntitlementStore
	MetricsRecorder  ports.MetricsRecorder
	TemplateRenderer *rendering.TemplateRenderer
	Logger           *zap.Logger
	PinnedIdPs       []string
}

// WithConfig sets the base configuration for the SAMLDisco instance.
func WithConfig(cfg Config) SAMLDiscoOption {
	return func(o *SAMLDiscoOptions) {
		o.Config = &cfg
	}
}

// WithPinnedIdPs sets the pinned IdPs for the discovery UI.
// This is a convenience option that sets the PinnedIdPs field in the config.
func WithPinnedIdPs(entityIDs []string) SAMLDiscoOption {
	return func(o *SAMLDiscoOptions) {
		o.PinnedIdPs = entityIDs
	}
}

// WithMetadataStore sets the metadata store for the SAMLDisco instance.
// Use this for testing with custom metadata stores.
func WithMetadataStore(store ports.MetadataStore) SAMLDiscoOption {
	return func(o *SAMLDiscoOptions) {
		o.MetadataStore = store
	}
}

// WithSessionStore sets the session store for the SAMLDisco instance.
// Use this for testing with custom session stores.
func WithSessionStore(store ports.SessionStore) SAMLDiscoOption {
	return func(o *SAMLDiscoOptions) {
		o.SessionStore = store
	}
}

// WithSAMLService sets the SAML service for the SAMLDisco instance.
// Use this for testing with custom SAML services.
func WithSAMLService(service *samlsp.SAMLService) SAMLDiscoOption {
	return func(o *SAMLDiscoOptions) {
		o.SAMLService = service
	}
}

// WithLogoStore sets the logo store for the SAMLDisco instance.
// Use this for testing with custom logo stores.
func WithLogoStore(store ports.LogoStore) SAMLDiscoOption {
	return func(o *SAMLDiscoOptions) {
		o.LogoStore = store
	}
}

// WithEntitlementStore sets the entitlement store for the SAMLDisco instance.
// Use this for testing with custom entitlement stores.
func WithEntitlementStore(store ports.EntitlementStore) SAMLDiscoOption {
	return func(o *SAMLDiscoOptions) {
		o.EntitlementStore = store
	}
}

// WithMetricsRecorder sets the metrics recorder for the SAMLDisco instance.
// Use this for testing with custom metrics recorders.
func WithMetricsRecorder(recorder ports.MetricsRecorder) SAMLDiscoOption {
	return func(o *SAMLDiscoOptions) {
		o.MetricsRecorder = recorder
	}
}

// WithTemplateRenderer sets the template renderer for the SAMLDisco instance.
// Use this for testing with custom template renderers.
func WithTemplateRenderer(renderer *rendering.TemplateRenderer) SAMLDiscoOption {
	return func(o *SAMLDiscoOptions) {
		o.TemplateRenderer = renderer
	}
}

// WithLogger sets the logger for the SAMLDisco instance.
// Use this for testing with custom loggers.
func WithLogger(logger *zap.Logger) SAMLDiscoOption {
	return func(o *SAMLDiscoOptions) {
		o.Logger = logger
	}
}
