package caddy

import (
	"time"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metrics"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// SetLogoStore sets the logo store. For testing purposes.
func (s *SAMLDisco) SetLogoStore(store ports.LogoStore) {
	s.logoStore = store
}

// SetMetadataStore sets the metadata store for testing.
func (s *SAMLDisco) SetMetadataStore(store ports.MetadataStore) {
	s.metadataStore = store
}

// SetSAMLService sets the SAML service for testing.
func (s *SAMLDisco) SetSAMLService(service *SAMLService) {
	s.samlService = service
}

// SetSessionStore sets the session store for testing.
func (s *SAMLDisco) SetSessionStore(store ports.SessionStore) {
	s.sessionStore = store
}

// SetEntitlementStore sets the entitlement store for testing.
func (s *SAMLDisco) SetEntitlementStore(store ports.EntitlementStore) {
	s.entitlementStore = store
}

// SetTemplateRenderer sets the template renderer for testing.
func (s *SAMLDisco) SetTemplateRenderer(renderer *TemplateRenderer) {
	s.templateRenderer = renderer
}

// SetRememberIdPDuration sets the remember IdP duration for testing.
func (s *SAMLDisco) SetRememberIdPDuration(d time.Duration) {
	s.rememberIdPDuration = d
}

// SetMetricsRecorder sets the metrics recorder for testing.
func (s *SAMLDisco) SetMetricsRecorder(recorder ports.MetricsRecorder) {
	s.metricsRecorder = recorder
}

// SetRegistry sets the SP config registry for testing.
func (s *SAMLDisco) SetRegistry(registry *SPConfigRegistry) {
	s.registry = registry
}

// GetRegistry returns the SP config registry for testing.
func (s *SAMLDisco) GetRegistry() *SPConfigRegistry {
	return s.registry
}

// getMetricsRecorder returns the metrics recorder, or a no-op recorder if not set.
// This allows tests to run without calling Provision().
func (s *SAMLDisco) getMetricsRecorder() ports.MetricsRecorder {
	if s.metricsRecorder != nil {
		return s.metricsRecorder
	}
	return metrics.NewNoopMetricsRecorder()
}

// initMetricsRecorder initializes the metrics recorder based on configuration.
func (s *SAMLDisco) initMetricsRecorder() {
	if s.MetricsEnabled {
		s.metricsRecorder = metrics.NewPrometheusMetricsRecorder()
	} else {
		s.metricsRecorder = metrics.NewNoopMetricsRecorder()
	}
}
