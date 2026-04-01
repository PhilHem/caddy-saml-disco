//go:build unit || integration

package caddy

import (
	"time"

	"github.com/philiph/caddy-saml-disco/internal/discovery"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	samlsvc "github.com/philiph/caddy-saml-disco/internal/saml"
)

// SAMLDisco setters for injecting dependencies in tests.

// SetLogoStore sets the logo store.
func (s *SAMLDisco) SetLogoStore(store ports.LogoStore) {
	s.defaultSPConfig().logoStore = store
}

// SetMetadataStore sets the metadata store.
func (s *SAMLDisco) SetMetadataStore(store ports.MetadataStore) {
	s.defaultSPConfig().metadataStore = store
}

// SetSAMLService sets the SAML service.
func (s *SAMLDisco) SetSAMLService(service *samlsvc.SAMLService) {
	s.defaultSPConfig().samlService = service
}

// SetSessionStore sets the session store.
func (s *SAMLDisco) SetSessionStore(store ports.SessionStore) {
	s.defaultSPConfig().sessionStore = store
}

// SetEntitlementStore sets the entitlement store.
func (s *SAMLDisco) SetEntitlementStore(store ports.EntitlementStore) {
	s.defaultSPConfig().entitlementStore = store
}

// SetTemplateRenderer sets the template renderer.
func (s *SAMLDisco) SetTemplateRenderer(renderer *discovery.TemplateRenderer) {
	s.defaultSPConfig().templateRenderer = renderer
}

// SetRememberIdPDuration sets the remember IdP duration.
func (s *SAMLDisco) SetRememberIdPDuration(d time.Duration) {
	sp := s.defaultSPConfig()
	sp.Config.RememberIdPDuration = d.String()
}

// SetMetricsRecorder sets the metrics recorder.
func (s *SAMLDisco) SetMetricsRecorder(recorder ports.MetricsRecorder) {
	s.metricsRecorder = recorder
}

// SetRegistry sets the SP config registry.
func (s *SAMLDisco) SetRegistry(registry *SPConfigRegistry) {
	s.registry = registry
}

// SPConfig setters for injecting dependencies in tests.

// SetMetadataStore sets the metadata store.
func (c *SPConfig) SetMetadataStore(store ports.MetadataStore) {
	c.metadataStore = store
}

// SetSessionStore sets the session store.
func (c *SPConfig) SetSessionStore(store ports.SessionStore) {
	c.sessionStore = store
}

// SetSAMLService sets the SAML service.
func (c *SPConfig) SetSAMLService(service *samlsvc.SAMLService) {
	c.samlService = service
}

// SetEntitlementStore sets the entitlement store.
func (c *SPConfig) SetEntitlementStore(store ports.EntitlementStore) {
	c.entitlementStore = store
}

// SetLogoStore sets the logo store.
func (c *SPConfig) SetLogoStore(store ports.LogoStore) {
	c.logoStore = store
}
