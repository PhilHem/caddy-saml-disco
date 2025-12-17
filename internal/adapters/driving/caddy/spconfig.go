package caddy

import (
	"fmt"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// SPConfig represents a single SP configuration within a multi-SP instance.
// Each SP config has its own hostname, configuration, and runtime state.
type SPConfig struct {
	// Hostname is the hostname this SP config handles (e.g., "app1.example.com").
	// Requests with this hostname will route to this SP config.
	Hostname string

	// Config contains the SAML SP configuration for this hostname.
	Config

	// Per-SP runtime state (initialized in Provision)
	// These fields are populated during provisioning and are not serialized.
	metadataStore    ports.MetadataStore
	sessionStore     ports.SessionStore
	entitlementStore ports.EntitlementStore
	logoStore        ports.LogoStore
	samlService      *SAMLService
	sessionDuration  time.Duration
	templateRenderer *TemplateRenderer

	// Config snapshots (immutable copies taken during Provision to prevent mutation)
	// These are used in applyAttributeHeadersForSP() to ensure header names match validation-time expectations.
	headerPrefixSnapshot     string
	attributeHeadersSnapshot []AttributeMapping
	entitlementHeadersSnapshot []EntitlementHeaderMapping
}

// Validate checks if the SP config is valid.
func (c *SPConfig) Validate() error {
	if c.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	return c.Config.Validate()
}

// SetMetadataStore sets the metadata store for testing.
func (c *SPConfig) SetMetadataStore(store ports.MetadataStore) {
	c.metadataStore = store
}

// SetSessionStore sets the session store for testing.
func (c *SPConfig) SetSessionStore(store ports.SessionStore) {
	c.sessionStore = store
}

// SetSAMLService sets the SAML service for testing.
func (c *SPConfig) SetSAMLService(service *SAMLService) {
	c.samlService = service
}

// SetEntitlementStore sets the entitlement store for testing.
func (c *SPConfig) SetEntitlementStore(store ports.EntitlementStore) {
	c.entitlementStore = store
}

// SetLogoStore sets the logo store for testing.
func (c *SPConfig) SetLogoStore(store ports.LogoStore) {
	c.logoStore = store
}

// validateSPConfigs validates a slice of SP configs and ensures cookie names are unique.
func validateSPConfigs(configs []*SPConfig) error {
	cookieNames := make(map[string]string) // cookie name -> hostname
	for _, cfg := range configs {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("sp config for %s: %w", cfg.Hostname, err)
		}
		cookieName := cfg.SessionCookieName
		if cookieName == "" {
			// Use default if not set
			cookieName = "saml_session"
		}
		if existingHost := cookieNames[cookieName]; existingHost != "" {
			return fmt.Errorf("duplicate session_cookie_name %q used by %s and %s",
				cookieName, existingHost, cfg.Hostname)
		}
		cookieNames[cookieName] = cfg.Hostname
	}
	return nil
}



