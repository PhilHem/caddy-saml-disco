package config

import (
	"fmt"
	"time"

	samlsp "github.com/philiph/caddy-saml-disco/internal/saml"
	"github.com/philiph/caddy-saml-disco/internal/caddy/rendering"
	"github.com/philiph/caddy-saml-disco/internal/ports"
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
	MetadataStore    ports.MetadataStore
	SessionStore     ports.SessionStore
	EntitlementStore ports.EntitlementStore
	LogoStore        ports.LogoStore
	SAMLService      *samlsp.SAMLService
	SessionDuration  time.Duration
	TemplateRenderer *rendering.TemplateRenderer

	// Config snapshots (immutable copies taken during Provision to prevent mutation)
	// These are used in applyAttributeHeadersForSP() to ensure header names match validation-time expectations.
	HeaderPrefixSnapshot       string
	AttributeHeadersSnapshot   []AttributeMapping
	EntitlementHeadersSnapshot []EntitlementHeaderMapping
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
	c.MetadataStore = store
}

// SetSessionStore sets the session store for testing.
func (c *SPConfig) SetSessionStore(store ports.SessionStore) {
	c.SessionStore = store
}

// SetSAMLService sets the SAML service for testing.
func (c *SPConfig) SetSAMLService(service *samlsp.SAMLService) {
	c.SAMLService = service
}

// SetEntitlementStore sets the entitlement store for testing.
func (c *SPConfig) SetEntitlementStore(store ports.EntitlementStore) {
	c.EntitlementStore = store
}

// SetLogoStore sets the logo store for testing.
func (c *SPConfig) SetLogoStore(store ports.LogoStore) {
	c.LogoStore = store
}

// ValidateSPConfigs validates a slice of SP configs and ensures cookie names are unique.
func ValidateSPConfigs(configs []*SPConfig) error {
	cookieNames := make(map[string]string) // cookie name -> hostname
	for _, cfg := range configs {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("sp config for %s: %w", cfg.Hostname, err)
		}
		cookieName := cfg.Config.SessionCookieName
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
