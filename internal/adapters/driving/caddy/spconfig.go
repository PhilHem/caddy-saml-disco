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
	metadataStore   ports.MetadataStore
	sessionStore    ports.SessionStore
	logoStore       ports.LogoStore
	samlService     *SAMLService
	sessionDuration time.Duration
	templateRenderer *TemplateRenderer
}

// Validate checks if the SP config is valid.
func (c *SPConfig) Validate() error {
	if c.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	return c.Config.Validate()
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
