package caddysamldisco

import "fmt"

// Config holds the configuration for the SAML Discovery plugin.
type Config struct {
	// EntityID is the SAML entity ID for this SP (required).
	EntityID string `json:"entity_id,omitempty"`

	// MetadataURL is the URL to fetch IdP metadata from.
	// Either MetadataURL or MetadataFile must be set.
	MetadataURL string `json:"metadata_url,omitempty"`

	// MetadataFile is the path to a local IdP metadata file.
	// Either MetadataURL or MetadataFile must be set.
	MetadataFile string `json:"metadata_file,omitempty"`

	// CertFile is the path to the SP certificate file (PEM format).
	CertFile string `json:"cert_file,omitempty"`

	// KeyFile is the path to the SP private key file (PEM format).
	KeyFile string `json:"key_file,omitempty"`

	// AcsURL is the Assertion Consumer Service URL.
	// If not set, defaults to {scheme}://{host}/saml/acs
	AcsURL string `json:"acs_url,omitempty"`

	// MetadataRefreshInterval is how often to refresh metadata (e.g., "1h").
	// Defaults to "1h" if not specified.
	MetadataRefreshInterval string `json:"metadata_refresh_interval,omitempty"`

	// SessionCookieName is the name of the session cookie.
	// Defaults to "saml_session".
	SessionCookieName string `json:"session_cookie_name,omitempty"`

	// SessionDuration is how long sessions last (e.g., "8h").
	// Defaults to "8h" if not specified.
	SessionDuration string `json:"session_duration,omitempty"`

	// TemplatesDir is the path to custom template files.
	// If not set, embedded templates are used.
	TemplatesDir string `json:"templates_dir,omitempty"`

	// LoginRedirect is the URL to redirect to for login instead of
	// showing the default discovery UI. Enables custom frontend usage.
	LoginRedirect string `json:"login_redirect,omitempty"`

	// IdPFilter is a pattern to filter IdPs from metadata aggregates.
	// Supports glob patterns (e.g., "*.example.edu").
	IdPFilter string `json:"idp_filter,omitempty"`
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.EntityID == "" {
		return fmt.Errorf("entity_id is required")
	}

	if c.MetadataURL == "" && c.MetadataFile == "" {
		return fmt.Errorf("either metadata_url or metadata_file must be specified")
	}

	if c.MetadataURL != "" && c.MetadataFile != "" {
		return fmt.Errorf("only one of metadata_url or metadata_file can be specified")
	}

	return nil
}

// SetDefaults applies default values to unset configuration fields.
func (c *Config) SetDefaults() {
	if c.MetadataRefreshInterval == "" {
		c.MetadataRefreshInterval = "1h"
	}
	if c.SessionCookieName == "" {
		c.SessionCookieName = "saml_session"
	}
	if c.SessionDuration == "" {
		c.SessionDuration = "8h"
	}
}
