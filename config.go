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

	// BackgroundRefresh enables periodic metadata refresh in the background.
	// When enabled, metadata is fetched at MetadataRefreshInterval regardless of cache TTL.
	// Only applies to URL metadata sources. Defaults to false (passive refresh).
	BackgroundRefresh bool `json:"background_refresh,omitempty"`

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

	// RememberIdPCookieName is the name of the cookie that stores the last-used IdP.
	// Defaults to "saml_last_idp".
	RememberIdPCookieName string `json:"remember_idp_cookie_name,omitempty"`

	// RememberIdPDuration is how long to remember the last-used IdP (e.g., "30d").
	// Defaults to "30d" if not specified.
	RememberIdPDuration string `json:"remember_idp_duration,omitempty"`

	// DiscoveryTemplate selects which discovery UI template to use.
	// Options: "" (default), "fels" (FeLS-style with autocomplete).
	DiscoveryTemplate string `json:"discovery_template,omitempty"`

	// ServiceName is displayed in the FeLS discovery UI header.
	// Example: "My Research Portal"
	ServiceName string `json:"service_name,omitempty"`

	// PinnedIdPs is a list of IdP entity IDs to display prominently in the discovery UI.
	PinnedIdPs []string `json:"pinned_idps,omitempty"`

	// AltLogins is a list of alternative login methods to display in the discovery UI.
	AltLogins []AltLoginConfig `json:"alt_logins,omitempty"`

	// CORSAllowedOrigins specifies which origins can access the JSON API.
	// Use ["*"] to allow any origin (not recommended for production).
	// Empty means CORS is disabled.
	CORSAllowedOrigins []string `json:"cors_allowed_origins,omitempty"`

	// CORSAllowCredentials allows cookies/auth headers in CORS requests.
	// Only works with specific origins, not with wildcard "*".
	CORSAllowCredentials bool `json:"cors_allow_credentials,omitempty"`

	// DefaultLanguage is the fallback language for display names when
	// the user's Accept-Language header doesn't match any available language.
	// Defaults to "en" if not specified.
	DefaultLanguage string `json:"default_language,omitempty"`

	// VerifyMetadataSignature enables XML signature verification on metadata.
	// Requires MetadataSigningCert to be set.
	VerifyMetadataSignature bool `json:"verify_metadata_signature,omitempty"`

	// MetadataSigningCert is the path to the PEM file containing the
	// federation signing certificate(s) used to verify metadata signatures.
	MetadataSigningCert string `json:"metadata_signing_cert,omitempty"`

	// MetricsEnabled enables Prometheus metrics exposition.
	// Metrics are exposed via Caddy's admin API /metrics endpoint.
	// Defaults to false.
	MetricsEnabled bool `json:"metrics_enabled,omitempty"`
}

// AltLoginConfig represents an alternative login method (non-SAML).
type AltLoginConfig struct {
	URL   string `json:"url"`
	Label string `json:"label"`
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

	// Validate CORS config: wildcard cannot be combined with other origins
	if len(c.CORSAllowedOrigins) > 1 {
		for _, o := range c.CORSAllowedOrigins {
			if o == "*" {
				return fmt.Errorf("cors_allowed_origins: wildcard '*' cannot be combined with other origins")
			}
		}
	}

	// Validate CORS config: credentials cannot be used with wildcard
	if c.CORSAllowCredentials && len(c.CORSAllowedOrigins) == 1 && c.CORSAllowedOrigins[0] == "*" {
		return fmt.Errorf("cors_allow_credentials cannot be used with wildcard origin")
	}

	// Validate signature verification config
	if c.VerifyMetadataSignature && c.MetadataSigningCert == "" {
		return fmt.Errorf("metadata_signing_cert is required when verify_metadata_signature is enabled")
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
	if c.RememberIdPCookieName == "" {
		c.RememberIdPCookieName = "saml_last_idp"
	}
	if c.RememberIdPDuration == "" {
		c.RememberIdPDuration = "30d"
	}
}
