package config

import (
	"fmt"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

// MetadataSource represents a single metadata source with per-source options.
type MetadataSource struct {
	// URL is the URL to fetch IdP metadata from.
	URL string `json:"url,omitempty"`

	// File is the path to a local IdP metadata file.
	File string `json:"file,omitempty"`

	// IdPFilter is a pattern to filter IdPs from this specific metadata source.
	// Supports glob patterns (e.g., "*.example.edu").
	IdPFilter string `json:"idp_filter,omitempty"`

	// RefreshInterval is how often to refresh metadata from this source.
	// Defaults to 30 minutes if not specified.
	RefreshInterval time.Duration `json:"refresh_interval,omitempty"`
}

// SetDefaults applies default values to MetadataSource fields.
func (m *MetadataSource) SetDefaults() {
	if m.RefreshInterval == 0 {
		m.RefreshInterval = 30 * time.Minute
	}
}

// GuestEntityID is a sentinel entity ID used for guest access entries.
// It never appears in real federation metadata.
const GuestEntityID = "urn:caddy-saml-disco:guest"

// Config holds the configuration for the SAML Discovery plugin.
// Currently 46 fields. If this exceeds 50, decompose into sub-configs
// (e.g., MetadataConfig, SessionConfig, EntitlementConfig).
type Config struct {
	// --- SP Identity ---

	// EntityID is the SAML entity ID for this SP (required).
	EntityID string `json:"entity_id,omitempty"`

	// CertFile is the path to the SP certificate file (PEM format).
	CertFile string `json:"cert_file,omitempty"`

	// KeyFile is the path to the SP private key file (PEM format).
	KeyFile string `json:"key_file,omitempty"`

	// AcsURL is the Assertion Consumer Service URL.
	// If not set, defaults to {scheme}://{host}/saml/acs
	AcsURL string `json:"acs_url,omitempty"`

	// SignMetadata enables XML signature on SP metadata output.
	// Uses the SP private key and certificate configured via key_file and cert_file.
	// Defaults to false.
	SignMetadata bool `json:"sign_metadata,omitempty"`

	// --- Metadata Sources ---

	// MetadataURL is the URL to fetch IdP metadata from.
	// Either MetadataURL or MetadataFile must be set.
	MetadataURL string `json:"metadata_url,omitempty"`

	// MetadataFile is the path to a local IdP metadata file.
	// Either MetadataURL or MetadataFile must be set.
	MetadataFile string `json:"metadata_file,omitempty"`

	// MetadataSources is a list of metadata sources with per-source options.
	// Allows multiple metadata URLs/files, each with its own IdPFilter and refresh interval.
	MetadataSources []MetadataSource `json:"metadata_sources,omitempty"`

	// MetadataRefreshInterval is how often to refresh metadata (e.g., "1h").
	// Defaults to "1h" if not specified.
	MetadataRefreshInterval string `json:"metadata_refresh_interval,omitempty"`

	// BackgroundRefresh enables periodic metadata refresh in the background.
	// When enabled, metadata is fetched at MetadataRefreshInterval regardless of cache TTL.
	// Only applies to URL metadata sources. Defaults to false (passive refresh).
	BackgroundRefresh bool `json:"background_refresh,omitempty"`

	// VerifyMetadataSignature enables XML signature verification on metadata.
	// Requires MetadataSigningCert to be set.
	VerifyMetadataSignature bool `json:"verify_metadata_signature,omitempty"`

	// MetadataSigningCert is the path to the PEM file containing the
	// federation signing certificate(s) used to verify metadata signatures.
	MetadataSigningCert string `json:"metadata_signing_cert,omitempty"`

	// --- IdP Filtering ---

	// IdPFilter is a pattern to filter IdPs from metadata aggregates.
	// Supports glob patterns (e.g., "*.example.edu").
	IdPFilter string `json:"idp_filter,omitempty"`

	// RegistrationAuthorityFilter filters IdPs by their registration authority URI.
	// Only IdPs registered by matching federations will be loaded.
	// Supports comma-separated patterns (e.g., "https://www.aai.dfn.de,https://incommon.org").
	// Each pattern supports glob-like patterns: "*substring*", "prefix*", "*suffix".
	RegistrationAuthorityFilter string `json:"registration_authority_filter,omitempty"`

	// EntityCategoryFilter filters IdPs by entity category.
	// Only IdPs that have at least one of the specified entity categories will be loaded.
	// Supports comma-separated categories (OR logic - IdP must have at least one).
	// Example: "http://refeds.org/category/research-and-scholarship,https://refeds.org/category/code-of-conduct/v2"
	EntityCategoryFilter string `json:"entity_category_filter,omitempty"`

	// AssuranceCertificationFilter filters IdPs by assurance certification.
	// Only IdPs that have at least one of the specified assurance certifications will be loaded.
	// Supports comma-separated certifications (OR logic - IdP must have at least one).
	// Example: "https://refeds.org/sirtfi"
	AssuranceCertificationFilter string `json:"assurance_certification_filter,omitempty"`

	// --- Session & Cookies ---

	// SessionCookieName is the name of the session cookie.
	// Defaults to "saml_session".
	SessionCookieName string `json:"session_cookie_name,omitempty"`

	// SessionDuration is how long sessions last (e.g., "8h").
	// Defaults to "8h" if not specified.
	SessionDuration string `json:"session_duration,omitempty"`

	// CookieSecure controls when the Secure flag is set on session cookies.
	// "auto" (default): uses r.TLS != nil — correct for direct TLS, wrong behind a TLS-terminating proxy.
	// "always": always set the Secure flag — use this when the plugin sits behind a TLS-terminating proxy.
	// "never": never set the Secure flag — only appropriate for local development.
	CookieSecure string `json:"cookie_secure,omitempty"`

	// RememberIdPCookieName is the name of the cookie that stores the last-used IdP.
	// Defaults to "saml_last_idp".
	RememberIdPCookieName string `json:"remember_idp_cookie_name,omitempty"`

	// RememberIdPDuration is how long to remember the last-used IdP (e.g., "30d").
	// Defaults to "30d" if not specified.
	RememberIdPDuration string `json:"remember_idp_duration,omitempty"`

	// --- Authentication ---

	// ForceAuthn requires fresh authentication for all protected routes.
	// When true, the IdP must re-authenticate users even if they have a valid session.
	ForceAuthn bool `json:"force_authn,omitempty"`

	// ForceAuthnPaths is a list of glob patterns for routes requiring fresh authentication.
	// Patterns support wildcard suffix (e.g., "/admin/*" matches "/admin/settings").
	// Takes precedence over ForceAuthn for matched paths.
	ForceAuthnPaths []string `json:"force_authn_paths,omitempty"`

	// AuthnContext is a list of authentication context class URIs to request from the IdP.
	// Examples:
	//   - "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	//   - "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
	//   - "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
	// If empty, no RequestedAuthnContext element is included in the AuthnRequest.
	AuthnContext []string `json:"authn_context,omitempty"`

	// AuthnContextComparison specifies how the IdP should match the requested context.
	// Valid values: "exact", "minimum", "maximum", "better", or "" (defaults to "exact").
	// See SAML 2.0 Core specification section 3.3.2.2.1 for details.
	AuthnContextComparison string `json:"authn_context_comparison,omitempty"`

	// RequestTTL is how long a pending SAML AuthnRequest ID is kept before expiry (e.g., "10m").
	// Defaults to "10m" if not specified.
	RequestTTL string `json:"request_ttl,omitempty"`

	// BypassIdPs is a list of IdP entity IDs that skip SAML authentication.
	// When a user selects a bypassed IdP in the discovery page, a guest session
	// is created immediately without redirecting to the IdP.
	// The IdP must still be present in the metadata (via idp_filter) to appear in the discovery page.
	BypassIdPs []string `json:"bypass_idps,omitempty"`

	// --- Attribute Headers ---

	// AttributeHeaders maps SAML attributes to HTTP headers for downstream handlers.
	// Header names must start with "X-" to prevent overwriting standard headers.
	// Example: map eduPersonPrincipalName to X-Remote-User.
	AttributeHeaders []domain.AttributeMapping `json:"attribute_headers,omitempty"`

	// EntitlementHeaders maps entitlement fields to HTTP headers.
	// Similar to AttributeHeaders but for local entitlements.
	EntitlementHeaders []httputil.EntitlementHeaderMapping `json:"entitlement_headers,omitempty"`

	// HeaderPrefix is prepended to all attribute header names.
	// Must start with "X-" if set. When set, individual header names
	// in AttributeHeaders don't need the X- prefix.
	// Example: prefix "X-Saml-" + header "User" = "X-Saml-User"
	HeaderPrefix string `json:"header_prefix,omitempty"`

	// StripAttributeHeaders controls whether incoming HTTP headers that match
	// configured attribute header names are removed before new values are set.
	// This prevents clients from spoofing headers such as X-Remote-User.
	// Defaults to true.
	StripAttributeHeaders *bool `json:"strip_attribute_headers,omitempty"`

	// --- Entitlements ---

	// EntitlementsFile is the path to a local entitlements file (JSON/YAML).
	// When set, enables file-based authorization.
	EntitlementsFile string `json:"entitlements_file,omitempty"`

	// EntitlementsRefreshInterval is how often to reload the entitlements file.
	// Defaults to "5m" if not specified.
	EntitlementsRefreshInterval string `json:"entitlements_refresh_interval,omitempty"`

	// RequireEntitlement specifies an entitlement role required for access.
	// Returns 403 if authenticated user lacks this role.
	RequireEntitlement string `json:"require_entitlement,omitempty"`

	// EntitlementDenyRedirect is the URL to redirect unauthorized users to.
	// If empty, returns a 403 Forbidden response.
	EntitlementDenyRedirect string `json:"entitlement_deny_redirect,omitempty"`

	// --- Discovery UI ---

	// DiscoveryTemplate selects which discovery UI template to use.
	// Options: "" (default), "fels" (FeLS-style with autocomplete).
	DiscoveryTemplate string `json:"discovery_template,omitempty"`

	// TemplatesDir is the path to custom template files.
	// If not set, embedded templates are used.
	TemplatesDir string `json:"templates_dir,omitempty"`

	// DefaultLanguage is the fallback language for display names when
	// the user's Accept-Language header doesn't match any available language.
	// Defaults to "en" if not specified.
	DefaultLanguage string `json:"default_language,omitempty"`

	// ServiceName is displayed in the FeLS discovery UI header.
	// Example: "My Research Portal"
	ServiceName string `json:"service_name,omitempty"`

	// PinnedIdPs is a list of IdP entity IDs to display prominently in the discovery UI.
	PinnedIdPs []string `json:"pinned_idps,omitempty"`

	// GuestAccessLabel is the display name for a virtual guest access entry
	// on the discovery page. When set, a pinned entry with this label appears
	// that creates a guest session without any SAML authentication.
	// Unlike bypass_idp, no real IdP metadata is required.
	GuestAccessLabel string `json:"guest_access_label,omitempty"`

	// GuestPasscode gates the no-authentication access paths (guest_access and
	// bypass_idp). When non-empty, /saml/api/select must carry a matching
	// passcode before a guest or bypass session is created, and the single-IdP
	// auto-bypass shortcut falls back to the discovery page instead of bypassing.
	// When empty, those paths are ungated (backward compatible). Real SAML logins
	// are never affected. The value is treated as a literal secret; the
	// deployment supplies it via Caddy parse-time env substitution.
	//
	// A present-but-empty guest_passcode directive (e.g. an unset env
	// substitution) is rejected at config-parse time so the backdoor is never
	// silently reopened.
	GuestPasscode string `json:"guest_passcode,omitempty"`

	// GuestPasscodes holds per-target passcodes that override GuestPasscode for
	// a single no-authentication target. The guest_access entry is keyed by the
	// guest sentinel (GuestEntityID); a bypass IdP is keyed by its own entity ID.
	// A target present here gates on its own value; a target absent here falls
	// back to the shared GuestPasscode. This lets guest_access and each
	// bypass_idp carry distinct passcodes (configured via a passcode subdirective
	// in their Caddyfile blocks). As with GuestPasscode, a present-but-empty
	// per-target passcode is rejected at config-parse time.
	GuestPasscodes map[string]string `json:"guest_passcodes,omitempty"`

	// AltLogins is a list of alternative login methods to display in the discovery UI.
	AltLogins []AltLoginConfig `json:"alt_logins,omitempty"`

	// LoginRedirect is the URL to redirect to for login instead of
	// showing the default discovery UI. Enables custom frontend usage.
	LoginRedirect string `json:"login_redirect,omitempty"`

	// --- CORS ---

	// CORSAllowedOrigins specifies which origins can access the JSON API.
	// Use ["*"] to allow any origin (not recommended for production).
	// Empty means CORS is disabled.
	CORSAllowedOrigins []string `json:"cors_allowed_origins,omitempty"`

	// CORSAllowCredentials allows cookies/auth headers in CORS requests.
	// Only works with specific origins, not with wildcard "*".
	CORSAllowCredentials bool `json:"cors_allow_credentials,omitempty"`

	// --- Observability ---

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
	if err := domain.ValidateEntityID(c.EntityID); err != nil {
		return err
	}
	if err := c.validateMetadataSources(); err != nil {
		return err
	}
	if err := c.validateCookieSecure(); err != nil {
		return err
	}
	if err := c.validateCORS(); err != nil {
		return err
	}
	if err := c.validateMetadataSignature(); err != nil {
		return err
	}
	if err := c.validateHeaderPrefix(); err != nil {
		return err
	}
	if err := c.validateAttributeHeaders(); err != nil {
		return err
	}
	if err := c.validateEntitlements(); err != nil {
		return err
	}
	if err := c.validateEntitlementHeaders(); err != nil {
		return err
	}
	return nil
}

// validateMetadataSources ensures exactly one consistent metadata source is set.
func (c *Config) validateMetadataSources() error {
	hasOldMetadata := c.MetadataURL != "" || c.MetadataFile != ""
	hasNewMetadata := len(c.MetadataSources) > 0

	if !hasOldMetadata && !hasNewMetadata {
		return fmt.Errorf("at least one metadata source must be specified (via metadata_url, metadata_file, or metadata_sources)")
	}
	// Backward compatibility: old fields can be used independently
	if c.MetadataURL != "" && c.MetadataFile != "" {
		return fmt.Errorf("only one of metadata_url or metadata_file can be specified")
	}
	return nil
}

// validateCookieSecure ensures the cookie_secure directive uses a known mode.
func (c *Config) validateCookieSecure() error {
	switch c.CookieSecure {
	case "", "auto", "always", "never":
		return nil
	default:
		return fmt.Errorf("cookie_secure must be \"auto\", \"always\", or \"never\", got %q", c.CookieSecure)
	}
}

// validateCORS ensures the wildcard origin is not mixed with concrete origins
// or with credentialed requests.
func (c *Config) validateCORS() error {
	if len(c.CORSAllowedOrigins) > 1 {
		for _, o := range c.CORSAllowedOrigins {
			if o == "*" {
				return fmt.Errorf("cors_allowed_origins: wildcard '*' cannot be combined with other origins")
			}
		}
	}
	if c.CORSAllowCredentials && len(c.CORSAllowedOrigins) == 1 && c.CORSAllowedOrigins[0] == "*" {
		return fmt.Errorf("cors_allow_credentials cannot be used with wildcard origin")
	}
	return nil
}

// validateMetadataSignature ensures a signing cert is present when verification is on.
func (c *Config) validateMetadataSignature() error {
	if c.VerifyMetadataSignature && c.MetadataSigningCert == "" {
		return fmt.Errorf("metadata_signing_cert is required when verify_metadata_signature is enabled")
	}
	return nil
}

// validateHeaderPrefix ensures a configured header prefix is a valid header name.
func (c *Config) validateHeaderPrefix() error {
	if c.HeaderPrefix == "" {
		return nil
	}
	if !domain.IsValidHeaderName(c.HeaderPrefix) {
		return fmt.Errorf("header_prefix %q must start with X- and contain only A-Za-z0-9-", c.HeaderPrefix)
	}
	return nil
}

// validateAttributeHeaders ensures each attribute mapping has the required
// fields and resolves to a valid (optionally prefixed) header name.
func (c *Config) validateAttributeHeaders() error {
	for i, m := range c.AttributeHeaders {
		if m.SAMLAttribute == "" {
			return fmt.Errorf("attribute_headers[%d]: saml_attribute is required", i)
		}
		if m.HeaderName == "" {
			return fmt.Errorf("attribute_headers[%d]: header_name is required", i)
		}
		if err := c.validateAttributeHeaderName(i, m.HeaderName); err != nil {
			return err
		}
	}
	return nil
}

// validateAttributeHeaderName validates a single attribute header name, applying
// the configured prefix when one is set.
func (c *Config) validateAttributeHeaderName(i int, headerName string) error {
	if c.HeaderPrefix == "" {
		if !domain.IsValidHeaderName(headerName) {
			return fmt.Errorf("attribute_headers[%d]: header_name %q must start with X- and contain only A-Za-z0-9-", i, headerName)
		}
		return nil
	}
	finalName := domain.ApplyHeaderPrefix(c.HeaderPrefix, headerName)
	if !domain.IsValidHeaderName(finalName) {
		return fmt.Errorf("attribute_headers[%d]: header_name %q with prefix %q results in invalid name %q: must start with X- and contain only A-Za-z0-9-", i, headerName, c.HeaderPrefix, finalName)
	}
	return nil
}

// validateEntitlements ensures the entitlements file is present whenever a
// dependent setting is configured, and that the refresh interval parses.
func (c *Config) validateEntitlements() error {
	if c.RequireEntitlement != "" && c.EntitlementsFile == "" {
		return fmt.Errorf("entitlements_file is required when require_entitlement is set")
	}
	if c.EntitlementsRefreshInterval == "" {
		return nil
	}
	if c.EntitlementsFile == "" {
		return fmt.Errorf("entitlements_file is required when entitlements_refresh_interval is set")
	}
	if _, err := time.ParseDuration(c.EntitlementsRefreshInterval); err != nil {
		return fmt.Errorf("entitlements_refresh_interval %q is not a valid duration: %w", c.EntitlementsRefreshInterval, err)
	}
	return nil
}

// validateEntitlementHeaders ensures each entitlement mapping has the required
// fields and a valid header name.
func (c *Config) validateEntitlementHeaders() error {
	for i, m := range c.EntitlementHeaders {
		if m.Field == "" {
			return fmt.Errorf("entitlement_headers[%d]: field is required", i)
		}
		if m.HeaderName == "" {
			return fmt.Errorf("entitlement_headers[%d]: header_name is required", i)
		}
		if !domain.IsValidHeaderName(m.HeaderName) {
			return fmt.Errorf("entitlement_headers[%d]: header_name %q must start with X- and contain only A-Za-z0-9-", i, m.HeaderName)
		}
	}
	return nil
}

// SetDefaults applies default values to unset configuration fields.
func (c *Config) SetDefaults() {
	if c.CookieSecure == "" {
		c.CookieSecure = "auto"
	}
	if c.MetadataRefreshInterval == "" {
		c.MetadataRefreshInterval = "1h"
	}
	if c.SessionCookieName == "" {
		c.SessionCookieName = "saml_session"
	}
	if c.SessionDuration == "" {
		c.SessionDuration = "8h"
	}
	if c.RequestTTL == "" {
		c.RequestTTL = "10m"
	}
	if c.RememberIdPCookieName == "" {
		c.RememberIdPCookieName = "saml_last_idp"
	}
	if c.RememberIdPDuration == "" {
		c.RememberIdPDuration = "30d"
	}
	if c.StripAttributeHeaders == nil {
		c.StripAttributeHeaders = boolPtr(true)
	}
}

func boolPtr(v bool) *bool {
	b := v
	return &b
}

// SPConfig holds the declarative fields for a single SP within a multi-SP instance.
// It contains only configuration that can be set in a Caddyfile or JSON config —
// no runtime state (stores, services, goroutine handles).
type SPConfig struct {
	// Hostname is the hostname this SP config handles (e.g., "app1.example.com").
	// Requests with this hostname will route to this SP config.
	Hostname string

	// Config contains the SAML SP configuration for this hostname.
	Config
}
