package caddy

import (
	"fmt"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

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

	// SignMetadata enables XML signature on SP metadata output.
	// Uses the SP private key and certificate configured via key_file and cert_file.
	// Defaults to false.
	SignMetadata bool `json:"sign_metadata,omitempty"`

	// AttributeHeaders maps SAML attributes to HTTP headers for downstream handlers.
	// Header names must start with "X-" to prevent overwriting standard headers.
	// Example: map eduPersonPrincipalName to X-Remote-User.
	AttributeHeaders []AttributeMapping `json:"attribute_headers,omitempty"`

	// StripAttributeHeaders controls whether incoming HTTP headers that match
	// configured attribute header names are removed before new values are set.
	// This prevents clients from spoofing headers such as X-Remote-User.
	// Defaults to true.
	StripAttributeHeaders *bool `json:"strip_attribute_headers,omitempty"`

	// HeaderPrefix is prepended to all attribute header names.
	// Must start with "X-" if set. When set, individual header names
	// in AttributeHeaders don't need the X- prefix.
	// Example: prefix "X-Saml-" + header "User" = "X-Saml-User"
	HeaderPrefix string `json:"header_prefix,omitempty"`

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

	// EntitlementsFile is the path to a local entitlements file (JSON/YAML).
	// When set, enables file-based authorization.
	EntitlementsFile string `json:"entitlements_file,omitempty"`

	// EntitlementsRefreshInterval is how often to reload the entitlements file.
	// Defaults to "5m" if not specified.
	EntitlementsRefreshInterval string `json:"entitlements_refresh_interval,omitempty"`

	// EntitlementHeaders maps entitlement fields to HTTP headers.
	// Similar to AttributeHeaders but for local entitlements.
	EntitlementHeaders []EntitlementHeaderMapping `json:"entitlement_headers,omitempty"`

	// RequireEntitlement specifies an entitlement role required for access.
	// Returns 403 if authenticated user lacks this role.
	RequireEntitlement string `json:"require_entitlement,omitempty"`

	// EntitlementDenyRedirect is the URL to redirect unauthorized users to.
	// If empty, returns a 403 Forbidden response.
	EntitlementDenyRedirect string `json:"entitlement_deny_redirect,omitempty"`
}

// AltLoginConfig represents an alternative login method (non-SAML).
type AltLoginConfig struct {
	URL   string `json:"url"`
	Label string `json:"label"`
}

// AttributeMapping maps a SAML attribute to an HTTP header.
type AttributeMapping struct {
	// SAMLAttribute is the SAML attribute name or OID to match.
	// Examples: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "eduPersonPrincipalName", "mail"
	SAMLAttribute string `json:"saml_attribute"`

	// HeaderName is the HTTP header name to set. Must start with "X-".
	// Examples: "X-Remote-User", "X-Mail", "X-Entitlements"
	HeaderName string `json:"header_name"`

	// Separator is the string used to join multiple attribute values.
	// Defaults to ";" if empty (Shibboleth convention).
	// Common alternatives: "," (HTTP convention), "|"
	Separator string `json:"separator,omitempty"`
}

// EntitlementHeaderMapping maps an entitlement field to an HTTP header.
type EntitlementHeaderMapping struct {
	// Field is the entitlement field to map (e.g., "roles", "department").
	Field string `json:"field"`

	// HeaderName is the HTTP header name to set. Must start with "X-".
	HeaderName string `json:"header_name"`

	// Separator is the string used to join multiple values (for roles).
	// Defaults to ";" if empty.
	Separator string `json:"separator,omitempty"`
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

	// Validate header prefix
	if c.HeaderPrefix != "" {
		if !domain.IsValidHeaderName(c.HeaderPrefix) {
			return fmt.Errorf("header_prefix %q must start with X- and contain only A-Za-z0-9-", c.HeaderPrefix)
		}
	}

	// Validate attribute header mappings
	for i, m := range c.AttributeHeaders {
		if m.SAMLAttribute == "" {
			return fmt.Errorf("attribute_headers[%d]: saml_attribute is required", i)
		}
		if m.HeaderName == "" {
			return fmt.Errorf("attribute_headers[%d]: header_name is required", i)
		}

		// If prefix is set, validate the final combined name
		// Otherwise, validate the header name directly (must start with X-)
		if c.HeaderPrefix != "" {
			finalName := ApplyHeaderPrefix(c.HeaderPrefix, m.HeaderName)
			if !domain.IsValidHeaderName(finalName) {
				return fmt.Errorf("attribute_headers[%d]: header_name %q with prefix %q results in invalid name %q: must start with X- and contain only A-Za-z0-9-", i, m.HeaderName, c.HeaderPrefix, finalName)
			}
		} else {
			if !domain.IsValidHeaderName(m.HeaderName) {
				return fmt.Errorf("attribute_headers[%d]: header_name %q must start with X- and contain only A-Za-z0-9-", i, m.HeaderName)
			}
		}
	}

	// Validate entitlements config
	if c.RequireEntitlement != "" && c.EntitlementsFile == "" {
		return fmt.Errorf("entitlements_file is required when require_entitlement is set")
	}

	// Validate entitlement header mappings
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
	if c.StripAttributeHeaders == nil {
		c.StripAttributeHeaders = boolPtr(true)
	}
}

func boolPtr(v bool) *bool {
	b := v
	return &b
}

// ApplyHeaderPrefix prepends prefix to header name.
// If prefix is empty, returns headerName unchanged.
func ApplyHeaderPrefix(prefix, headerName string) string {
	if prefix == "" {
		return headerName
	}
	return prefix + headerName
}







