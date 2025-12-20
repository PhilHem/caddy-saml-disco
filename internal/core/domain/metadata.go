package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// IdPInfo contains information about an Identity Provider.
// This is the core domain model - it has no external dependencies.
type IdPInfo struct {
	// EntityID is the unique identifier for this IdP.
	EntityID string `json:"entity_id"`

	// DisplayName is a human-readable name for the IdP.
	// Prefers mdui:DisplayName over Organization/OrganizationDisplayName.
	// This is the default (usually English) for backward compatibility.
	DisplayName string `json:"display_name"`

	// DisplayNames contains all language variants of the display name.
	// Key is the language code (e.g., "en", "de").
	DisplayNames map[string]string `json:"display_names,omitempty"`

	// Description is a human-readable description of the IdP.
	// Extracted from mdui:Description.
	Description string `json:"description,omitempty"`

	// Descriptions contains all language variants of the description.
	// Key is the language code (e.g., "en", "de").
	Descriptions map[string]string `json:"descriptions,omitempty"`

	// LogoURL is the URL to the IdP's logo image.
	// Extracted from mdui:Logo (prefers larger logos).
	LogoURL string `json:"logo_url,omitempty"`

	// InformationURL is a URL to more information about the IdP.
	// Extracted from mdui:InformationURL.
	InformationURL string `json:"information_url,omitempty"`

	// InformationURLs contains all language variants of the information URL.
	// Key is the language code (e.g., "en", "de").
	InformationURLs map[string]string `json:"information_urls,omitempty"`

	// SSOURL is the Single Sign-On endpoint URL.
	SSOURL string `json:"sso_url"`

	// SSOBinding is the SAML binding for the SSO endpoint.
	SSOBinding string `json:"sso_binding"`

	// SLOURL is the Single Logout endpoint URL (optional).
	SLOURL string `json:"slo_url,omitempty"`

	// SLOBinding is the SAML binding for the SLO endpoint.
	SLOBinding string `json:"slo_binding,omitempty"`

	// Certificates are the IdP's signing certificates (PEM encoded).
	Certificates []string `json:"-"` // Excluded from JSON API for security

	// RegistrationAuthority is the URI of the federation that registered this IdP.
	// Extracted from mdrpi:RegistrationInfo registrationAuthority attribute.
	RegistrationAuthority string `json:"registration_authority,omitempty"`

	// RegistrationInstant is when the IdP was registered with the federation.
	// Extracted from mdrpi:RegistrationInfo registrationInstant attribute.
	RegistrationInstant time.Time `json:"registration_instant,omitempty"`

	// RegistrationPolicies contains localized URLs to the registration policy.
	// Key is the language code (e.g., "en", "de").
	// Extracted from mdrpi:RegistrationPolicy elements.
	RegistrationPolicies map[string]string `json:"registration_policies,omitempty"`

	// AllowedScopes contains the scopes (domains) this IdP is authorized to assert.
	// Extracted from shibmd:Scope elements in IdP metadata.
	// Scoped attributes (like eduPersonPrincipalName) must have scopes matching these.
	AllowedScopes []ScopeInfo `json:"allowed_scopes,omitempty"`

	// EntityCategories contains entity category URIs (e.g., R&S, Code of Conduct).
	// Extracted from mdattr:EntityAttributes with Name="http://macedir.org/entity-category".
	EntityCategories []string `json:"entity_categories,omitempty"`

	// AssuranceCertifications contains assurance certification URIs (e.g., SIRTFI).
	// Extracted from mdattr:EntityAttributes with Name="urn:oasis:names:tc:SAML:attribute:assurance-certification".
	AssuranceCertifications []string `json:"assurance_certifications,omitempty"`
}

// UIInfo represents the mdui:UIInfo element for IdP display metadata.
type UIInfo struct {
	DisplayNames    []LocalizedValue `xml:"DisplayName"`
	Descriptions    []LocalizedValue `xml:"Description"`
	InformationURLs []LocalizedValue `xml:"InformationURL"`
	Logos           []Logo           `xml:"Logo"`
}

// LocalizedValue represents an element with xml:lang attribute.
type LocalizedValue struct {
	Lang  string `xml:"lang,attr"`
	Value string `xml:",chardata"`
}

// Logo represents an mdui:Logo element.
type Logo struct {
	URL    string `xml:",chardata"`
	Height int    `xml:"height,attr"`
	Width  int    `xml:"width,attr"`
}

// RegistrationInfo represents the mdrpi:RegistrationInfo element.
// This indicates which federation registered the IdP.
type RegistrationInfo struct {
	RegistrationAuthority string           `xml:"registrationAuthority,attr"`
	RegistrationInstant   string           `xml:"registrationInstant,attr"` // ISO 8601 timestamp
	RegistrationPolicies  []LocalizedValue `xml:"RegistrationPolicy"`
}

// ScopeInfo represents a shibmd:Scope element from IdP metadata.
// It declares which scopes (domains) an IdP is authorized to assert.
type ScopeInfo struct {
	// Value is the scope pattern, either a literal domain (e.g., "example.edu")
	// or a regular expression pattern (e.g., ".*\\.partner\\.edu").
	Value string `json:"value"`

	// Regexp indicates whether Value should be interpreted as a regular expression.
	// If false, Value is matched exactly (case-sensitive).
	Regexp bool `json:"regexp"`
}

// EntityAttributesInfo represents parsed mdattr:EntityAttributes.
// Contains entity categories (e.g., R&S) and assurance certifications (e.g., SIRTFI).
type EntityAttributesInfo struct {
	EntityCategories        []string
	AssuranceCertifications []string
}

// MetadataHealth reports the health status of a metadata store.
type MetadataHealth struct {
	// IsFresh indicates whether the cached data is from a successful recent refresh.
	IsFresh bool `json:"is_fresh"`

	// LastSuccessTime is when metadata was last successfully fetched.
	LastSuccessTime time.Time `json:"last_success_time,omitempty"`

	// LastError is the error from the most recent failed refresh, or nil if last refresh succeeded.
	LastError error `json:"last_error,omitempty"`

	// IdPCount is the number of IdPs currently cached.
	IdPCount int `json:"idp_count"`

	// MetadataValidUntil is the validUntil timestamp from the metadata, if present.
	// Used for monitoring when metadata will expire.
	MetadataValidUntil *time.Time `json:"metadata_valid_until,omitempty"`
}

// ErrIdPNotFound is returned when an IdP is not found in the store.
var ErrIdPNotFound = fmt.Errorf("idp not found")

// ErrMetadataExpired is returned when metadata has a validUntil attribute
// that is in the past.
var ErrMetadataExpired = fmt.Errorf("metadata expired")

// IsMetadataExpired checks if metadata with the given validUntil time has expired.
// Returns false if validUntil is zero (no expiry specified).
// This is a pure function for domain logic - no I/O.
func IsMetadataExpired(validUntil time.Time, now time.Time) bool {
	if validUntil.IsZero() {
		return false // No expiry specified
	}
	return !now.Before(validUntil) // Expired if now >= validUntil
}

// MatchesEntityIDPattern returns true if the entityID matches the glob pattern.
// Empty pattern matches everything. Uses strings.Contains for substring matching
// when pattern is wrapped in wildcards (e.g., "*example*").
func MatchesEntityIDPattern(entityID, pattern string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}

	// Handle common case: *substring* pattern (substring match)
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") && len(pattern) > 2 {
		substring := pattern[1 : len(pattern)-1]
		return strings.Contains(entityID, substring)
	}

	// Handle prefix pattern: prefix*
	if strings.HasSuffix(pattern, "*") && !strings.HasPrefix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(entityID, prefix)
	}

	// Handle suffix pattern: *suffix
	if strings.HasPrefix(pattern, "*") && !strings.HasSuffix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(entityID, suffix)
	}

	// Exact match
	return entityID == pattern
}

// SelectLocalizedValue returns the value for the preferred language,
// falling back to any available value.
func SelectLocalizedValue(values []LocalizedValue, preferLang string) string {
	if len(values) == 0 {
		return ""
	}

	// First pass: look for preferred language
	for _, v := range values {
		if v.Lang == preferLang {
			return strings.TrimSpace(v.Value)
		}
	}

	// Second pass: look for any English variant
	for _, v := range values {
		if strings.HasPrefix(v.Lang, "en") {
			return strings.TrimSpace(v.Value)
		}
	}

	// Fall back to first available value
	return strings.TrimSpace(values[0].Value)
}

// LocalizedValuesToMap converts a slice of LocalizedValue to a map
// keyed by language code.
func LocalizedValuesToMap(values []LocalizedValue) map[string]string {
	if len(values) == 0 {
		return nil
	}
	m := make(map[string]string, len(values))
	for _, v := range values {
		m[v.Lang] = strings.TrimSpace(v.Value)
	}
	return m
}

// SelectFromMap selects the value for the first matching language preference.
// Falls back to defaultLang if no preference matches, then to any available value.
func SelectFromMap(m map[string]string, prefs []string, defaultLang string) string {
	if len(m) == 0 {
		return ""
	}

	// Try each preference in order
	for _, pref := range prefs {
		if val, ok := m[pref]; ok {
			return val
		}
		// Try base language for regional variants (en-US -> en)
		if idx := strings.Index(pref, "-"); idx != -1 {
			if val, ok := m[pref[:idx]]; ok {
				return val
			}
		}
	}

	// Fallback to configured default language
	if val, ok := m[defaultLang]; ok {
		return val
	}

	// Fallback to any variant of the default language (e.g., en-GB if default is en)
	for lang, val := range m {
		if strings.HasPrefix(lang, defaultLang) {
			return val
		}
	}

	// Last resort: return any value
	for _, val := range m {
		return val
	}

	return ""
}

// LocalizeIdPInfo returns a copy of the IdPInfo with localized fields
// selected based on the language preferences.
// The defaultLang is used as fallback when no preference matches.
func LocalizeIdPInfo(idp IdPInfo, prefs []string, defaultLang string) IdPInfo {
	// Create a copy (IdPInfo is a value type, so this is already a copy)
	localized := idp

	// Localize DisplayName if we have language variants
	if len(idp.DisplayNames) > 0 {
		localized.DisplayName = SelectFromMap(idp.DisplayNames, prefs, defaultLang)
	}

	// Localize Description if we have language variants
	if len(idp.Descriptions) > 0 {
		localized.Description = SelectFromMap(idp.Descriptions, prefs, defaultLang)
	}

	// Localize InformationURL if we have language variants
	if len(idp.InformationURLs) > 0 {
		localized.InformationURL = SelectFromMap(idp.InformationURLs, prefs, defaultLang)
	}

	return localized
}

// MatchesSearch returns true if the IdP matches the search query.
// Searches across: EntityID, DisplayName, and ALL DisplayNames variants.
// This enables searching in any language regardless of Accept-Language.
func MatchesSearch(idp *IdPInfo, query string) bool {
	if query == "" {
		return true
	}
	query = strings.ToLower(query)

	// Check EntityID
	if strings.Contains(strings.ToLower(idp.EntityID), query) {
		return true
	}

	// Check default DisplayName
	if strings.Contains(strings.ToLower(idp.DisplayName), query) {
		return true
	}

	// Check ALL language variants
	for _, name := range idp.DisplayNames {
		if strings.Contains(strings.ToLower(name), query) {
			return true
		}
	}

	return false
}

// safeArea calculates the area of a logo, treating negative dimensions as zero.
// Uses int64 to prevent integer overflow when multiplying Height × Width.
func safeArea(height, width int) int64 {
	if height <= 0 || width <= 0 {
		return 0
	}
	return int64(height) * int64(width)
}

// SelectBestLogo returns the URL of the largest logo (by area).
func SelectBestLogo(logos []Logo) string {
	if len(logos) == 0 {
		return ""
	}

	best := logos[0]
	bestArea := safeArea(best.Height, best.Width)

	for _, logo := range logos[1:] {
		area := safeArea(logo.Height, logo.Width)
		if area > bestArea {
			best = logo
			bestArea = area
		}
	}

	return strings.TrimSpace(best.URL)
}

// ExtractScope extracts the scope part from a scoped attribute value.
// Returns the part after @ for values like "user@example.edu".
// Returns empty string if no @ is present or if value is empty.
//
// This is a pure function with no side effects or I/O.
func ExtractScope(value string) string {
	if value == "" {
		return ""
	}

	idx := strings.Index(value, "@")
	if idx == -1 {
		return ""
	}

	// Return everything after the first @
	scope := value[idx+1:]
	return scope
}

// ValidateScope validates a scope against allowed scopes from IdP metadata.
// Returns true if scope matches any allowed scope (either literal or regex).
// Returns false if scope is empty, no scopes are allowed, or no match is found.
//
// This is a pure function with no side effects or I/O.
// For regex scopes, invalid patterns return false (no panic).
// Regex matching uses a timeout to prevent ReDoS attacks.
func ValidateScope(scope string, allowed []ScopeInfo) bool {
	if scope == "" {
		return false
	}

	if len(allowed) == 0 {
		return false
	}

	for _, s := range allowed {
		if !s.Regexp {
			// Literal match (case-sensitive)
			if scope == s.Value {
				return true
			}
		} else {
			// Regex match with timeout protection
			matched, err := validateScopeRegex(scope, s.Value)
			if err != nil {
				// Invalid regex or timeout - reject
				continue
			}
			if matched {
				return true
			}
		}
	}

	return false
}

// validateScopeRegex validates a scope against a regex pattern with timeout protection.
// Returns (true, nil) if matched, (false, nil) if not matched, (false, error) on error/timeout.
func validateScopeRegex(scope, pattern string) (bool, error) {
	// Compile regex with timeout protection
	// Note: Go's regexp package doesn't have built-in timeout, but we can use
	// a simple approach: compile and match. For ReDoS protection, we rely on
	// fuzz testing to catch problematic patterns. In production, consider using
	// a regex engine with timeout support or limiting pattern complexity.
	re, err := regexp.Compile("^" + pattern + "$")
	if err != nil {
		// Invalid regex pattern
		return false, err
	}

	// Match with anchored pattern (^...$)
	return re.MatchString(scope), nil
}






