package caddysamldisco

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
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
}

// MetadataStore is the port interface for accessing IdP metadata.
type MetadataStore interface {
	// GetIdP returns information about a specific IdP by entity ID.
	GetIdP(entityID string) (*IdPInfo, error)

	// ListIdPs returns all IdPs, optionally filtered by a search term.
	ListIdPs(filter string) ([]IdPInfo, error)

	// Refresh reloads metadata from the source.
	Refresh(ctx context.Context) error

	// Health returns the health status of the metadata store.
	Health() MetadataHealth
}

// ErrIdPNotFound is returned when an IdP is not found in the store.
var ErrIdPNotFound = fmt.Errorf("idp not found")

// matchesEntityIDPattern returns true if the entityID matches the glob pattern.
// Empty pattern matches everything. Uses strings.Contains for substring matching
// when pattern is wrapped in wildcards (e.g., "*example*").
func matchesEntityIDPattern(entityID, pattern string) bool {
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

// MetadataOption is a functional option for configuring metadata stores.
type MetadataOption func(*metadataOptions)

type metadataOptions struct {
	idpFilter         string
	signatureVerifier SignatureVerifier
}

// WithIdPFilter returns an option that filters IdPs by entity ID pattern.
// Only IdPs whose entity ID matches the pattern will be loaded.
// Supports glob-like patterns: "*substring*", "prefix*", "*suffix".
func WithIdPFilter(pattern string) MetadataOption {
	return func(o *metadataOptions) {
		o.idpFilter = pattern
	}
}

// WithSignatureVerifier returns an option that enables signature verification.
// When set, metadata will be verified against the trusted certificates before parsing.
func WithSignatureVerifier(verifier SignatureVerifier) MetadataOption {
	return func(o *metadataOptions) {
		o.signatureVerifier = verifier
	}
}

// InMemoryMetadataStore is a simple in-memory metadata store for testing.
type InMemoryMetadataStore struct {
	mu   sync.RWMutex
	idps []IdPInfo
}

// NewInMemoryMetadataStore creates a new InMemoryMetadataStore with the given IdPs.
func NewInMemoryMetadataStore(idps []IdPInfo) *InMemoryMetadataStore {
	return &InMemoryMetadataStore{idps: idps}
}

// GetIdP returns the IdP with the given entity ID.
func (s *InMemoryMetadataStore) GetIdP(entityID string) (*IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.idps {
		if s.idps[i].EntityID == entityID {
			idp := s.idps[i]
			return &idp, nil
		}
	}
	return nil, ErrIdPNotFound
}

// ListIdPs returns all IdPs, optionally filtered by a search term.
// Searches across EntityID, DisplayName, and all DisplayNames language variants.
func (s *InMemoryMetadataStore) ListIdPs(filter string) ([]IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []IdPInfo
	for _, idp := range s.idps {
		if MatchesSearch(&idp, filter) {
			result = append(result, idp)
		}
	}
	return result, nil
}

// Refresh is a no-op for in-memory store.
func (s *InMemoryMetadataStore) Refresh(ctx context.Context) error {
	return nil
}

// Health returns the health status of the in-memory store.
// In-memory stores are always considered fresh.
func (s *InMemoryMetadataStore) Health() MetadataHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return MetadataHealth{
		IsFresh:  true,
		IdPCount: len(s.idps),
	}
}

// FileMetadataStore loads IdP metadata from a local file.
// Supports both single EntityDescriptor and aggregate EntitiesDescriptor formats.
type FileMetadataStore struct {
	path              string
	idpFilter         string
	signatureVerifier SignatureVerifier

	mu   sync.RWMutex
	idps []IdPInfo // Supports multiple IdPs from aggregate metadata
}

// NewFileMetadataStore creates a new FileMetadataStore.
func NewFileMetadataStore(path string, opts ...MetadataOption) *FileMetadataStore {
	options := &metadataOptions{}
	for _, opt := range opts {
		opt(options)
	}
	return &FileMetadataStore{
		path:              path,
		idpFilter:         options.idpFilter,
		signatureVerifier: options.signatureVerifier,
	}
}

// Load reads and parses the metadata file.
// This should be called during initialization.
func (s *FileMetadataStore) Load() error {
	return s.Refresh(context.Background())
}

// GetIdP returns the IdP if the entity ID matches.
func (s *FileMetadataStore) GetIdP(entityID string) (*IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.idps {
		if s.idps[i].EntityID == entityID {
			// Return a copy to prevent mutation
			idp := s.idps[i]
			return &idp, nil
		}
	}

	return nil, ErrIdPNotFound
}

// ListIdPs returns all IdPs, optionally filtered by a search term.
// Searches across EntityID, DisplayName, and all DisplayNames language variants.
func (s *FileMetadataStore) ListIdPs(filter string) ([]IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.idps) == 0 {
		return nil, nil
	}

	var result []IdPInfo
	for _, idp := range s.idps {
		if MatchesSearch(&idp, filter) {
			result = append(result, idp)
		}
	}

	return result, nil
}

// Refresh reloads metadata from the file.
func (s *FileMetadataStore) Refresh(ctx context.Context) error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read metadata file: %w", err)
	}

	// Verify signature if verifier is configured
	if s.signatureVerifier != nil {
		data, err = s.signatureVerifier.Verify(data)
		if err != nil {
			return fmt.Errorf("verify metadata signature: %w", err)
		}
	}

	idps, err := parseMetadata(data)
	if err != nil {
		return fmt.Errorf("parse metadata: %w", err)
	}

	// Apply IdP filter if configured
	if s.idpFilter != "" {
		idps = filterIdPs(idps, s.idpFilter)
		if len(idps) == 0 {
			return fmt.Errorf("no IdPs match filter pattern %q", s.idpFilter)
		}
	}

	s.mu.Lock()
	s.idps = idps
	s.mu.Unlock()

	return nil
}

// Health returns the health status of the file metadata store.
func (s *FileMetadataStore) Health() MetadataHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return MetadataHealth{
		IsFresh:  len(s.idps) > 0,
		IdPCount: len(s.idps),
	}
}

// filterIdPs returns only IdPs whose entity ID matches the pattern.
func filterIdPs(idps []IdPInfo, pattern string) []IdPInfo {
	if pattern == "" {
		return idps
	}
	var filtered []IdPInfo
	for _, idp := range idps {
		if matchesEntityIDPattern(idp.EntityID, pattern) {
			filtered = append(filtered, idp)
		}
	}
	return filtered
}

// parseMetadata parses SAML metadata XML, supporting both single EntityDescriptor
// and aggregate EntitiesDescriptor formats.
func parseMetadata(data []byte) ([]IdPInfo, error) {
	// Parse UIInfo and RegistrationInfo separately since crewjam/saml doesn't expose them
	uiInfoMap := parseAllUIInfo(data)
	regInfoMap := parseAllRegistrationInfo(data)

	// Try EntitiesDescriptor first (aggregate metadata)
	var entities saml.EntitiesDescriptor
	if err := xml.Unmarshal(data, &entities); err == nil && len(entities.EntityDescriptors) > 0 {
		return parseEntitiesDescriptorWithMaps(&entities, uiInfoMap, regInfoMap)
	}

	// Fall back to single EntityDescriptor
	idp, err := parseEntityDescriptorWithMaps(data, uiInfoMap, regInfoMap)
	if err != nil {
		return nil, err
	}
	return []IdPInfo{*idp}, nil
}

// entityUIInfo holds parsed UIInfo for a specific entity.
type entityUIInfo struct {
	EntityID string
	UIInfo   *UIInfo
}

// rawEntityDescriptor is used to parse UIInfo from raw XML.
type rawEntityDescriptor struct {
	EntityID          string `xml:"entityID,attr"`
	IDPSSODescriptors []struct {
		Extensions struct {
			UIInfo *UIInfo `xml:"urn:oasis:names:tc:SAML:metadata:ui UIInfo"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
}

// rawEntitiesDescriptor is used to parse UIInfo from aggregate metadata.
type rawEntitiesDescriptor struct {
	EntityDescriptors    []rawEntityDescriptor    `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntitiesDescriptors  []rawEntitiesDescriptor  `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
}

// rawEntityDescriptorForRegInfo is used to parse RegistrationInfo from raw XML.
// RegistrationInfo is at EntityDescriptor/Extensions level (not IDPSSODescriptor).
type rawEntityDescriptorForRegInfo struct {
	EntityID   string `xml:"entityID,attr"`
	Extensions struct {
		RegistrationInfo *RegistrationInfo `xml:"urn:oasis:names:tc:SAML:metadata:rpi RegistrationInfo"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions"`
}

// rawEntitiesDescriptorForRegInfo is used to parse RegistrationInfo from aggregate metadata.
type rawEntitiesDescriptorForRegInfo struct {
	EntityDescriptors   []rawEntityDescriptorForRegInfo   `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntitiesDescriptors []rawEntitiesDescriptorForRegInfo `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
}

// parseAllUIInfo extracts UIInfo for all entities from raw XML.
func parseAllUIInfo(data []byte) map[string]*UIInfo {
	result := make(map[string]*UIInfo)

	// Try parsing as EntitiesDescriptor (aggregate)
	var entities rawEntitiesDescriptor
	if err := xml.Unmarshal(data, &entities); err == nil {
		extractUIInfoFromEntities(&entities, result)
		if len(result) > 0 {
			return result
		}
	}

	// Try parsing as single EntityDescriptor
	var entity rawEntityDescriptor
	if err := xml.Unmarshal(data, &entity); err == nil {
		if len(entity.IDPSSODescriptors) > 0 && entity.IDPSSODescriptors[0].Extensions.UIInfo != nil {
			result[entity.EntityID] = entity.IDPSSODescriptors[0].Extensions.UIInfo
		}
	}

	return result
}

// extractUIInfoFromEntities recursively extracts UIInfo from EntitiesDescriptor.
func extractUIInfoFromEntities(entities *rawEntitiesDescriptor, result map[string]*UIInfo) {
	for _, ed := range entities.EntityDescriptors {
		if len(ed.IDPSSODescriptors) > 0 && ed.IDPSSODescriptors[0].Extensions.UIInfo != nil {
			result[ed.EntityID] = ed.IDPSSODescriptors[0].Extensions.UIInfo
		}
	}
	for i := range entities.EntitiesDescriptors {
		extractUIInfoFromEntities(&entities.EntitiesDescriptors[i], result)
	}
}

// parseAllRegistrationInfo extracts RegistrationInfo for all entities from raw XML.
func parseAllRegistrationInfo(data []byte) map[string]*RegistrationInfo {
	result := make(map[string]*RegistrationInfo)

	// Try parsing as EntitiesDescriptor (aggregate)
	var entities rawEntitiesDescriptorForRegInfo
	if err := xml.Unmarshal(data, &entities); err == nil {
		extractRegInfoFromEntities(&entities, result)
		if len(result) > 0 {
			return result
		}
	}

	// Try parsing as single EntityDescriptor
	var entity rawEntityDescriptorForRegInfo
	if err := xml.Unmarshal(data, &entity); err == nil {
		if entity.Extensions.RegistrationInfo != nil {
			result[entity.EntityID] = entity.Extensions.RegistrationInfo
		}
	}

	return result
}

// extractRegInfoFromEntities recursively extracts RegistrationInfo from EntitiesDescriptor.
func extractRegInfoFromEntities(entities *rawEntitiesDescriptorForRegInfo, result map[string]*RegistrationInfo) {
	for _, ed := range entities.EntityDescriptors {
		if ed.Extensions.RegistrationInfo != nil {
			result[ed.EntityID] = ed.Extensions.RegistrationInfo
		}
	}
	for i := range entities.EntitiesDescriptors {
		extractRegInfoFromEntities(&entities.EntitiesDescriptors[i], result)
	}
}

// parseEntitiesDescriptorWithMaps extracts all IdPs from an aggregate metadata document.
// It skips entities without IDPSSODescriptor (e.g., SP metadata).
func parseEntitiesDescriptorWithMaps(entities *saml.EntitiesDescriptor, uiInfoMap map[string]*UIInfo, regInfoMap map[string]*RegistrationInfo) ([]IdPInfo, error) {
	var idps []IdPInfo

	// Process direct EntityDescriptor children
	for i := range entities.EntityDescriptors {
		idp, err := extractIdPInfoWithMaps(&entities.EntityDescriptors[i], uiInfoMap, regInfoMap)
		if err != nil {
			// Skip entities without IDPSSODescriptor (SPs, etc.)
			continue
		}
		idps = append(idps, *idp)
	}

	// Process nested EntitiesDescriptor elements (recursive)
	for i := range entities.EntitiesDescriptors {
		nestedIdps, err := parseEntitiesDescriptorWithMaps(&entities.EntitiesDescriptors[i], uiInfoMap, regInfoMap)
		if err != nil {
			continue
		}
		idps = append(idps, nestedIdps...)
	}

	if len(idps) == 0 {
		return nil, fmt.Errorf("no IdPs found in aggregate metadata")
	}

	return idps, nil
}

// parseEntityDescriptorWithMaps extracts IdPInfo from a single EntityDescriptor XML.
func parseEntityDescriptorWithMaps(data []byte, uiInfoMap map[string]*UIInfo, regInfoMap map[string]*RegistrationInfo) (*IdPInfo, error) {
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(data, &ed); err != nil {
		return nil, fmt.Errorf("unmarshal xml: %w", err)
	}

	return extractIdPInfoWithMaps(&ed, uiInfoMap, regInfoMap)
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

// IDPSSODescriptorExtensions wraps Extensions to extract UIInfo.
type IDPSSODescriptorExtensions struct {
	UIInfo *UIInfo `xml:"UIInfo"`
}

// RegistrationInfo represents the mdrpi:RegistrationInfo element.
// This indicates which federation registered the IdP.
type RegistrationInfo struct {
	RegistrationAuthority string           `xml:"registrationAuthority,attr"`
	RegistrationInstant   string           `xml:"registrationInstant,attr"` // ISO 8601 timestamp
	RegistrationPolicies  []LocalizedValue `xml:"RegistrationPolicy"`
}

// extractIdPInfoWithMaps extracts IdPInfo from a single EntityDescriptor,
// using pre-parsed UIInfo and RegistrationInfo from the maps.
func extractIdPInfoWithMaps(ed *saml.EntityDescriptor, uiInfoMap map[string]*UIInfo, regInfoMap map[string]*RegistrationInfo) (*IdPInfo, error) {
	if len(ed.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("no IDPSSODescriptor found")
	}

	idpDesc := ed.IDPSSODescriptors[0]

	// Find SSO endpoint - prefer HTTP-Redirect, fall back to HTTP-POST
	var ssoURL, ssoBinding string
	for _, sso := range idpDesc.SingleSignOnServices {
		if sso.Binding == saml.HTTPRedirectBinding {
			ssoURL = sso.Location
			ssoBinding = sso.Binding
			break
		}
		if sso.Binding == saml.HTTPPostBinding && ssoURL == "" {
			ssoURL = sso.Location
			ssoBinding = sso.Binding
		}
	}

	// Get UIInfo from pre-parsed map
	uiInfo := uiInfoMap[ed.EntityID]

	// Extract all language variants and default display name
	var displayNames map[string]string
	displayName := ed.EntityID
	if uiInfo != nil && len(uiInfo.DisplayNames) > 0 {
		displayNames = localizedValuesToMap(uiInfo.DisplayNames)
		displayName = selectLocalizedValue(uiInfo.DisplayNames, "en")
	} else if ed.Organization != nil && len(ed.Organization.OrganizationDisplayNames) > 0 {
		displayName = ed.Organization.OrganizationDisplayNames[0].Value
	}

	// Extract all language variants and default description
	var descriptions map[string]string
	var description string
	if uiInfo != nil && len(uiInfo.Descriptions) > 0 {
		descriptions = localizedValuesToMap(uiInfo.Descriptions)
		description = selectLocalizedValue(uiInfo.Descriptions, "en")
	}

	// Extract logo URL from UIInfo (prefer larger logos)
	var logoURL string
	if uiInfo != nil && len(uiInfo.Logos) > 0 {
		logoURL = selectBestLogo(uiInfo.Logos)
	}

	// Extract all language variants and default information URL
	var informationURLs map[string]string
	var informationURL string
	if uiInfo != nil && len(uiInfo.InformationURLs) > 0 {
		informationURLs = localizedValuesToMap(uiInfo.InformationURLs)
		informationURL = selectLocalizedValue(uiInfo.InformationURLs, "en")
	}

	// Extract certificates
	var certs []string
	for _, kd := range idpDesc.KeyDescriptors {
		if kd.Use == "signing" || kd.Use == "" {
			for _, cert := range kd.KeyInfo.X509Data.X509Certificates {
				certs = append(certs, cert.Data)
			}
		}
	}

	// Extract RegistrationInfo from pre-parsed map
	var registrationAuthority string
	var registrationInstant time.Time
	var registrationPolicies map[string]string
	if regInfo := regInfoMap[ed.EntityID]; regInfo != nil {
		registrationAuthority = regInfo.RegistrationAuthority
		if regInfo.RegistrationInstant != "" {
			if t, err := time.Parse(time.RFC3339, regInfo.RegistrationInstant); err == nil {
				registrationInstant = t
			}
		}
		if len(regInfo.RegistrationPolicies) > 0 {
			registrationPolicies = localizedValuesToMap(regInfo.RegistrationPolicies)
		}
	}

	return &IdPInfo{
		EntityID:              ed.EntityID,
		DisplayName:           displayName,
		DisplayNames:          displayNames,
		Description:           description,
		Descriptions:          descriptions,
		LogoURL:               logoURL,
		InformationURL:        informationURL,
		InformationURLs:       informationURLs,
		SSOURL:                ssoURL,
		SSOBinding:            ssoBinding,
		Certificates:          certs,
		RegistrationAuthority: registrationAuthority,
		RegistrationInstant:   registrationInstant,
		RegistrationPolicies:  registrationPolicies,
	}, nil
}

// selectLocalizedValue returns the value for the preferred language,
// falling back to any available value.
func selectLocalizedValue(values []LocalizedValue, preferLang string) string {
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

// localizedValuesToMap converts a slice of LocalizedValue to a map
// keyed by language code.
func localizedValuesToMap(values []LocalizedValue) map[string]string {
	if len(values) == 0 {
		return nil
	}
	m := make(map[string]string, len(values))
	for _, v := range values {
		m[v.Lang] = strings.TrimSpace(v.Value)
	}
	return m
}

// selectFromMap selects the value for the first matching language preference.
// Falls back to defaultLang if no preference matches, then to any available value.
func selectFromMap(m map[string]string, prefs []string, defaultLang string) string {
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
		localized.DisplayName = selectFromMap(idp.DisplayNames, prefs, defaultLang)
	}

	// Localize Description if we have language variants
	if len(idp.Descriptions) > 0 {
		localized.Description = selectFromMap(idp.Descriptions, prefs, defaultLang)
	}

	// Localize InformationURL if we have language variants
	if len(idp.InformationURLs) > 0 {
		localized.InformationURL = selectFromMap(idp.InformationURLs, prefs, defaultLang)
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

// selectBestLogo returns the URL of the largest logo (by area).
func selectBestLogo(logos []Logo) string {
	if len(logos) == 0 {
		return ""
	}

	best := logos[0]
	bestArea := best.Height * best.Width

	for _, logo := range logos[1:] {
		area := logo.Height * logo.Width
		if area > bestArea {
			best = logo
			bestArea = area
		}
	}

	return strings.TrimSpace(best.URL)
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
}

// URLMetadataStore loads IdP metadata from a URL with caching.
type URLMetadataStore struct {
	url               string
	httpClient        *http.Client
	cacheTTL          time.Duration
	idpFilter         string
	signatureVerifier SignatureVerifier

	mu              sync.RWMutex
	idps            []IdPInfo
	lastFetch       time.Time
	etag            string
	lastModified    string
	isFresh         bool      // true if last refresh succeeded
	lastSuccessTime time.Time // time of last successful refresh
	lastError       error     // error from last refresh (nil if success)
}

// NewURLMetadataStore creates a new URLMetadataStore.
func NewURLMetadataStore(url string, cacheTTL time.Duration, opts ...MetadataOption) *URLMetadataStore {
	options := &metadataOptions{}
	for _, opt := range opts {
		opt(options)
	}
	return &URLMetadataStore{
		url:               url,
		cacheTTL:          cacheTTL,
		idpFilter:         options.idpFilter,
		signatureVerifier: options.signatureVerifier,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Load fetches and parses the metadata from the URL.
// This should be called during initialization.
func (s *URLMetadataStore) Load() error {
	return s.Refresh(context.Background())
}

// GetIdP returns the IdP if the entity ID matches.
func (s *URLMetadataStore) GetIdP(entityID string) (*IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.idps {
		if s.idps[i].EntityID == entityID {
			idp := s.idps[i]
			return &idp, nil
		}
	}

	return nil, ErrIdPNotFound
}

// ListIdPs returns all IdPs, optionally filtered by a search term.
// Searches across EntityID, DisplayName, and all DisplayNames language variants.
func (s *URLMetadataStore) ListIdPs(filter string) ([]IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.idps) == 0 {
		return nil, nil
	}

	var result []IdPInfo
	for _, idp := range s.idps {
		if MatchesSearch(&idp, filter) {
			result = append(result, idp)
		}
	}

	return result, nil
}

// IsFresh returns true if the cached metadata is from a successful recent refresh.
// Returns false before any load, or after a failed refresh (stale data is still served).
func (s *URLMetadataStore) IsFresh() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isFresh
}

// LastError returns the error from the most recent failed refresh, or nil if
// the last refresh succeeded.
func (s *URLMetadataStore) LastError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastError
}

// Health returns comprehensive health status for monitoring.
func (s *URLMetadataStore) Health() MetadataHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return MetadataHealth{
		IsFresh:         s.isFresh,
		LastSuccessTime: s.lastSuccessTime,
		LastError:       s.lastError,
		IdPCount:        len(s.idps),
	}
}

// Refresh fetches metadata from the URL if cache has expired.
// On failure, existing cached data is preserved (graceful degradation) and
// IsFresh() returns false. The error is still returned for logging/monitoring.
func (s *URLMetadataStore) Refresh(ctx context.Context) error {
	// Check if cache is still valid
	s.mu.RLock()
	if !s.lastFetch.IsZero() && time.Since(s.lastFetch) < s.cacheTTL {
		s.mu.RUnlock()
		return nil // Cache hit
	}
	etag := s.etag
	lastModified := s.lastModified
	s.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		refreshErr := fmt.Errorf("create request: %w", err)
		s.markRefreshFailed(refreshErr)
		return refreshErr
	}

	// Set User-Agent header for identification
	req.Header.Set("User-Agent", "caddy-saml-disco/"+Version)

	// Add conditional request headers if we have cached values
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		refreshErr := fmt.Errorf("fetch metadata: %w", err)
		s.markRefreshFailed(refreshErr)
		return refreshErr
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified - data hasn't changed, still counts as success
	if resp.StatusCode == http.StatusNotModified {
		s.mu.Lock()
		s.lastFetch = time.Now()
		s.isFresh = true
		s.lastError = nil
		// lastSuccessTime stays the same (data itself didn't change)
		s.mu.Unlock()
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		refreshErr := fmt.Errorf("fetch metadata: HTTP %d", resp.StatusCode)
		s.markRefreshFailed(refreshErr)
		return refreshErr
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		refreshErr := fmt.Errorf("read response: %w", err)
		s.markRefreshFailed(refreshErr)
		return refreshErr
	}

	// Verify signature if verifier is configured
	if s.signatureVerifier != nil {
		data, err = s.signatureVerifier.Verify(data)
		if err != nil {
			refreshErr := fmt.Errorf("verify metadata signature: %w", err)
			s.markRefreshFailed(refreshErr)
			return refreshErr
		}
	}

	idps, err := parseMetadata(data)
	if err != nil {
		refreshErr := fmt.Errorf("parse metadata: %w", err)
		s.markRefreshFailed(refreshErr)
		return refreshErr
	}

	// Apply IdP filter if configured
	if s.idpFilter != "" {
		idps = filterIdPs(idps, s.idpFilter)
		if len(idps) == 0 {
			refreshErr := fmt.Errorf("no IdPs match filter pattern %q", s.idpFilter)
			s.markRefreshFailed(refreshErr)
			return refreshErr
		}
	}

	// Success - update all state
	now := time.Now()
	s.mu.Lock()
	s.idps = idps
	s.lastFetch = now
	s.etag = resp.Header.Get("ETag")
	s.lastModified = resp.Header.Get("Last-Modified")
	s.isFresh = true
	s.lastSuccessTime = now
	s.lastError = nil
	s.mu.Unlock()

	return nil
}

// markRefreshFailed updates state when refresh fails, preserving existing data.
func (s *URLMetadataStore) markRefreshFailed(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isFresh = false
	s.lastError = err
	// idps, lastSuccessTime are preserved - serve stale data
}
