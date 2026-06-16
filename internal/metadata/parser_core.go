package metadata

import (
	"encoding/xml"
	"fmt"
	"time"

	"github.com/crewjam/saml"

	"github.com/philiph/caddy-saml-disco/internal/domain"
)

// rawMetadataValidity is used to extract validUntil from metadata.
// Works for both EntitiesDescriptor and EntityDescriptor.
type rawMetadataValidity struct {
	ValidUntil string `xml:"validUntil,attr"`
}

// idpInfoMaps bundles the four entity-keyed lookup maps that are parsed
// separately from the crewjam/saml descriptors and always travel together
// while building IdPInfo records.
type idpInfoMaps struct {
	uiInfo      map[string]*domain.UIInfo
	regInfo     map[string]*domain.RegistrationInfo
	scope       map[string][]domain.ScopeInfo
	entityAttrs map[string]*domain.EntityAttributesInfo
}

// ParseMetadata parses SAML metadata XML, supporting both single EntityDescriptor
// and aggregate EntitiesDescriptor formats.
// Returns ErrMetadataExpired if the metadata has a validUntil attribute in the past.
// Also returns the validUntil timestamp if present (nil otherwise).
func ParseMetadata(data []byte) ([]domain.IdPInfo, *time.Time, error) {
	// Check validUntil before parsing the rest
	validUntil, err := extractAndValidateExpiry(data)
	if err != nil {
		return nil, nil, err
	}

	// Parse UIInfo, RegistrationInfo, Scopes, and EntityAttributes separately since crewjam/saml doesn't expose them
	maps := idpInfoMaps{
		uiInfo:      parseAllUIInfo(data),
		regInfo:     parseAllRegistrationInfo(data),
		scope:       parseAllScopes(data),
		entityAttrs: parseAllEntityAttributes(data),
	}

	// Try EntitiesDescriptor first (aggregate metadata)
	var entities saml.EntitiesDescriptor
	if err := xml.Unmarshal(data, &entities); err == nil && isEntitiesDescriptor(data) {
		idps, err := parseEntitiesDescriptorWithMaps(&entities, maps)
		return idps, validUntil, err
	}

	// Fall back to single EntityDescriptor
	idp, err := parseEntityDescriptorWithMaps(data, maps)
	if err != nil {
		return nil, nil, err
	}
	return []domain.IdPInfo{*idp}, validUntil, nil
}

// isEntitiesDescriptor checks if the XML data has EntitiesDescriptor as root element.
// This helps distinguish between aggregate metadata (EntitiesDescriptor) and single IdP metadata (EntityDescriptor).
func isEntitiesDescriptor(data []byte) bool {
	// Quick heuristic: check if the root element is EntitiesDescriptor
	// This is faster than full XML parsing and sufficient for our needs
	type rootDetector struct {
		XMLName xml.Name
	}
	var root rootDetector
	if err := xml.Unmarshal(data, &root); err != nil {
		return false
	}
	return root.XMLName.Local == "EntitiesDescriptor"
}

// extractAndValidateExpiry extracts validUntil from metadata and validates it.
// Returns the validUntil timestamp (nil if not present) and an error if expired.
func extractAndValidateExpiry(data []byte) (*time.Time, error) {
	var validity rawMetadataValidity
	if err := xml.Unmarshal(data, &validity); err != nil {
		// If we can't parse, let the main parser handle the error
		return nil, nil
	}

	if validity.ValidUntil == "" {
		return nil, nil // No validUntil attribute
	}

	validUntil, err := time.Parse(time.RFC3339, validity.ValidUntil)
	if err != nil {
		return nil, fmt.Errorf("invalid validUntil format %q: %w", validity.ValidUntil, err)
	}

	if domain.IsMetadataExpired(validUntil, time.Now()) {
		return nil, fmt.Errorf("%w: validUntil %s is in the past", domain.ErrMetadataExpired, validity.ValidUntil)
	}

	return &validUntil, nil
}

// parseEntitiesDescriptorWithMaps extracts all IdPs from an aggregate metadata document.
// It skips entities without IDPSSODescriptor (e.g., SP metadata).
func parseEntitiesDescriptorWithMaps(entities *saml.EntitiesDescriptor, maps idpInfoMaps) ([]domain.IdPInfo, error) {
	var idps []domain.IdPInfo

	// Process direct EntityDescriptor children
	for i := range entities.EntityDescriptors {
		idp, err := extractIdPInfoWithMaps(&entities.EntityDescriptors[i], maps)
		if err != nil {
			// Skip entities without IDPSSODescriptor (SPs, etc.)
			continue
		}
		idps = append(idps, *idp)
	}

	// Process nested EntitiesDescriptor elements (recursive)
	for i := range entities.EntitiesDescriptors {
		nestedIdps, err := parseEntitiesDescriptorWithMaps(&entities.EntitiesDescriptors[i], maps)
		if err != nil {
			continue
		}
		idps = append(idps, nestedIdps...)
	}

	// Return empty slice (not nil) when no IdPs found - this is valid for empty aggregate metadata
	if idps == nil {
		idps = []domain.IdPInfo{}
	}

	return idps, nil
}

// parseEntityDescriptorWithMaps extracts IdPInfo from a single EntityDescriptor XML.
func parseEntityDescriptorWithMaps(data []byte, maps idpInfoMaps) (*domain.IdPInfo, error) {
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(data, &ed); err != nil {
		return nil, fmt.Errorf("unmarshal xml: %w", err)
	}

	return extractIdPInfoWithMaps(&ed, maps)
}

// extractIdPInfoWithMaps extracts IdPInfo from a single EntityDescriptor,
// using pre-parsed UIInfo, RegistrationInfo, Scopes, and EntityAttributes from the maps.
func extractIdPInfoWithMaps(ed *saml.EntityDescriptor, maps idpInfoMaps) (*domain.IdPInfo, error) {
	if ed.EntityID == "" {
		return nil, fmt.Errorf("missing entityID attribute")
	}
	if len(ed.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("no IDPSSODescriptor found")
	}

	idpDesc := ed.IDPSSODescriptors[0]

	ssoURL, ssoBinding := selectPreferredEndpoint(idpDesc.SingleSignOnServices)
	sloURL, sloBinding := selectPreferredEndpoint(idpDesc.SingleLogoutServices)

	display := extractDisplayInfo(ed, maps.uiInfo[ed.EntityID])
	registration := extractRegistrationInfo(maps.regInfo[ed.EntityID])

	// Extract EntityAttributes from pre-parsed map
	var entityCategories []string
	var assuranceCertifications []string
	if attrs := maps.entityAttrs[ed.EntityID]; attrs != nil {
		entityCategories = attrs.EntityCategories
		assuranceCertifications = attrs.AssuranceCertifications
	}

	return &domain.IdPInfo{
		EntityID:                ed.EntityID,
		DisplayName:             display.displayName,
		DisplayNames:            display.displayNames,
		Description:             display.description,
		Descriptions:            display.descriptions,
		LogoURL:                 display.logoURL,
		InformationURL:          display.informationURL,
		InformationURLs:         display.informationURLs,
		SSOURL:                  ssoURL,
		SSOBinding:              ssoBinding,
		SLOURL:                  sloURL,
		SLOBinding:              sloBinding,
		Certificates:            extractSigningCertificates(idpDesc.KeyDescriptors),
		RegistrationAuthority:   registration.authority,
		RegistrationInstant:     registration.instant,
		RegistrationPolicies:    registration.policies,
		AllowedScopes:           maps.scope[ed.EntityID],
		EntityCategories:        entityCategories,
		AssuranceCertifications: assuranceCertifications,
	}, nil
}

// selectPreferredEndpoint picks the SSO/SLO endpoint to use from a list of
// SAML endpoints, preferring HTTP-Redirect and falling back to HTTP-POST.
// Returns the location URL and the binding that was selected (empty if none).
func selectPreferredEndpoint(endpoints []saml.Endpoint) (location, binding string) {
	for _, ep := range endpoints {
		if ep.Binding == saml.HTTPRedirectBinding {
			return ep.Location, ep.Binding
		}
		if ep.Binding == saml.HTTPPostBinding && location == "" {
			location = ep.Location
			binding = ep.Binding
		}
	}
	return location, binding
}

// idpDisplayInfo holds the human-facing fields derived from UIInfo (with
// EntityID / Organization fallbacks), each as a default value plus a map of
// localized language variants.
type idpDisplayInfo struct {
	displayName     string
	displayNames    map[string]string
	description     string
	descriptions    map[string]string
	logoURL         string
	informationURL  string
	informationURLs map[string]string
}

// extractDisplayInfo derives the display-related fields from the entity's
// UIInfo, falling back to the EntityID and Organization name when UIInfo is
// absent.
func extractDisplayInfo(ed *saml.EntityDescriptor, uiInfo *domain.UIInfo) idpDisplayInfo {
	info := idpDisplayInfo{displayName: ed.EntityID}

	if uiInfo != nil && len(uiInfo.DisplayNames) > 0 {
		info.displayNames = domain.LocalizedValuesToMap(uiInfo.DisplayNames)
		info.displayName = domain.SelectLocalizedValue(uiInfo.DisplayNames, "en")
	} else if ed.Organization != nil && len(ed.Organization.OrganizationDisplayNames) > 0 {
		info.displayName = ed.Organization.OrganizationDisplayNames[0].Value
	}

	if uiInfo == nil {
		return info
	}

	if len(uiInfo.Descriptions) > 0 {
		info.descriptions = domain.LocalizedValuesToMap(uiInfo.Descriptions)
		info.description = domain.SelectLocalizedValue(uiInfo.Descriptions, "en")
	}
	if len(uiInfo.Logos) > 0 {
		info.logoURL = domain.SelectBestLogo(uiInfo.Logos)
	}
	if len(uiInfo.InformationURLs) > 0 {
		info.informationURLs = domain.LocalizedValuesToMap(uiInfo.InformationURLs)
		info.informationURL = domain.SelectLocalizedValue(uiInfo.InformationURLs, "en")
	}

	return info
}

// extractSigningCertificates collects the X.509 certificate data from the
// signing key descriptors (Use == "signing" or unspecified).
func extractSigningCertificates(keyDescriptors []saml.KeyDescriptor) []string {
	var certs []string
	for _, kd := range keyDescriptors {
		if kd.Use != "signing" && kd.Use != "" {
			continue
		}
		for _, cert := range kd.KeyInfo.X509Data.X509Certificates {
			certs = append(certs, cert.Data)
		}
	}
	return certs
}

// idpRegistrationInfo holds the MDRPI registration fields derived from a
// pre-parsed RegistrationInfo entry.
type idpRegistrationInfo struct {
	authority string
	instant   time.Time
	policies  map[string]string
}

// extractRegistrationInfo derives the registration fields from a pre-parsed
// RegistrationInfo entry, returning zero values when it is absent.
func extractRegistrationInfo(regInfo *domain.RegistrationInfo) idpRegistrationInfo {
	if regInfo == nil {
		return idpRegistrationInfo{}
	}

	info := idpRegistrationInfo{authority: regInfo.RegistrationAuthority}
	if regInfo.RegistrationInstant != "" {
		if t, err := time.Parse(time.RFC3339, regInfo.RegistrationInstant); err == nil {
			info.instant = t
		}
	}
	if len(regInfo.RegistrationPolicies) > 0 {
		info.policies = domain.LocalizedValuesToMap(regInfo.RegistrationPolicies)
	}
	return info
}
