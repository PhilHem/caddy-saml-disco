package metadata

import (
	"encoding/xml"
	"fmt"
	"time"

	"github.com/crewjam/saml"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// rawMetadataValidity is used to extract validUntil from metadata.
// Works for both EntitiesDescriptor and EntityDescriptor.
type rawMetadataValidity struct {
	ValidUntil string `xml:"validUntil,attr"`
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
	uiInfoMap := parseAllUIInfo(data)
	regInfoMap := parseAllRegistrationInfo(data)
	scopeMap := parseAllScopes(data)
	entityAttrsMap := parseAllEntityAttributes(data)

	// Try EntitiesDescriptor first (aggregate metadata)
	var entities saml.EntitiesDescriptor
	if err := xml.Unmarshal(data, &entities); err == nil && len(entities.EntityDescriptors) > 0 {
		idps, err := parseEntitiesDescriptorWithMaps(&entities, uiInfoMap, regInfoMap, scopeMap, entityAttrsMap)
		return idps, validUntil, err
	}

	// Fall back to single EntityDescriptor
	idp, err := parseEntityDescriptorWithMaps(data, uiInfoMap, regInfoMap, scopeMap, entityAttrsMap)
	if err != nil {
		return nil, nil, err
	}
	return []domain.IdPInfo{*idp}, validUntil, nil
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
func parseEntitiesDescriptorWithMaps(entities *saml.EntitiesDescriptor, uiInfoMap map[string]*domain.UIInfo, regInfoMap map[string]*domain.RegistrationInfo, scopeMap map[string][]domain.ScopeInfo, entityAttrsMap map[string]*domain.EntityAttributesInfo) ([]domain.IdPInfo, error) {
	var idps []domain.IdPInfo

	// Process direct EntityDescriptor children
	for i := range entities.EntityDescriptors {
		idp, err := extractIdPInfoWithMaps(&entities.EntityDescriptors[i], uiInfoMap, regInfoMap, scopeMap, entityAttrsMap)
		if err != nil {
			// Skip entities without IDPSSODescriptor (SPs, etc.)
			continue
		}
		idps = append(idps, *idp)
	}

	// Process nested EntitiesDescriptor elements (recursive)
	for i := range entities.EntitiesDescriptors {
		nestedIdps, err := parseEntitiesDescriptorWithMaps(&entities.EntitiesDescriptors[i], uiInfoMap, regInfoMap, scopeMap, entityAttrsMap)
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
func parseEntityDescriptorWithMaps(data []byte, uiInfoMap map[string]*domain.UIInfo, regInfoMap map[string]*domain.RegistrationInfo, scopeMap map[string][]domain.ScopeInfo, entityAttrsMap map[string]*domain.EntityAttributesInfo) (*domain.IdPInfo, error) {
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(data, &ed); err != nil {
		return nil, fmt.Errorf("unmarshal xml: %w", err)
	}

	return extractIdPInfoWithMaps(&ed, uiInfoMap, regInfoMap, scopeMap, entityAttrsMap)
}

// extractIdPInfoWithMaps extracts IdPInfo from a single EntityDescriptor,
// using pre-parsed UIInfo, RegistrationInfo, Scopes, and EntityAttributes from the maps.
func extractIdPInfoWithMaps(ed *saml.EntityDescriptor, uiInfoMap map[string]*domain.UIInfo, regInfoMap map[string]*domain.RegistrationInfo, scopeMap map[string][]domain.ScopeInfo, entityAttrsMap map[string]*domain.EntityAttributesInfo) (*domain.IdPInfo, error) {
	if ed.EntityID == "" {
		return nil, fmt.Errorf("missing entityID attribute")
	}
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

	// Find SLO endpoint - prefer HTTP-Redirect, fall back to HTTP-POST
	var sloURL, sloBinding string
	for _, slo := range idpDesc.SingleLogoutServices {
		if slo.Binding == saml.HTTPRedirectBinding {
			sloURL = slo.Location
			sloBinding = slo.Binding
			break
		}
		if slo.Binding == saml.HTTPPostBinding && sloURL == "" {
			sloURL = slo.Location
			sloBinding = slo.Binding
		}
	}

	// Get UIInfo from pre-parsed map
	uiInfo := uiInfoMap[ed.EntityID]

	// Extract all language variants and default display name
	var displayNames map[string]string
	displayName := ed.EntityID
	if uiInfo != nil && len(uiInfo.DisplayNames) > 0 {
		displayNames = domain.LocalizedValuesToMap(uiInfo.DisplayNames)
		displayName = domain.SelectLocalizedValue(uiInfo.DisplayNames, "en")
	} else if ed.Organization != nil && len(ed.Organization.OrganizationDisplayNames) > 0 {
		displayName = ed.Organization.OrganizationDisplayNames[0].Value
	}

	// Extract all language variants and default description
	var descriptions map[string]string
	var description string
	if uiInfo != nil && len(uiInfo.Descriptions) > 0 {
		descriptions = domain.LocalizedValuesToMap(uiInfo.Descriptions)
		description = domain.SelectLocalizedValue(uiInfo.Descriptions, "en")
	}

	// Extract logo URL from UIInfo (prefer larger logos)
	var logoURL string
	if uiInfo != nil && len(uiInfo.Logos) > 0 {
		logoURL = domain.SelectBestLogo(uiInfo.Logos)
	}

	// Extract all language variants and default information URL
	var informationURLs map[string]string
	var informationURL string
	if uiInfo != nil && len(uiInfo.InformationURLs) > 0 {
		informationURLs = domain.LocalizedValuesToMap(uiInfo.InformationURLs)
		informationURL = domain.SelectLocalizedValue(uiInfo.InformationURLs, "en")
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
			registrationPolicies = domain.LocalizedValuesToMap(regInfo.RegistrationPolicies)
		}
	}

	// Extract AllowedScopes from pre-parsed map
	var allowedScopes []domain.ScopeInfo
	if scopes, ok := scopeMap[ed.EntityID]; ok {
		allowedScopes = scopes
	}

	// Extract EntityAttributes from pre-parsed map
	var entityCategories []string
	var assuranceCertifications []string
	if attrs := entityAttrsMap[ed.EntityID]; attrs != nil {
		entityCategories = attrs.EntityCategories
		assuranceCertifications = attrs.AssuranceCertifications
	}

	return &domain.IdPInfo{
		EntityID:                ed.EntityID,
		DisplayName:             displayName,
		DisplayNames:            displayNames,
		Description:             description,
		Descriptions:            descriptions,
		LogoURL:                 logoURL,
		InformationURL:          informationURL,
		InformationURLs:         informationURLs,
		SSOURL:                  ssoURL,
		SSOBinding:              ssoBinding,
		SLOURL:                  sloURL,
		SLOBinding:              sloBinding,
		Certificates:            certs,
		RegistrationAuthority:   registrationAuthority,
		RegistrationInstant:     registrationInstant,
		RegistrationPolicies:    registrationPolicies,
		AllowedScopes:           allowedScopes,
		EntityCategories:        entityCategories,
		AssuranceCertifications: assuranceCertifications,
	}, nil
}
