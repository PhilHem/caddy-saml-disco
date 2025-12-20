package metadata

import (
	"encoding/xml"
	"fmt"
	"time"

	"github.com/crewjam/saml"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// rawEntityDescriptor is used to parse UIInfo from raw XML.
type rawEntityDescriptor struct {
	EntityID          string `xml:"entityID,attr"`
	IDPSSODescriptors []struct {
		Extensions struct {
			UIInfo *domain.UIInfo `xml:"urn:oasis:names:tc:SAML:metadata:ui UIInfo"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
}

// rawEntityDescriptorForScope is used to parse shibmd:Scope from raw XML.
// Scope is at IDPSSODescriptor/Extensions level.
type rawEntityDescriptorForScope struct {
	EntityID          string `xml:"entityID,attr"`
	IDPSSODescriptors []struct {
		Extensions struct {
			Scopes []struct {
				Value  string `xml:",chardata"`
				Regexp bool   `xml:"regexp,attr"`
			} `xml:"urn:mace:shibboleth:metadata:1.0 Scope"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
}

// rawEntitiesDescriptor is used to parse UIInfo from aggregate metadata.
type rawEntitiesDescriptor struct {
	EntityDescriptors   []rawEntityDescriptor   `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntitiesDescriptors []rawEntitiesDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
}

// rawEntitiesDescriptorForScope is used to parse shibmd:Scope from aggregate metadata.
type rawEntitiesDescriptorForScope struct {
	EntityDescriptors   []rawEntityDescriptorForScope   `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntitiesDescriptors []rawEntitiesDescriptorForScope `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
}

// rawEntityDescriptorForRegInfo is used to parse RegistrationInfo from raw XML.
// RegistrationInfo is at EntityDescriptor/Extensions level (not IDPSSODescriptor).
type rawEntityDescriptorForRegInfo struct {
	EntityID   string `xml:"entityID,attr"`
	Extensions struct {
		RegistrationInfo *domain.RegistrationInfo `xml:"urn:oasis:names:tc:SAML:metadata:rpi RegistrationInfo"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions"`
}

// rawEntitiesDescriptorForRegInfo is used to parse RegistrationInfo from aggregate metadata.
type rawEntitiesDescriptorForRegInfo struct {
	EntityDescriptors   []rawEntityDescriptorForRegInfo   `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntitiesDescriptors []rawEntitiesDescriptorForRegInfo `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
}

// rawEntityAttributes represents the EntityAttributes XML structure.
type rawEntityAttributes struct {
	Attributes []struct {
		Name   string   `xml:"Name,attr"`
		Values []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// rawEntityDescriptorForEntityAttrs is used to parse EntityAttributes from raw XML.
// EntityAttributes is at EntityDescriptor/Extensions level (not IDPSSODescriptor).
type rawEntityDescriptorForEntityAttrs struct {
	EntityID   string `xml:"entityID,attr"`
	Extensions struct {
		EntityAttributes rawEntityAttributes `xml:"urn:oasis:names:tc:SAML:metadata:attribute EntityAttributes"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions"`
}

// rawEntitiesDescriptorForEntityAttrs is used to parse EntityAttributes from aggregate metadata.
type rawEntitiesDescriptorForEntityAttrsAggregate struct {
	EntityDescriptors   []rawEntityDescriptorForEntityAttrs   `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntitiesDescriptors []rawEntitiesDescriptorForEntityAttrsAggregate `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
}

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

// parseAllUIInfo extracts UIInfo for all entities from raw XML.
func parseAllUIInfo(data []byte) map[string]*domain.UIInfo {
	result := make(map[string]*domain.UIInfo)

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
func extractUIInfoFromEntities(entities *rawEntitiesDescriptor, result map[string]*domain.UIInfo) {
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
func parseAllRegistrationInfo(data []byte) map[string]*domain.RegistrationInfo {
	result := make(map[string]*domain.RegistrationInfo)

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
func extractRegInfoFromEntities(entities *rawEntitiesDescriptorForRegInfo, result map[string]*domain.RegistrationInfo) {
	for _, ed := range entities.EntityDescriptors {
		if ed.Extensions.RegistrationInfo != nil {
			result[ed.EntityID] = ed.Extensions.RegistrationInfo
		}
	}
	for i := range entities.EntitiesDescriptors {
		extractRegInfoFromEntities(&entities.EntitiesDescriptors[i], result)
	}
}

// parseAllScopes extracts shibmd:Scope for all entities from raw XML.
func parseAllScopes(data []byte) map[string][]domain.ScopeInfo {
	result := make(map[string][]domain.ScopeInfo)

	// Try parsing as EntitiesDescriptor (aggregate)
	var entities rawEntitiesDescriptorForScope
	if err := xml.Unmarshal(data, &entities); err == nil {
		extractScopesFromEntities(&entities, result)
		if len(result) > 0 {
			return result
		}
	}

	// Try parsing as single EntityDescriptor
	var entity rawEntityDescriptorForScope
	if err := xml.Unmarshal(data, &entity); err == nil {
		if len(entity.IDPSSODescriptors) > 0 && len(entity.IDPSSODescriptors[0].Extensions.Scopes) > 0 {
			scopes := make([]domain.ScopeInfo, len(entity.IDPSSODescriptors[0].Extensions.Scopes))
			for i, s := range entity.IDPSSODescriptors[0].Extensions.Scopes {
				scopes[i] = domain.ScopeInfo{
					Value:  s.Value,
					Regexp: s.Regexp,
				}
			}
			result[entity.EntityID] = scopes
		}
	}

	return result
}

// extractScopesFromEntities recursively extracts scopes from EntitiesDescriptor.
func extractScopesFromEntities(entities *rawEntitiesDescriptorForScope, result map[string][]domain.ScopeInfo) {
	for _, ed := range entities.EntityDescriptors {
		if len(ed.IDPSSODescriptors) > 0 && len(ed.IDPSSODescriptors[0].Extensions.Scopes) > 0 {
			scopes := make([]domain.ScopeInfo, len(ed.IDPSSODescriptors[0].Extensions.Scopes))
			for i, s := range ed.IDPSSODescriptors[0].Extensions.Scopes {
				scopes[i] = domain.ScopeInfo{
					Value:  s.Value,
					Regexp: s.Regexp,
				}
			}
			result[ed.EntityID] = scopes
		}
	}
	for i := range entities.EntitiesDescriptors {
		extractScopesFromEntities(&entities.EntitiesDescriptors[i], result)
	}
}

// parseAllEntityAttributes extracts EntityAttributes for all entities from raw XML.
func parseAllEntityAttributes(data []byte) map[string]*domain.EntityAttributesInfo {
	result := make(map[string]*domain.EntityAttributesInfo)

	// Try parsing as EntitiesDescriptor (aggregate)
	var entities rawEntitiesDescriptorForEntityAttrsAggregate
	if err := xml.Unmarshal(data, &entities); err == nil {
		extractEntityAttrsFromEntities(&entities, result)
		if len(result) > 0 {
			return result
		}
	}

	// Try parsing as single EntityDescriptor
	var entity rawEntityDescriptorForEntityAttrs
	if err := xml.Unmarshal(data, &entity); err == nil {
		attrs := parseEntityAttributes(&entity.Extensions.EntityAttributes)
		if attrs != nil {
			result[entity.EntityID] = attrs
		}
	}

	return result
}

// extractEntityAttrsFromEntities recursively extracts EntityAttributes from EntitiesDescriptor.
func extractEntityAttrsFromEntities(entities *rawEntitiesDescriptorForEntityAttrsAggregate, result map[string]*domain.EntityAttributesInfo) {
	for _, ed := range entities.EntityDescriptors {
		attrs := parseEntityAttributes(&ed.Extensions.EntityAttributes)
		if attrs != nil {
			result[ed.EntityID] = attrs
		}
	}
	for i := range entities.EntitiesDescriptors {
		extractEntityAttrsFromEntities(&entities.EntitiesDescriptors[i], result)
	}
}

// parseEntityAttributes parses EntityAttributes XML into domain.EntityAttributesInfo.
// Extracts entity categories and assurance certifications based on Attribute Name.
func parseEntityAttributes(xmlAttrs *rawEntityAttributes) *domain.EntityAttributesInfo {
	if xmlAttrs == nil || len(xmlAttrs.Attributes) == 0 {
		return nil
	}

	var entityCategories []string
	var assuranceCerts []string

	entityCategoryName := "http://macedir.org/entity-category"
	assuranceCertName := "urn:oasis:names:tc:SAML:attribute:assurance-certification"

	for _, attr := range xmlAttrs.Attributes {
		if attr.Name == entityCategoryName {
			entityCategories = append(entityCategories, attr.Values...)
		} else if attr.Name == assuranceCertName {
			assuranceCerts = append(assuranceCerts, attr.Values...)
		}
	}

	if len(entityCategories) == 0 && len(assuranceCerts) == 0 {
		return nil
	}

	return &domain.EntityAttributesInfo{
		EntityCategories:        entityCategories,
		AssuranceCertifications: assuranceCerts,
	}
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
		EntityID:               ed.EntityID,
		DisplayName:            displayName,
		DisplayNames:           displayNames,
		Description:            description,
		Descriptions:           descriptions,
		LogoURL:                logoURL,
		InformationURL:         informationURL,
		InformationURLs:        informationURLs,
		SSOURL:                 ssoURL,
		SSOBinding:             ssoBinding,
		SLOURL:                 sloURL,
		SLOBinding:             sloBinding,
		Certificates:           certs,
		RegistrationAuthority:  registrationAuthority,
		RegistrationInstant:    registrationInstant,
		RegistrationPolicies:   registrationPolicies,
		AllowedScopes:          allowedScopes,
		EntityCategories:       entityCategories,
		AssuranceCertifications: assuranceCertifications,
	}, nil
}






