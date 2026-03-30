package metadata

import (
	"encoding/xml"

	"github.com/philiph/caddy-saml-disco/internal/domain"
)

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

// rawEntitiesDescriptorForEntityAttrsAggregate is used to parse EntityAttributes from aggregate metadata.
type rawEntitiesDescriptorForEntityAttrsAggregate struct {
	EntityDescriptors   []rawEntityDescriptorForEntityAttrs            `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntitiesDescriptors []rawEntitiesDescriptorForEntityAttrsAggregate `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
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
