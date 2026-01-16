package metadata

import (
	"encoding/xml"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

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
