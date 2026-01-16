package metadata

import (
	"encoding/xml"

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

// rawEntitiesDescriptor is used to parse UIInfo from aggregate metadata.
type rawEntitiesDescriptor struct {
	EntityDescriptors   []rawEntityDescriptor   `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntitiesDescriptors []rawEntitiesDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
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
