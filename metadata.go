package caddysamldisco

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/crewjam/saml"
)

// IdPInfo contains information about an Identity Provider.
// This is the core domain model - it has no external dependencies.
type IdPInfo struct {
	// EntityID is the unique identifier for this IdP.
	EntityID string

	// DisplayName is a human-readable name for the IdP.
	DisplayName string

	// SSOURL is the Single Sign-On endpoint URL.
	SSOURL string

	// SSOBinding is the SAML binding for the SSO endpoint.
	SSOBinding string

	// Certificates are the IdP's signing certificates (PEM encoded).
	Certificates []string
}

// MetadataStore is the port interface for accessing IdP metadata.
type MetadataStore interface {
	// GetIdP returns information about a specific IdP by entity ID.
	GetIdP(entityID string) (*IdPInfo, error)

	// ListIdPs returns all IdPs, optionally filtered by a search term.
	ListIdPs(filter string) ([]IdPInfo, error)

	// Refresh reloads metadata from the source.
	Refresh(ctx context.Context) error
}

// ErrIdPNotFound is returned when an IdP is not found in the store.
var ErrIdPNotFound = fmt.Errorf("idp not found")

// FileMetadataStore loads IdP metadata from a local file.
// Supports both single EntityDescriptor and aggregate EntitiesDescriptor formats.
type FileMetadataStore struct {
	path string

	mu   sync.RWMutex
	idps []IdPInfo // Supports multiple IdPs from aggregate metadata
}

// NewFileMetadataStore creates a new FileMetadataStore.
func NewFileMetadataStore(path string) *FileMetadataStore {
	return &FileMetadataStore{path: path}
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

// ListIdPs returns all IdPs, optionally filtered by display name or entity ID.
func (s *FileMetadataStore) ListIdPs(filter string) ([]IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.idps) == 0 {
		return nil, nil
	}

	// No filter - return all IdPs
	if filter == "" {
		result := make([]IdPInfo, len(s.idps))
		copy(result, s.idps)
		return result, nil
	}

	// Apply filter
	filter = strings.ToLower(filter)
	var result []IdPInfo
	for _, idp := range s.idps {
		if strings.Contains(strings.ToLower(idp.DisplayName), filter) ||
			strings.Contains(strings.ToLower(idp.EntityID), filter) {
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

	idps, err := parseMetadata(data)
	if err != nil {
		return fmt.Errorf("parse metadata: %w", err)
	}

	s.mu.Lock()
	s.idps = idps
	s.mu.Unlock()

	return nil
}

// parseMetadata parses SAML metadata XML, supporting both single EntityDescriptor
// and aggregate EntitiesDescriptor formats.
func parseMetadata(data []byte) ([]IdPInfo, error) {
	// Try EntitiesDescriptor first (aggregate metadata)
	var entities saml.EntitiesDescriptor
	if err := xml.Unmarshal(data, &entities); err == nil && len(entities.EntityDescriptors) > 0 {
		return parseEntitiesDescriptor(&entities)
	}

	// Fall back to single EntityDescriptor
	idp, err := parseEntityDescriptor(data)
	if err != nil {
		return nil, err
	}
	return []IdPInfo{*idp}, nil
}

// parseEntitiesDescriptor extracts all IdPs from an aggregate metadata document.
// It skips entities without IDPSSODescriptor (e.g., SP metadata).
func parseEntitiesDescriptor(entities *saml.EntitiesDescriptor) ([]IdPInfo, error) {
	var idps []IdPInfo

	// Process direct EntityDescriptor children
	for i := range entities.EntityDescriptors {
		idp, err := extractIdPInfo(&entities.EntityDescriptors[i])
		if err != nil {
			// Skip entities without IDPSSODescriptor (SPs, etc.)
			continue
		}
		idps = append(idps, *idp)
	}

	// Process nested EntitiesDescriptor elements (recursive)
	for i := range entities.EntitiesDescriptors {
		nestedIdps, err := parseEntitiesDescriptor(&entities.EntitiesDescriptors[i])
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

// extractIdPInfo extracts IdPInfo from a single EntityDescriptor.
func extractIdPInfo(ed *saml.EntityDescriptor) (*IdPInfo, error) {
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

	// Extract display name from Organization or fall back to EntityID
	displayName := ed.EntityID
	if ed.Organization != nil && len(ed.Organization.OrganizationDisplayNames) > 0 {
		displayName = ed.Organization.OrganizationDisplayNames[0].Value
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

	return &IdPInfo{
		EntityID:     ed.EntityID,
		DisplayName:  displayName,
		SSOURL:       ssoURL,
		SSOBinding:   ssoBinding,
		Certificates: certs,
	}, nil
}

// parseEntityDescriptor extracts IdPInfo from a single EntityDescriptor XML.
func parseEntityDescriptor(data []byte) (*IdPInfo, error) {
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(data, &ed); err != nil {
		return nil, fmt.Errorf("unmarshal xml: %w", err)
	}

	return extractIdPInfo(&ed)
}
