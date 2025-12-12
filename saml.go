package caddysamldisco

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

// SAMLService provides SAML Service Provider operations.
type SAMLService struct {
	entityID     string
	privateKey   *rsa.PrivateKey
	certificate  *x509.Certificate
	requestCache *MemoryRequestIDCache
}

// AuthResult contains the result of processing a SAML assertion.
type AuthResult struct {
	Subject     string
	Attributes  map[string]string
	IdPEntityID string
}

// NewSAMLService creates a new SAML service with the given configuration.
func NewSAMLService(entityID string, privateKey *rsa.PrivateKey, certificate *x509.Certificate) *SAMLService {
	return &SAMLService{
		entityID:     entityID,
		privateKey:   privateKey,
		certificate:  certificate,
		requestCache: NewMemoryRequestIDCache(),
	}
}

// MemoryRequestIDCache stores pending SAML request IDs for replay protection.
// Request IDs are single-use and expire after a configured duration.
type MemoryRequestIDCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// NewMemoryRequestIDCache creates a new in-memory request ID cache.
func NewMemoryRequestIDCache() *MemoryRequestIDCache {
	return &MemoryRequestIDCache{
		entries: make(map[string]time.Time),
	}
}

// Store adds a request ID with the given expiry time.
func (c *MemoryRequestIDCache) Store(requestID string, expiry time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[requestID] = expiry
	return nil
}

// Valid checks if a request ID exists and is not expired.
// If valid, the ID is removed (single-use) and returns true.
// Returns false for unknown or expired IDs.
func (c *MemoryRequestIDCache) Valid(requestID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiry, exists := c.entries[requestID]
	if !exists {
		return false
	}

	// Check expiry
	if time.Now().After(expiry) {
		delete(c.entries, requestID)
		return false
	}

	// Single-use: remove after validation
	delete(c.entries, requestID)
	return true
}

// GetAll returns all non-expired request IDs.
// This is used for SAML response validation where we need all possible IDs.
func (c *MemoryRequestIDCache) GetAll() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var ids []string

	for id, expiry := range c.entries {
		if now.Before(expiry) {
			ids = append(ids, id)
		}
	}

	return ids
}

// GenerateSPMetadata creates SP metadata XML for the given ACS URL.
func (s *SAMLService) GenerateSPMetadata(acsURL *url.URL) ([]byte, error) {
	sp := s.buildServiceProvider(acsURL)
	metadata := sp.Metadata()
	return xml.MarshalIndent(metadata, "", "  ")
}

// buildServiceProvider creates a crewjam/saml.ServiceProvider for SP operations.
func (s *SAMLService) buildServiceProvider(acsURL *url.URL) *saml.ServiceProvider {
	metadataURL := url.URL{
		Scheme: acsURL.Scheme,
		Host:   acsURL.Host,
		Path:   "/saml/metadata",
	}

	return &saml.ServiceProvider{
		EntityID:    s.entityID,
		Key:         s.privateKey,
		Certificate: s.certificate,
		MetadataURL: metadataURL,
		AcsURL:      *acsURL,
	}
}

// StartAuth generates an AuthnRequest redirect URL for the given IdP.
// The relayState parameter is optional and will be included in the redirect URL.
func (s *SAMLService) StartAuth(idp *IdPInfo, acsURL *url.URL, relayState string) (*url.URL, error) {
	sp := s.buildServiceProvider(acsURL)

	// Configure IdP metadata
	idpMetadata, err := idpInfoToEntityDescriptor(idp)
	if err != nil {
		return nil, err
	}
	sp.IDPMetadata = idpMetadata

	// Generate AuthnRequest and redirect URL
	authReq, err := sp.MakeAuthenticationRequest(idp.SSOURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return nil, err
	}

	// Store request ID for later validation (10 minute expiry)
	s.requestCache.Store(authReq.ID, time.Now().Add(10*time.Minute))

	// Build redirect URL
	redirectURL, err := authReq.Redirect(relayState, sp)
	if err != nil {
		return nil, err
	}

	return redirectURL, nil
}

// idpInfoToEntityDescriptor converts our IdPInfo to saml.EntityDescriptor.
func idpInfoToEntityDescriptor(idp *IdPInfo) (*saml.EntityDescriptor, error) {
	ed := &saml.EntityDescriptor{
		EntityID: idp.EntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SingleSignOnServices: []saml.Endpoint{{
				Binding:  idp.SSOBinding,
				Location: idp.SSOURL,
			}},
		}},
	}

	// Add certificates
	for _, certData := range idp.Certificates {
		ed.IDPSSODescriptors[0].KeyDescriptors = append(
			ed.IDPSSODescriptors[0].KeyDescriptors,
			saml.KeyDescriptor{
				Use: "signing",
				KeyInfo: saml.KeyInfo{
					X509Data: saml.X509Data{
						X509Certificates: []saml.X509Certificate{{Data: certData}},
					},
				},
			},
		)
	}

	return ed, nil
}

// HandleACS processes a SAML Response from the IdP.
// Returns the authentication result with user information or an error.
func (s *SAMLService) HandleACS(r *http.Request, acsURL *url.URL, idp *IdPInfo) (*AuthResult, error) {
	sp := s.buildServiceProvider(acsURL)

	// Configure IdP metadata
	idpMetadata, err := idpInfoToEntityDescriptor(idp)
	if err != nil {
		return nil, fmt.Errorf("build idp metadata: %w", err)
	}
	sp.IDPMetadata = idpMetadata

	// Get all valid request IDs for validation
	possibleRequestIDs := s.requestCache.GetAll()

	// Parse and validate the SAML response
	assertion, err := sp.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		return nil, fmt.Errorf("parse saml response: %w", err)
	}

	// Extract subject (user identifier)
	subject := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		subject = assertion.Subject.NameID.Value
	}

	// Extract attributes
	attrs := make(map[string]string)
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) > 0 {
				// Use FriendlyName if available, otherwise use Name
				key := attr.FriendlyName
				if key == "" {
					key = attr.Name
				}
				attrs[key] = attr.Values[0].Value
			}
		}
	}

	// Consume the request ID (mark as used)
	// The InResponseTo field links back to our original AuthnRequest
	if assertion.Subject != nil {
		for _, sc := range assertion.Subject.SubjectConfirmations {
			if sc.SubjectConfirmationData != nil && sc.SubjectConfirmationData.InResponseTo != "" {
				s.requestCache.Valid(sc.SubjectConfirmationData.InResponseTo)
			}
		}
	}

	return &AuthResult{
		Subject:     subject,
		Attributes:  attrs,
		IdPEntityID: idp.EntityID,
	}, nil
}
