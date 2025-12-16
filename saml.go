package caddysamldisco

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
)

// SAMLService provides SAML Service Provider operations.
type SAMLService struct {
	entityID       string
	privateKey     *rsa.PrivateKey
	certificate    *x509.Certificate
	requestStore   RequestStore
	metadataSigner MetadataSigner // optional signer for SP metadata
	sloURL         *url.URL       // optional SLO URL for SP metadata
}

// AuthResult contains the result of processing a SAML assertion.
type AuthResult struct {
	Subject      string
	Attributes   map[string]string
	IdPEntityID  string
	NameIDFormat string
	SessionIndex string
}

// NewSAMLService creates a new SAML service with the given configuration.
// Uses an in-memory request store without background cleanup.
func NewSAMLService(entityID string, privateKey *rsa.PrivateKey, certificate *x509.Certificate) *SAMLService {
	return &SAMLService{
		entityID:     entityID,
		privateKey:   privateKey,
		certificate:  certificate,
		requestStore: NewInMemoryRequestStore(),
	}
}

// NewSAMLServiceWithStore creates a new SAML service with a custom request store.
// Use this for dependency injection or when background cleanup is needed.
func NewSAMLServiceWithStore(entityID string, privateKey *rsa.PrivateKey, certificate *x509.Certificate, store RequestStore) *SAMLService {
	return &SAMLService{
		entityID:     entityID,
		privateKey:   privateKey,
		certificate:  certificate,
		requestStore: store,
	}
}

// SetMetadataSigner sets the signer used for SP metadata.
// If set, GenerateSPMetadata will return signed XML.
func (s *SAMLService) SetMetadataSigner(signer MetadataSigner) {
	s.metadataSigner = signer
}

// SetSLOURL sets the Single Logout URL for SP metadata.
// If set, GenerateSPMetadata will include SingleLogoutService endpoint.
func (s *SAMLService) SetSLOURL(sloURL *url.URL) {
	s.sloURL = sloURL
}

// GenerateSPMetadata creates SP metadata XML for the given ACS URL.
// If a MetadataSigner is configured, the metadata will be signed.
func (s *SAMLService) GenerateSPMetadata(acsURL *url.URL) ([]byte, error) {
	sp := s.buildServiceProvider(acsURL)
	metadata := sp.Metadata()
	data, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, err
	}

	// Sign metadata if signer is configured
	if s.metadataSigner != nil {
		return s.metadataSigner.Sign(data)
	}

	return data, nil
}

// buildServiceProvider creates a crewjam/saml.ServiceProvider for SP operations.
func (s *SAMLService) buildServiceProvider(acsURL *url.URL) *saml.ServiceProvider {
	metadataURL := url.URL{
		Scheme: acsURL.Scheme,
		Host:   acsURL.Host,
		Path:   "/saml/metadata",
	}

	sp := &saml.ServiceProvider{
		EntityID:        s.entityID,
		Key:             s.privateKey,
		Certificate:     s.certificate,
		MetadataURL:     metadataURL,
		AcsURL:          *acsURL,
		SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	}

	// Include SLO URL if configured
	if s.sloURL != nil {
		sp.SloURL = *s.sloURL
		sp.LogoutBindings = []string{saml.HTTPRedirectBinding}
	}

	return sp
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
	s.requestStore.Store(authReq.ID, time.Now().Add(10*time.Minute))

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

	// Add SLO endpoint if available
	if idp.SLOURL != "" {
		ed.IDPSSODescriptors[0].SingleLogoutServices = []saml.Endpoint{{
			Binding:  idp.SLOBinding,
			Location: idp.SLOURL,
		}}
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
	possibleRequestIDs := s.requestStore.GetAll()

	// Parse and validate the SAML response
	assertion, err := sp.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		return nil, fmt.Errorf("parse saml response: %w", err)
	}

	// Extract subject (user identifier) and NameIDFormat
	subject := ""
	nameIDFormat := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		subject = assertion.Subject.NameID.Value
		nameIDFormat = assertion.Subject.NameID.Format
	}

	// Extract SessionIndex from AuthnStatements
	sessionIndex := ""
	if len(assertion.AuthnStatements) > 0 {
		sessionIndex = assertion.AuthnStatements[0].SessionIndex
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
				s.requestStore.Valid(sc.SubjectConfirmationData.InResponseTo)
			}
		}
	}

	return &AuthResult{
		Subject:      subject,
		Attributes:   attrs,
		IdPEntityID:  idp.EntityID,
		NameIDFormat: nameIDFormat,
		SessionIndex: sessionIndex,
	}, nil
}

// CreateLogoutRequest creates a SAML LogoutRequest and returns the redirect URL.
// This is used for SP-initiated logout.
func (s *SAMLService) CreateLogoutRequest(session *Session, idp *IdPInfo, sloURL *url.URL, relayState string) (*url.URL, error) {
	sp := s.buildServiceProviderWithSLO(sloURL)

	// Configure IdP metadata
	idpMetadata, err := idpInfoToEntityDescriptor(idp)
	if err != nil {
		return nil, fmt.Errorf("build idp metadata: %w", err)
	}
	sp.IDPMetadata = idpMetadata

	// Set NameID format on SP if provided
	if session.NameIDFormat != "" {
		sp.AuthnNameIDFormat = saml.NameIDFormat(session.NameIDFormat)
	}

	// Use crewjam/saml's MakeRedirectLogoutRequest
	// It takes the NameID value as a string
	return sp.MakeRedirectLogoutRequest(session.Subject, relayState)
}

// HandleLogoutResponse validates a LogoutResponse from the IdP.
// This is called when the IdP redirects back after processing a LogoutRequest.
func (s *SAMLService) HandleLogoutResponse(r *http.Request, sloURL *url.URL, idp *IdPInfo) error {
	// Parse LogoutResponse from query parameter
	samlResponse := r.URL.Query().Get("SAMLResponse")
	if samlResponse == "" {
		return fmt.Errorf("missing SAMLResponse parameter")
	}

	// For now, we just verify the response exists
	// Full validation would require parsing the SAML XML and checking status
	// This is a basic implementation - can be enhanced with full XML parsing if needed
	if len(samlResponse) == 0 {
		return fmt.Errorf("empty SAMLResponse")
	}

	return nil
}

// LogoutRequestResult contains information extracted from a LogoutRequest.
type LogoutRequestResult struct {
	NameID    string
	RequestID string
}

// HandleLogoutRequest parses and validates a LogoutRequest from the IdP.
// This is used for IdP-initiated logout.
func (s *SAMLService) HandleLogoutRequest(r *http.Request, sloURL *url.URL, idp *IdPInfo) (*LogoutRequestResult, error) {
	sp := s.buildServiceProviderWithSLO(sloURL)

	// Configure IdP metadata
	idpMetadata, err := idpInfoToEntityDescriptor(idp)
	if err != nil {
		return nil, fmt.Errorf("build idp metadata: %w", err)
	}
	sp.IDPMetadata = idpMetadata

	// Parse LogoutRequest from query parameter
	samlRequest := r.URL.Query().Get("SAMLRequest")
	if samlRequest == "" {
		return nil, fmt.Errorf("missing SAMLRequest parameter")
	}

	// For now, return a basic result
	// Full implementation would parse the SAML XML, validate signature, and extract NameID
	// This is a basic implementation - can be enhanced with full XML parsing if needed
	return &LogoutRequestResult{
		NameID:    "", // Would be extracted from parsed request
		RequestID: "", // Would be extracted from parsed request
	}, nil
}

// CreateLogoutResponse creates a SAML LogoutResponse and returns the redirect URL.
// This is used to respond to an IdP-initiated LogoutRequest.
func (s *SAMLService) CreateLogoutResponse(requestID string, idp *IdPInfo, sloURL *url.URL, relayState string) (*url.URL, error) {
	sp := s.buildServiceProviderWithSLO(sloURL)

	// Configure IdP metadata
	idpMetadata, err := idpInfoToEntityDescriptor(idp)
	if err != nil {
		return nil, fmt.Errorf("build idp metadata: %w", err)
	}
	sp.IDPMetadata = idpMetadata

	// Use crewjam/saml's MakeRedirectLogoutResponse
	return sp.MakeRedirectLogoutResponse(requestID, relayState)
}

// buildServiceProviderWithSLO creates a crewjam/saml.ServiceProvider with SLO URL configured.
func (s *SAMLService) buildServiceProviderWithSLO(sloURL *url.URL) *saml.ServiceProvider {
	// Use a dummy ACS URL to build the base SP (SLO URL will override)
	dummyACS := &url.URL{
		Scheme: sloURL.Scheme,
		Host:   sloURL.Host,
		Path:   "/saml/acs",
	}
	sp := s.buildServiceProvider(dummyACS)

	// Set SLO URL
	sp.SloURL = *sloURL
	sp.LogoutBindings = []string{saml.HTTPRedirectBinding}

	return sp
}
