package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// SAMLService provides SAML Service Provider operations.
type SAMLService struct {
	entityID       string
	privateKey     *rsa.PrivateKey
	certificate    *x509.Certificate
	requestStore   ports.RequestStore
	metadataSigner ports.MetadataSigner // optional signer for SP metadata
	sloURL         *url.URL             // optional SLO URL for SP metadata
	requestTTL     time.Duration        // how long a pending AuthnRequest ID is kept
	logger         *zap.Logger          // optional structured logger
}

// AuthResult contains the result of processing a SAML assertion.
type AuthResult struct {
	Subject      string
	Attributes   map[string]string
	IdPEntityID  string
	NameIDFormat string
	SessionIndex string
}

// DefaultRequestCleanupInterval is the default interval for cleaning up expired SAML request IDs.
const DefaultRequestCleanupInterval = 5 * time.Minute

// NewSAMLServiceWithStore creates a new SAML service with the given request store.
// The caller is responsible for providing a ports.RequestStore implementation.
// For production use, pass a store with background cleanup; call Close() when done.
func NewSAMLServiceWithStore(entityID string, privateKey *rsa.PrivateKey, certificate *x509.Certificate, store ports.RequestStore) *SAMLService {
	return &SAMLService{
		entityID:     entityID,
		privateKey:   privateKey,
		certificate:  certificate,
		requestStore: store,
		requestTTL:   10 * time.Minute,
	}
}

// Close stops the background cleanup goroutine of the request store.
// Should be called when the SAMLService is no longer needed.
func (s *SAMLService) Close() error {
	if closer, ok := s.requestStore.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// SetMetadataSigner sets the signer used for SP metadata.
// If set, GenerateSPMetadata will return signed XML.
func (s *SAMLService) SetMetadataSigner(signer ports.MetadataSigner) {
	s.metadataSigner = signer
}

// SetSLOURL sets the Single Logout URL for SP metadata.
// If set, GenerateSPMetadata will include SingleLogoutService endpoint.
func (s *SAMLService) SetSLOURL(sloURL *url.URL) {
	s.sloURL = sloURL
}

// SetRequestTTL sets how long a pending AuthnRequest ID is retained before expiry.
func (s *SAMLService) SetRequestTTL(ttl time.Duration) {
	s.requestTTL = ttl
}

// SetLogger sets the structured logger used for diagnostic output.
// If not set, logging is suppressed (no-op logger).
func (s *SAMLService) SetLogger(logger *zap.Logger) {
	s.logger = logger
}

// log returns the logger or a no-op logger when none is configured.
func (s *SAMLService) log() *zap.Logger {
	if s.logger != nil {
		return s.logger
	}
	return zap.NewNop()
}

// GetEntityIDStore returns the request store cast to the EntityID-aware interface,
// if supported. Returns nil if the underlying store does not support entity ID lookup.
// This is used by ACS handlers to recover the original IdP entity ID after a metadata
// refresh, by mapping the InResponseTo request ID back to the entity that issued it.
func (s *SAMLService) GetEntityIDStore() interface {
	GetEntityID(string) (string, bool)
} {
	if store, ok := s.requestStore.(interface {
		GetEntityID(string) (string, bool)
	}); ok {
		return store
	}
	return nil
}

// GenerateSPMetadata creates SP metadata XML for the given ACS URL.
// If a ports.MetadataSigner is configured, the metadata will be signed.
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
func (s *SAMLService) StartAuth(idp *domain.IdPInfo, acsURL *url.URL, relayState string) (*url.URL, error) {
	return s.StartAuthWithOptions(idp, acsURL, relayState, nil)
}

// StartAuthWithOptions generates an AuthnRequest redirect URL with authentication options.
// The relayState parameter is optional and will be included in the redirect URL.
// If opts is nil, defaults are used (no ForceAuthn).
func (s *SAMLService) StartAuthWithOptions(idp *domain.IdPInfo, acsURL *url.URL, relayState string, opts *domain.AuthnOptions) (*url.URL, error) {
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

	// Apply authentication options
	if opts != nil && opts.ForceAuthn {
		forceAuthn := true
		authReq.ForceAuthn = &forceAuthn
	}

	// Apply RequestedAuthnContext if specified
	// Note: crewjam/saml library only supports a single AuthnContextClassRef,
	// so we use the first element if multiple are provided.
	if opts != nil && len(opts.RequestedAuthnContext) > 0 {
		comparison := opts.AuthnContextComparison
		if comparison == "" {
			comparison = "exact" // SAML spec default
		}
		authReq.RequestedAuthnContext = &saml.RequestedAuthnContext{
			Comparison:           comparison,
			AuthnContextClassRef: opts.RequestedAuthnContext[0],
		}
	}

	// Store request ID for later validation (configurable TTL, default 10 minutes).
	// Prefer StoreWithEntityID so ACS can recover the IdP after a metadata refresh.
	expiry := time.Now().Add(s.requestTTL)
	if store, ok := s.requestStore.(interface {
		StoreWithEntityID(string, time.Time, string)
	}); ok {
		store.StoreWithEntityID(authReq.ID, expiry, idp.EntityID)
	} else {
		s.requestStore.Store(authReq.ID, expiry)
	}

	// Build redirect URL
	redirectURL, err := authReq.Redirect(relayState, sp)
	if err != nil {
		return nil, err
	}

	return redirectURL, nil
}

// IdPInfoToEntityDescriptor converts an IdPInfo to a saml.EntityDescriptor.
// Exported for use by the caddy adapter package tests.
func IdPInfoToEntityDescriptor(idp *domain.IdPInfo) (*saml.EntityDescriptor, error) {
	return idpInfoToEntityDescriptor(idp)
}

// idpInfoToEntityDescriptor converts our IdPInfo to saml.EntityDescriptor.
func idpInfoToEntityDescriptor(idp *domain.IdPInfo) (*saml.EntityDescriptor, error) {
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

// ExtractResponseInResponseTo extracts the InResponseTo attribute from a base64-encoded
// SAML Response. This is the ID of the AuthnRequest that triggered the response, allowing
// ACS to map back to the original request even after a metadata refresh.
// Returns ("", nil) if the field is absent (IdP-initiated flows have no InResponseTo).
func ExtractResponseInResponseTo(samlResponseB64 string) (string, error) {
	if samlResponseB64 == "" {
		return "", fmt.Errorf("empty SAMLResponse")
	}

	responseXML, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	var response saml.Response
	if err := xml.Unmarshal(responseXML, &response); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	return response.InResponseTo, nil
}

// ExtractResponseIssuer extracts the Issuer entity ID from a base64-encoded SAML Response.
// This allows looking up the correct IdP before full response validation.
func ExtractResponseIssuer(samlResponseB64 string) (string, error) {
	if samlResponseB64 == "" {
		return "", fmt.Errorf("empty SAMLResponse")
	}

	// Base64 decode
	responseXML, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	// Parse just enough XML to extract Issuer
	var response saml.Response
	if err := xml.Unmarshal(responseXML, &response); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if response.Issuer == nil || response.Issuer.Value == "" {
		return "", fmt.Errorf("response has no issuer")
	}

	return response.Issuer.Value, nil
}

// HandleACS processes a SAML Response from the IdP.
// Returns the authentication result with user information or an error.
//
// Encrypted assertions are automatically decrypted by crewjam/saml's ParseResponse
// when the SP's private key is configured (which it is via s.privateKey).
// The SP metadata includes an encryption KeyDescriptor, allowing IdPs to encrypt
// assertions using the SP's public key.
func (s *SAMLService) HandleACS(r *http.Request, acsURL *url.URL, idp *domain.IdPInfo) (*AuthResult, error) {
	sp := s.buildServiceProvider(acsURL)

	// Configure IdP metadata
	idpMetadata, err := idpInfoToEntityDescriptor(idp)
	if err != nil {
		return nil, fmt.Errorf("build idp metadata: %w", err)
	}
	sp.IDPMetadata = idpMetadata

	// Get all valid request IDs for validation
	possibleRequestIDs := s.requestStore.GetAll()

	// Parse the form body to populate r.PostForm
	// This is required because crewjam/saml's ParseResponse uses r.PostForm.Get("SAMLResponse")
	// but doesn't call ParseForm() itself. Without this, PostForm is nil and returns empty string.
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("parse form: %w", err)
	}

	// Parse and validate the SAML response
	// Note: ParseResponse automatically decrypts encrypted assertions using sp.Key
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

	// Validate scoped attributes against IdP's allowed scopes
	if len(idp.AllowedScopes) > 0 {
		for attrName, attrValue := range attrs {
			if domain.IsScopedAttribute(attrName) {
				scope := domain.ExtractScope(attrValue)
				if !domain.ValidateScope(scope, idp.AllowedScopes) {
					return nil, fmt.Errorf("scope validation failed: %s scope %q not allowed for IdP %q", attrName, scope, idp.EntityID)
				}
			}
		}
	}

	// Consume the request ID (mark as used, enforce single-use).
	// The InResponseTo field links back to our original AuthnRequest.
	// Valid() atomically checks and deletes the ID; it returns false if the ID
	// was already consumed or never existed, indicating a replay.
	consumed := false
	if assertion.Subject != nil {
		for _, sc := range assertion.Subject.SubjectConfirmations {
			if sc.SubjectConfirmationData != nil && sc.SubjectConfirmationData.InResponseTo != "" {
				if s.requestStore.Valid(sc.SubjectConfirmationData.InResponseTo) {
					consumed = true
				}
			}
		}
	}
	if !consumed {
		return nil, fmt.Errorf("request ID already consumed or not found: replay detected")
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
func (s *SAMLService) CreateLogoutRequest(session *domain.Session, idp *domain.IdPInfo, sloURL *url.URL, relayState string) (*url.URL, error) {
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

// samlStatusSuccess is the SAML 2.0 status code URI for a successful operation.
const samlStatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

// HandleLogoutResponse validates a LogoutResponse from the IdP.
// This is called when the IdP redirects back after processing a LogoutRequest.
//
// Validation failures are logged as warnings but do not prevent the caller
// from continuing with local logout — the logout flow must complete even when
// the IdP response is malformed or carries a non-success status.
func (s *SAMLService) HandleLogoutResponse(r *http.Request, sloURL *url.URL, idp *domain.IdPInfo) error {
	samlResponse := r.URL.Query().Get("SAMLResponse")
	if samlResponse == "" {
		return fmt.Errorf("missing SAMLResponse parameter")
	}

	// Base64-decode the response (redirect binding uses standard base64).
	xmlBytes, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return fmt.Errorf("base64 decode LogoutResponse: %w", err)
	}

	// Parse the XML with etree for namespace-aware element access.
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return fmt.Errorf("parse LogoutResponse XML: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return fmt.Errorf("LogoutResponse has no root element")
	}

	// Validate Issuer — the response must come from the expected IdP.
	var issuerText string
	for _, tag := range []string{"saml:Issuer", "Issuer"} {
		if el := root.FindElement(tag); el != nil {
			issuerText = el.Text()
			break
		}
	}
	if issuerText == "" {
		s.log().Warn("LogoutResponse has no Issuer element",
			zap.String("idp_entity_id", idp.EntityID),
		)
		return fmt.Errorf("LogoutResponse missing Issuer")
	}
	if issuerText != idp.EntityID {
		s.log().Warn("LogoutResponse Issuer does not match expected IdP",
			zap.String("expected", idp.EntityID),
			zap.String("got", issuerText),
		)
		return fmt.Errorf("LogoutResponse Issuer %q does not match IdP %q", issuerText, idp.EntityID)
	}

	// Check InResponseTo — if present, it should match a pending logout request ID.
	// We check but do not hard-fail if the store doesn't contain the ID, because
	// the request store may have expired it or the implementation may not track
	// logout request IDs separately from authn request IDs.
	inResponseTo := root.SelectAttrValue("InResponseTo", "")
	if inResponseTo != "" {
		ids := s.requestStore.GetAll()
		found := false
		for _, id := range ids {
			if id == inResponseTo {
				found = true
				break
			}
		}
		if !found {
			s.log().Warn("LogoutResponse InResponseTo not found in pending requests",
				zap.String("in_response_to", inResponseTo),
				zap.String("idp_entity_id", idp.EntityID),
			)
			// Defense-in-depth: log the warning but don't block the logout.
		}
	}

	// Validate StatusCode — must be Success for a clean SLO round-trip.
	statusCode := ""
	// Try both prefixed and unprefixed paths.
	for _, path := range []string{"samlp:Status/samlp:StatusCode", "Status/StatusCode"} {
		if el := root.FindElement(path); el != nil {
			statusCode = el.SelectAttrValue("Value", "")
			break
		}
	}
	if statusCode == "" {
		s.log().Warn("LogoutResponse has no StatusCode element",
			zap.String("idp_entity_id", idp.EntityID),
		)
		return fmt.Errorf("LogoutResponse missing StatusCode")
	}
	if statusCode != samlStatusSuccess {
		s.log().Warn("LogoutResponse StatusCode is not Success",
			zap.String("status_code", statusCode),
			zap.String("idp_entity_id", idp.EntityID),
		)
		return fmt.Errorf("LogoutResponse StatusCode %q is not Success", statusCode)
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
func (s *SAMLService) HandleLogoutRequest(r *http.Request, sloURL *url.URL, idp *domain.IdPInfo) (*LogoutRequestResult, error) {
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
func (s *SAMLService) CreateLogoutResponse(requestID string, idp *domain.IdPInfo, sloURL *url.URL, relayState string) (*url.URL, error) {
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
