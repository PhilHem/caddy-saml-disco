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

	applyAuthnOptions(authReq, opts)
	s.rememberAuthnRequest(authReq.ID, idp.EntityID)

	// Build redirect URL
	redirectURL, err := authReq.Redirect(relayState, sp)
	if err != nil {
		return nil, err
	}

	return redirectURL, nil
}

// applyAuthnOptions applies the optional ForceAuthn and RequestedAuthnContext
// settings to an outgoing AuthnRequest. A nil opts leaves the request unchanged.
func applyAuthnOptions(authReq *saml.AuthnRequest, opts *domain.AuthnOptions) {
	if opts == nil {
		return
	}

	if opts.ForceAuthn {
		forceAuthn := true
		authReq.ForceAuthn = &forceAuthn
	}

	// Note: crewjam/saml library only supports a single AuthnContextClassRef,
	// so we use the first element if multiple are provided.
	if len(opts.RequestedAuthnContext) > 0 {
		comparison := opts.AuthnContextComparison
		if comparison == "" {
			comparison = "exact" // SAML spec default
		}
		authReq.RequestedAuthnContext = &saml.RequestedAuthnContext{
			Comparison:           comparison,
			AuthnContextClassRef: opts.RequestedAuthnContext[0],
		}
	}
}

// rememberAuthnRequest stores the AuthnRequest ID for later validation
// (configurable TTL, default 10 minutes). It prefers StoreWithEntityID so ACS
// can recover the IdP after a metadata refresh.
func (s *SAMLService) rememberAuthnRequest(requestID, entityID string) {
	expiry := time.Now().Add(s.requestTTL)
	if store, ok := s.requestStore.(interface {
		StoreWithEntityID(string, time.Time, string)
	}); ok {
		store.StoreWithEntityID(requestID, expiry, entityID)
	} else {
		s.requestStore.Store(requestID, expiry)
	}
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
	assertion, err := s.parseACSResponse(r, acsURL, idp)
	if err != nil {
		return nil, err
	}

	subject, nameIDFormat := extractSubject(assertion)
	sessionIndex := extractSessionIndex(assertion)
	attrs := extractAttributes(assertion)

	if err := validateScopes(attrs, idp); err != nil {
		return nil, err
	}

	if err := s.consumeRequestID(assertion); err != nil {
		return nil, err
	}

	return &AuthResult{
		Subject:      subject,
		Attributes:   attrs,
		IdPEntityID:  idp.EntityID,
		NameIDFormat: nameIDFormat,
		SessionIndex: sessionIndex,
	}, nil
}

// parseACSResponse configures the SP for the IdP and parses/validates the SAML
// Response from the request, returning the verified assertion.
// Note: ParseResponse automatically decrypts encrypted assertions using sp.Key.
func (s *SAMLService) parseACSResponse(r *http.Request, acsURL *url.URL, idp *domain.IdPInfo) (*saml.Assertion, error) {
	sp := s.buildServiceProvider(acsURL)

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

	assertion, err := sp.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		return nil, fmt.Errorf("parse saml response: %w", err)
	}
	return assertion, nil
}

// extractSubject returns the user identifier and NameIDFormat from the assertion.
func extractSubject(assertion *saml.Assertion) (subject, nameIDFormat string) {
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		return assertion.Subject.NameID.Value, assertion.Subject.NameID.Format
	}
	return "", ""
}

// extractSessionIndex returns the SessionIndex from the first AuthnStatement, if any.
func extractSessionIndex(assertion *saml.Assertion) string {
	if len(assertion.AuthnStatements) > 0 {
		return assertion.AuthnStatements[0].SessionIndex
	}
	return ""
}

// extractAttributes flattens the assertion's attribute statements into a map,
// keyed by FriendlyName when present, otherwise by Name.
func extractAttributes(assertion *saml.Assertion) map[string]string {
	attrs := make(map[string]string)
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) == 0 {
				continue
			}
			key := attr.FriendlyName
			if key == "" {
				key = attr.Name
			}
			attrs[key] = attr.Values[0].Value
		}
	}
	return attrs
}

// validateScopes verifies that every scoped attribute carries a scope the IdP is
// allowed to assert. A no-op when the IdP declares no allowed scopes.
func validateScopes(attrs map[string]string, idp *domain.IdPInfo) error {
	if len(idp.AllowedScopes) == 0 {
		return nil
	}
	for attrName, attrValue := range attrs {
		if !domain.IsScopedAttribute(attrName) {
			continue
		}
		scope := domain.ExtractScope(attrValue)
		if !domain.ValidateScope(scope, idp.AllowedScopes) {
			return fmt.Errorf("scope validation failed: %s scope %q not allowed for IdP %q", attrName, scope, idp.EntityID)
		}
	}
	return nil
}

// consumeRequestID marks the AuthnRequest that triggered this assertion as used,
// enforcing single-use. The InResponseTo field links back to our original
// request; Valid() atomically checks and deletes the ID, returning false if the
// ID was already consumed or never existed, indicating a replay.
func (s *SAMLService) consumeRequestID(assertion *saml.Assertion) error {
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
		return fmt.Errorf("request ID already consumed or not found: replay detected")
	}
	return nil
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

// ValidateLogoutResponse validates a LogoutResponse from the IdP.
// The raw response must have been extracted from the HTTP request by the caller.
//
// Validation failures are logged as warnings but do not prevent the caller
// from continuing with local logout — the logout flow must complete even when
// the IdP response is malformed or carries a non-success status.
func (s *SAMLService) ValidateLogoutResponse(raw domain.RawLogoutResponse, idp *domain.IdPInfo) (domain.ValidatedLogoutResponse, error) {
	root, err := parseLogoutResponse(raw)
	if err != nil {
		return domain.ValidatedLogoutResponse{}, err
	}

	issuerText, err := s.validateLogoutIssuer(root, idp)
	if err != nil {
		return domain.ValidatedLogoutResponse{}, err
	}

	inResponseTo := s.checkLogoutInResponseTo(root, idp)

	statusCode, err := s.validateLogoutStatus(root, idp)
	if err != nil {
		return domain.ValidatedLogoutResponse{}, err
	}

	return domain.ValidatedLogoutResponse{
		StatusCode:   statusCode,
		InResponseTo: inResponseTo,
		Issuer:       issuerText,
	}, nil
}

// parseLogoutResponse base64-decodes the redirect-binding payload and returns
// the root element of the parsed XML.
func parseLogoutResponse(raw domain.RawLogoutResponse) (*etree.Element, error) {
	if raw.Encoded == "" {
		return nil, fmt.Errorf("missing SAMLResponse parameter")
	}

	// Base64-decode the response (redirect binding uses standard base64).
	xmlBytes, err := base64.StdEncoding.DecodeString(raw.Encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode LogoutResponse: %w", err)
	}

	// Parse the XML with etree for namespace-aware element access.
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("parse LogoutResponse XML: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("LogoutResponse has no root element")
	}
	return root, nil
}

// validateLogoutIssuer ensures the response carries an Issuer matching the
// expected IdP, returning the issuer text on success.
func (s *SAMLService) validateLogoutIssuer(root *etree.Element, idp *domain.IdPInfo) (string, error) {
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
		return "", fmt.Errorf("LogoutResponse missing Issuer")
	}
	if issuerText != idp.EntityID {
		s.log().Warn("LogoutResponse Issuer does not match expected IdP",
			zap.String("expected", idp.EntityID),
			zap.String("got", issuerText),
		)
		return "", fmt.Errorf("LogoutResponse Issuer %q does not match IdP %q", issuerText, idp.EntityID)
	}
	return issuerText, nil
}

// checkLogoutInResponseTo returns the InResponseTo attribute, if any.
// When present but unknown to the request store it logs a warning but does not
// fail: the store may have expired the ID or may not track logout request IDs
// separately from authn request IDs.
func (s *SAMLService) checkLogoutInResponseTo(root *etree.Element, idp *domain.IdPInfo) string {
	inResponseTo := root.SelectAttrValue("InResponseTo", "")
	if inResponseTo == "" {
		return ""
	}

	for _, id := range s.requestStore.GetAll() {
		if id == inResponseTo {
			return inResponseTo
		}
	}

	// Defense-in-depth: log the warning but don't block the logout.
	s.log().Warn("LogoutResponse InResponseTo not found in pending requests",
		zap.String("in_response_to", inResponseTo),
		zap.String("idp_entity_id", idp.EntityID),
	)
	return inResponseTo
}

// validateLogoutStatus ensures the response carries a Success StatusCode,
// returning the status code on success.
func (s *SAMLService) validateLogoutStatus(root *etree.Element, idp *domain.IdPInfo) (string, error) {
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
		return "", fmt.Errorf("LogoutResponse missing StatusCode")
	}
	if statusCode != samlStatusSuccess {
		s.log().Warn("LogoutResponse StatusCode is not Success",
			zap.String("status_code", statusCode),
			zap.String("idp_entity_id", idp.EntityID),
		)
		return "", fmt.Errorf("LogoutResponse StatusCode %q is not Success", statusCode)
	}
	return statusCode, nil
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
