// Package idp provides a test SAML Identity Provider for integration testing.
// It wraps crewjam/saml/samlidp to provide a simple API for tests.
package idp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/crewjam/saml/samlidp"
)

// TestIdP is a test SAML Identity Provider for integration testing.
type TestIdP struct {
	t      testing.TB
	server *httptest.Server
	idp    *samlidp.Server
	store  *samlidp.MemoryStore
}

// New creates a new test IdP. Call Close() when done.
func New(t testing.TB) *TestIdP {
	t.Helper()

	// Generate self-signed certificate for the IdP
	key, cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate IdP certificate: %v", err)
	}

	store := &samlidp.MemoryStore{}

	// Create httptest server first to get the URL
	var tidp *TestIdP
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tidp != nil && tidp.idp != nil {
			tidp.idp.ServeHTTP(w, r)
		}
	}))

	baseURL, err := url.Parse(ts.URL)
	if err != nil {
		ts.Close()
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *baseURL,
		Key:         key,
		Certificate: cert,
		Store:       store,
	})
	if err != nil {
		ts.Close()
		t.Fatalf("failed to create IdP server: %v", err)
	}

	tidp = &TestIdP{
		t:      t,
		server: ts,
		idp:    idpServer,
		store:  store,
	}

	return tidp
}

// Close shuts down the test IdP server.
func (idp *TestIdP) Close() {
	if idp.server != nil {
		idp.server.Close()
	}
}

// BaseURL returns the base URL of the test IdP.
func (idp *TestIdP) BaseURL() string {
	return idp.server.URL
}

// MetadataURL returns the URL to fetch IdP metadata.
func (idp *TestIdP) MetadataURL() string {
	return idp.server.URL + "/metadata"
}

// SSOURL returns the SSO endpoint URL.
func (idp *TestIdP) SSOURL() string {
	return idp.server.URL + "/sso"
}

// AddUser creates a test user in the IdP.
func (idp *TestIdP) AddUser(username, password string) {
	idp.t.Helper()

	user := samlidp.User{
		Name:              username,
		PlaintextPassword: &password,
		Email:             username + "@example.com",
		CommonName:        username,
		GivenName:         username,
		Surname:           "Test",
	}

	if err := idp.store.Put("/users/"+username, user); err != nil {
		idp.t.Fatalf("failed to add user %s: %v", username, err)
	}
}

// AddUserWithAttributes creates a test user with custom attributes.
func (idp *TestIdP) AddUserWithAttributes(user samlidp.User) {
	idp.t.Helper()

	if err := idp.store.Put("/users/"+user.Name, user); err != nil {
		idp.t.Fatalf("failed to add user %s: %v", user.Name, err)
	}
}

// AddServiceProvider registers an SP with the IdP using its metadata URL.
func (idp *TestIdP) AddServiceProvider(metadataURL string) {
	idp.t.Helper()

	// Fetch SP metadata
	resp, err := http.Get(metadataURL)
	if err != nil {
		idp.t.Fatalf("failed to fetch SP metadata from %s: %v", metadataURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		idp.t.Fatalf("failed to fetch SP metadata: status %d", resp.StatusCode)
	}

	// Read metadata XML
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		idp.t.Fatalf("failed to read SP metadata: %v", err)
	}

	idp.AddServiceProviderMetadata(metadataURL, buf.Bytes())
}

// AddServiceProviderMetadata registers an SP with the IdP using raw metadata XML.
func (idp *TestIdP) AddServiceProviderMetadata(entityID string, metadata []byte) {
	idp.t.Helper()

	// The samlidp expects to PUT metadata via HTTP, but we can store directly
	// Store key format: /services/{entityID}
	req, err := http.NewRequest(http.MethodPut, idp.server.URL+"/services/"+url.PathEscape(entityID), bytes.NewReader(metadata))
	if err != nil {
		idp.t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		idp.t.Fatalf("failed to register SP: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusCreated {
		idp.t.Fatalf("failed to register SP: status %d", resp.StatusCode)
	}
}

// generateSelfSignedCert creates a self-signed certificate for the test IdP.
func generateSelfSignedCert() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test IdP",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	return key, cert, nil
}

// CertificatePEM returns the IdP certificate in PEM format.
// Useful for configuring SPs that need to trust the IdP.
func (idp *TestIdP) CertificatePEM() []byte {
	cert := idp.idp.IDP.Certificate
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}
