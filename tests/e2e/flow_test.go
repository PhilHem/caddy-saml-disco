//go:build e2e

package e2e

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	caddyadapter "github.com/philiph/caddy-saml-disco/internal/caddy"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	"github.com/philiph/caddy-saml-disco/internal/session"
	"github.com/philiph/caddy-saml-disco/testfixtures/idp"
)

// TestE2E_ProtectedRoute_RedirectsToIdP tests that:
// 1. Unauthenticated user accessing protected resource gets redirected to IdP
// 2. The redirect contains valid SAMLRequest
// 3. RelayState preserves the original URL
func TestE2E_ProtectedRoute_RedirectsToIdP(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, err := session.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create SP server using the plugin
	spServer := createTestSPServer(t, key, cert, testIdP)
	defer spServer.Close()

	// Create HTTP client that does NOT follow redirects
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Access protected resource without session
	resp, err := client.Get(spServer.URL + "/protected/dashboard?tab=settings")
	if err != nil {
		t.Fatalf("access protected resource: %v", err)
	}
	defer resp.Body.Close()

	// Should be redirected (302)
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected redirect (302), got %d", resp.StatusCode)
	}

	// Get redirect location
	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("expected Location header")
	}

	t.Logf("Redirect location: %s", location)

	// Parse redirect URL
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}

	// Should redirect to IdP
	if !strings.HasPrefix(location, testIdP.BaseURL()) {
		t.Errorf("expected redirect to IdP (%s), got: %s", testIdP.BaseURL(), location)
	}

	// Should have SAMLRequest parameter
	samlRequest := redirectURL.Query().Get("SAMLRequest")
	if samlRequest == "" {
		t.Error("expected SAMLRequest parameter in redirect URL")
	}

	// Should have RelayState with original URL
	relayState := redirectURL.Query().Get("RelayState")
	expectedRelayState := "/protected/dashboard?tab=settings"
	if relayState != expectedRelayState {
		t.Errorf("RelayState = %q, want %q", relayState, expectedRelayState)
	}
}

// TestE2E_ValidSession_AccessesProtectedResource tests that:
// 1. User with valid session cookie can access protected resources
// 2. No redirect occurs
func TestE2E_ValidSession_AccessesProtectedResource(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, err := session.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create SP server
	spServer := createTestSPServer(t, key, cert, testIdP)
	defer spServer.Close()

	// Create a valid session token
	sessionStore := session.NewCookieSessionStore(key, 8*time.Hour)
	sess := &domain.Session{
		Subject:     "testuser@example.com",
		IdPEntityID: testIdP.BaseURL(),
		Attributes:  map[string]string{"email": "testuser@example.com"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}
	token, err := sessionStore.Create(sess)
	if err != nil {
		t.Fatalf("create session token: %v", err)
	}

	// Create HTTP client with cookie jar
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(mustParseURL(spServer.URL), []*http.Cookie{
		{
			Name:  "saml_session",
			Value: token,
		},
	})
	client := &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
	}

	// Access protected resource
	resp, err := client.Get(spServer.URL + "/protected/dashboard")
	if err != nil {
		t.Fatalf("access protected resource: %v", err)
	}
	defer resp.Body.Close()

	// Should get 200 OK (protected content)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200 OK, got %d: %s", resp.StatusCode, string(body))
	}

	// Should contain protected content
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Protected Content") {
		t.Errorf("expected protected content, got: %s", string(body))
	}
}

// TestE2E_ExpiredSession_RedirectsToIdP tests that:
// 1. User with expired session cookie gets redirected to IdP
func TestE2E_ExpiredSession_RedirectsToIdP(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, err := session.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create SP server
	spServer := createTestSPServer(t, key, cert, testIdP)
	defer spServer.Close()

	// Create an expired session token (using very short duration)
	shortStore := session.NewCookieSessionStore(key, 1*time.Millisecond)
	sess := &domain.Session{
		Subject:     "testuser@example.com",
		IdPEntityID: testIdP.BaseURL(),
	}
	token, err := shortStore.Create(sess)
	if err != nil {
		t.Fatalf("create session token: %v", err)
	}

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	// Create HTTP client with expired session cookie
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(mustParseURL(spServer.URL), []*http.Cookie{
		{
			Name:  "saml_session",
			Value: token,
		},
	})
	client := &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Access protected resource
	resp, err := client.Get(spServer.URL + "/protected/dashboard")
	if err != nil {
		t.Fatalf("access protected resource: %v", err)
	}
	defer resp.Body.Close()

	// Should be redirected to IdP (session expired)
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected redirect (302), got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if !strings.HasPrefix(location, testIdP.BaseURL()) {
		t.Errorf("expected redirect to IdP, got: %s", location)
	}
}

// TestE2E_LogoutEndpoint_ClearsCookieAndRedirects tests that:
// 1. GET /saml/logout clears the session cookie
// 2. Redirects to return_to or /
func TestE2E_LogoutEndpoint_ClearsCookieAndRedirects(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, err := session.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create SP server
	spServer := createTestSPServer(t, key, cert, testIdP)
	defer spServer.Close()

	// Create HTTP client without following redirects
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Call logout endpoint
	resp, err := client.Get(spServer.URL + "/saml/logout?return_to=/goodbye")
	if err != nil {
		t.Fatalf("call logout: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected redirect (302), got %d", resp.StatusCode)
	}

	// Should redirect to return_to
	location := resp.Header.Get("Location")
	if location != "/goodbye" {
		t.Errorf("expected redirect to /goodbye, got: %s", location)
	}

	// Should have Set-Cookie header clearing the session
	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "saml_session" {
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("expected Set-Cookie header for session cookie")
	}

	if sessionCookie.MaxAge != -1 {
		t.Errorf("cookie MaxAge = %d, want -1 (delete)", sessionCookie.MaxAge)
	}
}

// TestE2E_SPMetadata_ValidXML tests that SP metadata endpoint returns valid XML.
func TestE2E_SPMetadata_ValidXML(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, err := session.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create SP server
	spServer := createTestSPServer(t, key, cert, testIdP)
	defer spServer.Close()

	// Fetch SP metadata
	resp, err := http.Get(spServer.URL + "/saml/metadata")
	if err != nil {
		t.Fatalf("fetch metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	// Check Content-Type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/samlmetadata+xml" {
		t.Errorf("Content-Type = %q, want application/samlmetadata+xml", contentType)
	}

	// Read body and verify it contains expected elements
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "EntityDescriptor") {
		t.Error("metadata should contain EntityDescriptor")
	}
	if !strings.Contains(bodyStr, "AssertionConsumerService") {
		t.Error("metadata should contain AssertionConsumerService")
	}
}

// createTestSPServer creates an httptest.Server that simulates the SAML plugin.
func createTestSPServer(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, testIdP *idp.TestIdP) *httptest.Server {
	t.Helper()

	var spURL string

	// Handler function - we'll update spURL after server starts
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := &testSPHandler{
			sessionStore: session.NewCookieSessionStore(key, 8*time.Hour),
			metadataStore: &testMetadataStore{
				idps: []domain.IdPInfo{
					{
						EntityID:     testIdP.BaseURL(),
						DisplayName:  "Test IdP",
						SSOURL:       testIdP.SSOURL(),
						SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
						Certificates: []string{},
					},
				},
			},
			samlService:       caddyadapter.NewSAMLService(spURL, key, cert),
			sessionCookieName: "saml_session",
			sessionDuration:   8 * time.Hour,
			spURL:             spURL,
		}
		h.ServeHTTP(w, r)
	})

	ts := httptest.NewServer(handler)
	spURL = ts.URL

	return ts
}

// testSPHandler simulates the SAML plugin behavior for E2E testing.
type testSPHandler struct {
	sessionStore      domain.SessionStore
	metadataStore     ports.MetadataStore
	samlService       *caddyadapter.SAMLService
	sessionCookieName string
	sessionDuration   time.Duration
	spURL             string
}

func (h *testSPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/saml/metadata":
		h.handleMetadata(w, r)
	case "/saml/acs":
		h.handleACS(w, r)
	case "/saml/logout":
		h.handleLogout(w, r)
	default:
		h.handleProtected(w, r)
	}
}

func (h *testSPHandler) handleMetadata(w http.ResponseWriter, r *http.Request) {
	acsURL, _ := url.Parse(h.spURL + "/saml/acs")
	metadata, err := h.samlService.GenerateSPMetadata(acsURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(metadata)
}

func (h *testSPHandler) handleACS(w http.ResponseWriter, r *http.Request) {
	idps, _ := h.metadataStore.ListIdPs("")
	if len(idps) == 0 {
		http.Error(w, "no IdP configured", http.StatusInternalServerError)
		return
	}
	idp := &idps[0]

	acsURL, _ := url.Parse(h.spURL + "/saml/acs")
	result, err := h.samlService.HandleACS(r, acsURL, idp)
	if err != nil {
		http.Error(w, "SAML auth failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Create session
	sess := &domain.Session{
		Subject:     result.Subject,
		Attributes:  result.Attributes,
		IdPEntityID: result.IdPEntityID,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(h.sessionDuration),
	}

	token, err := h.sessionStore.Create(sess)
	if err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(h.sessionDuration.Seconds()),
	})

	// Redirect to RelayState
	relayState := r.FormValue("RelayState")
	if relayState == "" {
		relayState = "/"
	}
	http.Redirect(w, r, relayState, http.StatusFound)
}

func (h *testSPHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	// Redirect to return_to or /
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" || !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (h *testSPHandler) handleProtected(w http.ResponseWriter, r *http.Request) {
	// Check session
	cookie, err := r.Cookie(h.sessionCookieName)
	if err != nil || cookie.Value == "" {
		h.redirectToIdP(w, r)
		return
	}

	_, err = h.sessionStore.Get(cookie.Value)
	if err != nil {
		h.redirectToIdP(w, r)
		return
	}

	// Session valid - serve protected content
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<html><body>Protected Content</body></html>"))
}

func (h *testSPHandler) redirectToIdP(w http.ResponseWriter, r *http.Request) {
	idps, _ := h.metadataStore.ListIdPs("")
	if len(idps) == 0 {
		http.Error(w, "no IdP", http.StatusInternalServerError)
		return
	}
	idp := &idps[0]

	acsURL, _ := url.Parse(h.spURL + "/saml/acs")
	relayState := r.URL.RequestURI()

	redirectURL, err := h.samlService.StartAuth(idp, acsURL, relayState)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// testMetadataStore implements MetadataStore for testing.
type testMetadataStore struct {
	idps []domain.IdPInfo
}

func (s *testMetadataStore) GetIdP(entityID string) (*domain.IdPInfo, error) {
	for i := range s.idps {
		if s.idps[i].EntityID == entityID {
			return &s.idps[i], nil
		}
	}
	return nil, domain.ErrIdPNotFound
}

func (s *testMetadataStore) ListIdPs(filter string) ([]domain.IdPInfo, error) {
	return s.idps, nil
}

func (s *testMetadataStore) Refresh(ctx context.Context) error {
	return nil
}

func (s *testMetadataStore) Health() domain.MetadataHealth {
	return domain.MetadataHealth{IsFresh: true, IdPCount: len(s.idps)}
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}
