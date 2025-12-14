//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	caddysamldisco "github.com/philiph/caddy-saml-disco"
	"github.com/philiph/caddy-saml-disco/testfixtures/idp"
)

// loadFileMetadataStore is a helper that creates and loads a file metadata store.
func loadFileMetadataStore(t *testing.T, path string) *caddysamldisco.FileMetadataStore {
	store := caddysamldisco.NewFileMetadataStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("load metadata: %v", err)
	}
	return store
}

// testTemplateRenderer creates a template renderer for integration tests.
func testTemplateRenderer(t *testing.T) *caddysamldisco.TemplateRenderer {
	t.Helper()
	renderer, err := caddysamldisco.NewTemplateRenderer()
	if err != nil {
		t.Fatalf("create template renderer: %v", err)
	}
	return renderer
}

// TestDiscoveryFlow_ListIdPs_ReturnsMultipleIdPs tests that the discovery API
// lists multiple IdPs from the metadata store.
func TestDiscoveryFlow_ListIdPs_ReturnsMultipleIdPs(t *testing.T) {
	// Create plugin with file metadata store (DFN sample has multiple IdPs)
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(loadFileMetadataStore(t, "../../testdata/dfn-aai-sample.xml"))

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Request IdP list
	resp, err := http.Get(server.URL + "/saml/api/idps")
	if err != nil {
		t.Fatalf("GET /saml/api/idps: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Parse response
	var result struct {
		IdPs []caddysamldisco.IdPInfo `json:"idps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	// Should have multiple IdPs
	if len(result.IdPs) < 2 {
		t.Errorf("len(idps) = %d, want >= 2", len(result.IdPs))
	}

	// Each IdP should have required fields
	for i, idp := range result.IdPs {
		if idp.EntityID == "" {
			t.Errorf("idps[%d].EntityID is empty", i)
		}
		if idp.DisplayName == "" {
			t.Errorf("idps[%d].DisplayName is empty", i)
		}
		if idp.SSOURL == "" {
			t.Errorf("idps[%d].SSOURL is empty", i)
		}
	}
}

// TestDiscoveryFlow_SearchIdPs_FiltersResults tests that searching IdPs
// returns only matching results.
func TestDiscoveryFlow_SearchIdPs_FiltersResults(t *testing.T) {
	// Create plugin with file metadata store
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(loadFileMetadataStore(t, "../../testdata/dfn-aai-sample.xml"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Search for "RWTH" - should find RWTH Aachen
	resp, err := http.Get(server.URL + "/saml/api/idps?q=RWTH")
	if err != nil {
		t.Fatalf("GET /saml/api/idps?q=RWTH: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		IdPs []caddysamldisco.IdPInfo `json:"idps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	// Should find exactly one match
	if len(result.IdPs) != 1 {
		t.Errorf("len(idps) = %d, want 1", len(result.IdPs))
	}

	if len(result.IdPs) > 0 && !strings.Contains(result.IdPs[0].DisplayName, "RWTH") {
		t.Errorf("idps[0].DisplayName = %q, want to contain 'RWTH'", result.IdPs[0].DisplayName)
	}
}

// TestDiscoveryFlow_SelectIdP_StartsAuth tests that selecting an IdP via the API
// starts the SAML authentication flow.
func TestDiscoveryFlow_SelectIdP_StartsAuth(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := caddysamldisco.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create in-memory metadata store with test IdP
	idpInfo := caddysamldisco.IdPInfo{
		EntityID:     testIdP.BaseURL(),
		DisplayName:  "Test IdP",
		SSOURL:       testIdP.SSOURL(),
		SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{},
	}
	store := caddysamldisco.NewInMemoryMetadataStore([]caddysamldisco.IdPInfo{idpInfo})

	// Create SAML service
	service := caddysamldisco.NewSAMLService("https://sp.example.com", key, cert)

	// Create plugin
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(store)
	disco.SetSAMLService(service)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// POST to select IdP
	body := strings.NewReader(`{"entity_id":"` + testIdP.BaseURL() + `"}`)
	req, _ := http.NewRequest("POST", server.URL+"/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /saml/api/select: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect to IdP
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d, body: %s", resp.StatusCode, http.StatusFound, body)
	}

	location := resp.Header.Get("Location")
	if !strings.HasPrefix(location, testIdP.BaseURL()) {
		t.Errorf("Location = %q, want prefix %q", location, testIdP.BaseURL())
	}

	// Verify SAMLRequest is in the redirect URL
	locationURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if locationURL.Query().Get("SAMLRequest") == "" {
		t.Error("redirect URL should contain SAMLRequest parameter")
	}
}

// TestDiscoveryFlow_DiscoUI_SingleIdP_AutoRedirect tests that the discovery UI
// automatically redirects when there's only one IdP.
func TestDiscoveryFlow_DiscoUI_SingleIdP_AutoRedirect(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := caddysamldisco.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create in-memory store with single IdP
	idpInfo := caddysamldisco.IdPInfo{
		EntityID:     testIdP.BaseURL(),
		DisplayName:  "Test IdP",
		SSOURL:       testIdP.SSOURL(),
		SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{},
	}
	store := caddysamldisco.NewInMemoryMetadataStore([]caddysamldisco.IdPInfo{idpInfo})

	// Create SAML service and plugin
	service := caddysamldisco.NewSAMLService("https://sp.example.com", key, cert)
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(store)
	disco.SetSAMLService(service)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// GET disco UI
	resp, err := client.Get(server.URL + "/saml/disco")
	if err != nil {
		t.Fatalf("GET /saml/disco: %v", err)
	}
	defer resp.Body.Close()

	// Should auto-redirect to IdP
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}

	location := resp.Header.Get("Location")
	if !strings.HasPrefix(location, testIdP.BaseURL()) {
		t.Errorf("Location = %q, want prefix %q", location, testIdP.BaseURL())
	}
}

// TestDiscoveryFlow_DiscoUI_MultipleIdPs_ShowsPage tests that the discovery UI
// shows the selection page when there are multiple IdPs.
func TestDiscoveryFlow_DiscoUI_MultipleIdPs_ShowsPage(t *testing.T) {
	// Create plugin with file metadata store (multiple IdPs)
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(loadFileMetadataStore(t, "../../testdata/dfn-aai-sample.xml"))
	disco.SetTemplateRenderer(testTemplateRenderer(t))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	resp, err := http.Get(server.URL + "/saml/disco")
	if err != nil {
		t.Fatalf("GET /saml/disco: %v", err)
	}
	defer resp.Body.Close()

	// Should return HTML page (not redirect)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want to contain 'text/html'", contentType)
	}

	// Body should contain IdP selection elements
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "idp-list") {
		t.Error("HTML should contain idp-list element")
	}
}

// TestDiscoveryFlow_SessionInfo_Unauthenticated tests that session info endpoint
// returns unauthenticated status when there's no session.
func TestDiscoveryFlow_SessionInfo_Unauthenticated(t *testing.T) {
	disco := &caddysamldisco.SAMLDisco{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	resp, err := http.Get(server.URL + "/saml/api/session")
	if err != nil {
		t.Fatalf("GET /saml/api/session: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if result["authenticated"] != false {
		t.Errorf("authenticated = %v, want false", result["authenticated"])
	}
}

// TestDiscoveryFlow_FullFlow_SelectAndAuthenticate tests the complete discovery
// and authentication flow from UI to session.
func TestDiscoveryFlow_FullFlow_SelectAndAuthenticate(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Add test user to IdP
	testIdP.AddUser("testuser", "password123")

	// Load SP credentials
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := caddysamldisco.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create in-memory metadata store with test IdP
	idpInfo := caddysamldisco.IdPInfo{
		EntityID:     testIdP.BaseURL(),
		DisplayName:  "Test IdP",
		SSOURL:       testIdP.SSOURL(),
		SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{},
	}
	store := caddysamldisco.NewInMemoryMetadataStore([]caddysamldisco.IdPInfo{idpInfo})

	// Create SAML service and register SP with IdP
	service := caddysamldisco.NewSAMLService("https://sp.example.com", key, cert)
	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	metadata, _ := service.GenerateSPMetadata(acsURL)
	testIdP.AddServiceProviderMetadata("https://sp.example.com", metadata)

	// Create plugin
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(store)
	disco.SetSAMLService(service)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Create HTTP client with cookie jar
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Check discovery UI lists IdP
	resp, err := http.Get(server.URL + "/saml/api/idps")
	if err != nil {
		t.Fatalf("GET /saml/api/idps: %v", err)
	}
	var idpResult struct {
		IdPs []caddysamldisco.IdPInfo `json:"idps"`
	}
	json.NewDecoder(resp.Body).Decode(&idpResult)
	resp.Body.Close()

	if len(idpResult.IdPs) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idpResult.IdPs))
	}
	t.Logf("Step 1: Found %d IdP(s)", len(idpResult.IdPs))

	// Step 2: Select IdP via API
	body := strings.NewReader(`{"entity_id":"` + testIdP.BaseURL() + `"}`)
	req, _ := http.NewRequest("POST", server.URL+"/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST /saml/api/select: %v", err)
	}

	if resp.StatusCode != http.StatusFound {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected redirect, got %d: %s", resp.StatusCode, respBody)
	}

	idpRedirectURL := resp.Header.Get("Location")
	resp.Body.Close()
	t.Logf("Step 2: Redirecting to IdP: %s", idpRedirectURL)

	// Step 3: Follow redirect to IdP (this simulates browser behavior)
	resp, err = client.Get(idpRedirectURL)
	if err != nil {
		t.Fatalf("GET IdP redirect: %v", err)
	}
	t.Logf("Step 3: IdP response status: %d", resp.StatusCode)
	resp.Body.Close()

	// The full flow would continue with:
	// - IdP presenting login form
	// - User submitting credentials
	// - IdP returning SAMLResponse to ACS
	// - SP validating response and creating session
	//
	// For this integration test, we've verified:
	// 1. Discovery API lists IdPs
	// 2. Select API starts SAML flow
	// 3. Redirect to IdP is valid

	// Verify session is still unauthenticated (since we didn't complete IdP login)
	resp, _ = http.Get(server.URL + "/saml/api/session")
	var session map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&session)
	resp.Body.Close()

	if session["authenticated"] != false {
		t.Error("session should be unauthenticated before completing IdP login")
	}
	t.Log("Step 4: Session is unauthenticated as expected")
}

// TestDiscoveryFlow_LoginRedirect_RedirectsToCustomURL tests that when
// LoginRedirect is configured, unauthenticated requests to protected routes
// are redirected to the custom login URL instead of the IdP.
func TestDiscoveryFlow_LoginRedirect_RedirectsToCustomURL(t *testing.T) {
	// Load SP credentials for session store
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	// Create session store (needed for session checking)
	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*3600*1000000000) // 8 hours

	// Create plugin with LoginRedirect configured
	discoWithConfig := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			SessionCookieName: "saml_session",
			LoginRedirect:     "/my-custom-login",
		},
	}
	discoWithConfig.SetSessionStore(sessionStore)

	// Create test server
	// Note: The redirect happens before next handler is called, so we pass nil
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discoWithConfig.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Request protected route without session
	resp, err := client.Get(server.URL + "/protected/resource?foo=bar")
	if err != nil {
		t.Fatalf("GET /protected/resource: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect to custom login URL
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d, body: %s", resp.StatusCode, http.StatusFound, body)
	}

	location := resp.Header.Get("Location")

	// Should redirect to custom login URL with return_url
	if !strings.HasPrefix(location, "/my-custom-login?") {
		t.Errorf("Location = %q, want prefix '/my-custom-login?'", location)
	}

	// Parse to verify return_url parameter
	locationURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}

	returnURL := locationURL.Query().Get("return_url")
	if returnURL != "/protected/resource?foo=bar" {
		t.Errorf("return_url = %q, want '/protected/resource?foo=bar'", returnURL)
	}
}

// TestSelectIdP_SetsRememberCookie tests that selecting an IdP sets a cookie
// to remember the user's preference.
func TestSelectIdP_SetsRememberCookie(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := caddysamldisco.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create in-memory metadata store with test IdP
	idpInfo := caddysamldisco.IdPInfo{
		EntityID:     testIdP.BaseURL(),
		DisplayName:  "Test IdP",
		SSOURL:       testIdP.SSOURL(),
		SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{},
	}
	store := caddysamldisco.NewInMemoryMetadataStore([]caddysamldisco.IdPInfo{idpInfo})

	// Create SAML service
	service := caddysamldisco.NewSAMLService("https://sp.example.com", key, cert)

	// Create plugin with remember IdP cookie configured
	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			RememberIdPCookieName: "saml_last_idp",
			RememberIdPDuration:   "30d",
		},
	}
	disco.SetMetadataStore(store)
	disco.SetSAMLService(service)
	disco.SetRememberIdPDuration(30 * 24 * time.Hour) // 30 days

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// POST to select IdP
	body := strings.NewReader(`{"entity_id":"` + testIdP.BaseURL() + `"}`)
	req, _ := http.NewRequest("POST", server.URL+"/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /saml/api/select: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect to IdP
	if resp.StatusCode != http.StatusFound {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d, body: %s", resp.StatusCode, http.StatusFound, respBody)
	}

	// Check for remember cookie in Set-Cookie headers
	var foundRememberCookie bool
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "saml_last_idp" {
			foundRememberCookie = true
			if cookie.Value != testIdP.BaseURL() {
				t.Errorf("cookie value = %q, want %q", cookie.Value, testIdP.BaseURL())
			}
			if !cookie.HttpOnly {
				t.Error("cookie should be HttpOnly")
			}
			if cookie.SameSite != http.SameSiteLaxMode {
				t.Errorf("cookie SameSite = %v, want Lax", cookie.SameSite)
			}
			// MaxAge should be ~30 days (2592000 seconds)
			if cookie.MaxAge < 2500000 {
				t.Errorf("cookie MaxAge = %d, want ~2592000", cookie.MaxAge)
			}
			break
		}
	}

	if !foundRememberCookie {
		t.Error("expected saml_last_idp cookie to be set")
	}
}

// TestDiscoveryPage_ReadsRememberCookie tests that the discovery page reads
// the remembered IdP cookie and passes it to the template.
func TestDiscoveryPage_ReadsRememberCookie(t *testing.T) {
	// Create plugin with file metadata store (multiple IdPs)
	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			RememberIdPCookieName: "saml_last_idp",
		},
	}
	disco.SetMetadataStore(loadFileMetadataStore(t, "../../testdata/dfn-aai-sample.xml"))
	disco.SetTemplateRenderer(testTemplateRenderer(t))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Make request with remember cookie set
	req, _ := http.NewRequest("GET", server.URL+"/saml/disco", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_last_idp",
		Value: "https://idp.uni-heidelberg.de/idp/shibboleth",
	})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /saml/disco: %v", err)
	}
	defer resp.Body.Close()

	// Should return HTML page
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Body should contain the remembered IdP marked
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "remembered") {
		t.Error("HTML should contain 'remembered' class for the remembered IdP")
	}
}

// TestListIdPs_IncludesRememberedIdP tests that the list IdPs API returns
// the remembered IdP ID when the cookie is set.
func TestListIdPs_IncludesRememberedIdP(t *testing.T) {
	// Create plugin with file metadata store
	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			RememberIdPCookieName: "saml_last_idp",
		},
	}
	disco.SetMetadataStore(loadFileMetadataStore(t, "../../testdata/dfn-aai-sample.xml"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Make request with remember cookie set
	req, _ := http.NewRequest("GET", server.URL+"/saml/api/idps", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_last_idp",
		Value: "https://idp.uni-heidelberg.de/idp/shibboleth",
	})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /saml/api/idps: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Parse response - should now be an object with idps and remembered_idp_id
	var result struct {
		IdPs          []caddysamldisco.IdPInfo `json:"idps"`
		RememberedIdP string                   `json:"remembered_idp_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if result.RememberedIdP != "https://idp.uni-heidelberg.de/idp/shibboleth" {
		t.Errorf("remembered_idp_id = %q, want %q", result.RememberedIdP, "https://idp.uni-heidelberg.de/idp/shibboleth")
	}

	if len(result.IdPs) < 2 {
		t.Errorf("len(idps) = %d, want >= 2", len(result.IdPs))
	}
}

// TestLogout_ClearsRememberCookie tests that logging out clears the
// remembered IdP cookie.
func TestLogout_ClearsRememberCookie(t *testing.T) {
	// Load SP key for session store
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	// Create session store
	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	// Create plugin with remember IdP cookie configured
	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			SessionCookieName:     "saml_session",
			RememberIdPCookieName: "saml_last_idp",
		},
	}
	disco.SetSessionStore(sessionStore)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// GET /saml/logout
	resp, err := client.Get(server.URL + "/saml/logout")
	if err != nil {
		t.Fatalf("GET /saml/logout: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}

	// Check for remember cookie being cleared (MaxAge = -1)
	var foundRememberCookie bool
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "saml_last_idp" {
			foundRememberCookie = true
			if cookie.MaxAge != -1 {
				t.Errorf("cookie MaxAge = %d, want -1 (delete)", cookie.MaxAge)
			}
			break
		}
	}

	if !foundRememberCookie {
		t.Error("expected saml_last_idp cookie to be cleared on logout")
	}
}

// =============================================================================
// Multi-Language Support Tests (Phase 3)
// =============================================================================

// TestDiscoveryFlow_MultiLanguage_GermanPreference tests that the JSON API
// returns German display names when Accept-Language: de is set.
func TestDiscoveryFlow_MultiLanguage_GermanPreference(t *testing.T) {
	// Create plugin with DFN sample metadata (has German/English variants)
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(loadFileMetadataStore(t, "../../testdata/dfn-aai-sample.xml"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Request with German Accept-Language header
	req, _ := http.NewRequest("GET", server.URL+"/saml/api/idps", nil)
	req.Header.Set("Accept-Language", "de, en;q=0.8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /saml/api/idps: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result struct {
		IdPs []caddysamldisco.IdPInfo `json:"idps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	// Find TUM which has different German/English names
	var tumIdP *caddysamldisco.IdPInfo
	for i := range result.IdPs {
		if result.IdPs[i].EntityID == "https://tumidp.lrz.de/idp/shibboleth" {
			tumIdP = &result.IdPs[i]
			break
		}
	}

	if tumIdP == nil {
		t.Fatal("TUM IdP not found in response")
	}

	// Should have German display name when Accept-Language: de
	expectedName := "Technische Universität München (TUM)"
	if tumIdP.DisplayName != expectedName {
		t.Errorf("TUM DisplayName = %q, want %q", tumIdP.DisplayName, expectedName)
	}

	// Should have German description
	expectedDesc := "Die TUM ist eine der führenden technischen Universitäten Europas."
	if tumIdP.Description != expectedDesc {
		t.Errorf("TUM Description = %q, want %q", tumIdP.Description, expectedDesc)
	}
}

// TestDiscoveryFlow_MultiLanguage_EnglishDefault tests that the JSON API
// returns English display names by default (no Accept-Language header).
func TestDiscoveryFlow_MultiLanguage_EnglishDefault(t *testing.T) {
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(loadFileMetadataStore(t, "../../testdata/dfn-aai-sample.xml"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Request without Accept-Language header
	resp, err := http.Get(server.URL + "/saml/api/idps")
	if err != nil {
		t.Fatalf("GET /saml/api/idps: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		IdPs []caddysamldisco.IdPInfo `json:"idps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	// Find TUM
	var tumIdP *caddysamldisco.IdPInfo
	for i := range result.IdPs {
		if result.IdPs[i].EntityID == "https://tumidp.lrz.de/idp/shibboleth" {
			tumIdP = &result.IdPs[i]
			break
		}
	}

	if tumIdP == nil {
		t.Fatal("TUM IdP not found in response")
	}

	// Should have English display name by default
	expectedName := "Technical University of Munich (TUM)"
	if tumIdP.DisplayName != expectedName {
		t.Errorf("TUM DisplayName = %q, want %q", tumIdP.DisplayName, expectedName)
	}
}

// TestDiscoveryFlow_MultiLanguage_IncludesAllVariants tests that the JSON API
// includes the DisplayNames map with all language variants.
func TestDiscoveryFlow_MultiLanguage_IncludesAllVariants(t *testing.T) {
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(loadFileMetadataStore(t, "../../testdata/dfn-aai-sample.xml"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	resp, err := http.Get(server.URL + "/saml/api/idps")
	if err != nil {
		t.Fatalf("GET /saml/api/idps: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		IdPs []caddysamldisco.IdPInfo `json:"idps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	// Find TUM
	var tumIdP *caddysamldisco.IdPInfo
	for i := range result.IdPs {
		if result.IdPs[i].EntityID == "https://tumidp.lrz.de/idp/shibboleth" {
			tumIdP = &result.IdPs[i]
			break
		}
	}

	if tumIdP == nil {
		t.Fatal("TUM IdP not found in response")
	}

	// Should include all language variants in the DisplayNames map
	if tumIdP.DisplayNames == nil {
		t.Fatal("DisplayNames map should not be nil")
	}

	if tumIdP.DisplayNames["en"] != "Technical University of Munich (TUM)" {
		t.Errorf("DisplayNames[en] = %q, want English name", tumIdP.DisplayNames["en"])
	}

	if tumIdP.DisplayNames["de"] != "Technische Universität München (TUM)" {
		t.Errorf("DisplayNames[de] = %q, want German name", tumIdP.DisplayNames["de"])
	}
}
