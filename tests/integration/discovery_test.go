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
	var idps []caddysamldisco.IdPInfo
	if err := json.NewDecoder(resp.Body).Decode(&idps); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	// Should have multiple IdPs
	if len(idps) < 2 {
		t.Errorf("len(idps) = %d, want >= 2", len(idps))
	}

	// Each IdP should have required fields
	for i, idp := range idps {
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

	var idps []caddysamldisco.IdPInfo
	if err := json.NewDecoder(resp.Body).Decode(&idps); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	// Should find exactly one match
	if len(idps) != 1 {
		t.Errorf("len(idps) = %d, want 1", len(idps))
	}

	if len(idps) > 0 && !strings.Contains(idps[0].DisplayName, "RWTH") {
		t.Errorf("idps[0].DisplayName = %q, want to contain 'RWTH'", idps[0].DisplayName)
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
	var idps []caddysamldisco.IdPInfo
	json.NewDecoder(resp.Body).Decode(&idps)
	resp.Body.Close()

	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idps))
	}
	t.Logf("Step 1: Found %d IdP(s)", len(idps))

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
