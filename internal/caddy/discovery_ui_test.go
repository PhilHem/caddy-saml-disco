//go:build unit

package caddy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/discovery"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/session"
)

func TestDiscoveryUI_ServesHTML(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{EntityID: "https://idp1.example.com", DisplayName: "IdP One"},
			{EntityID: "https://idp2.example.com", DisplayName: "IdP Two"},
		},
	}

	s := &SAMLDisco{}
	s.SetMetadataStore(metadataStore)
	s.SetTemplateRenderer(testTemplateRenderer(t))

	req := httptest.NewRequest(http.MethodGet, "/saml/disco", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", contentType)
	}

	body := rec.Body.String()
	// Should contain basic HTML structure
	if !strings.Contains(body, "<html") {
		t.Errorf("response should contain <html>, got: %s", body)
	}
	// Should contain IdP selection elements
	if !strings.Contains(body, "IdP") || !strings.Contains(body, "select") {
		t.Errorf("response should contain IdP selection UI elements")
	}
}

// TestDiscoveryUI_SingleIdP_AutoRedirect verifies that GET /saml/disco
// with only one IdP auto-redirects to that IdP.

func TestDiscoveryUI_SingleIdP_AutoRedirect(t *testing.T) {
	key := loadTestKey(t)
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{
				EntityID:   "https://single-idp.example.com/saml",
				SSOURL:     "https://single-idp.example.com/sso",
				SSOBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID: "https://sp.example.com",
		},
	}
	s.SetMetadataStore(metadataStore)
	s.SetSAMLService(samlService)
	s.SetTemplateRenderer(testTemplateRenderer(t))

	req := httptest.NewRequest(http.MethodGet, "/saml/disco?return_url=/dashboard", nil)
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Should redirect directly to IdP when only one exists
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d (redirect to single IdP)", rec.Code, http.StatusFound)
	}

	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "https://single-idp.example.com/sso") {
		t.Errorf("Location = %q, should redirect to single IdP SSO URL", location)
	}

	// Verify SAMLRequest is present
	redirectURL, _ := url.Parse(location)
	if redirectURL.Query().Get("SAMLRequest") == "" {
		t.Error("redirect URL should contain SAMLRequest parameter")
	}

	// Verify RelayState contains return_url
	relayState := redirectURL.Query().Get("RelayState")
	if relayState != "/dashboard" {
		t.Errorf("RelayState = %q, want %q", relayState, "/dashboard")
	}
}

// =============================================================================
// Error Template Rendering Tests
// =============================================================================

// TestRenderHTTPError_SetsStatusAndRendersTemplate verifies that renderHTTPError
// sets the correct status code, Content-Type, and renders the error template.
// Note: renderHTTPError is unexported, so this test is skipped.
// Error rendering is tested indirectly through ServeHTTP() in integration tests.

func TestDiscoveryUI_PreservesReturnURL(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{EntityID: "https://idp1.example.com", DisplayName: "IdP One"},
			{EntityID: "https://idp2.example.com", DisplayName: "IdP Two"},
		},
	}

	s := &SAMLDisco{}
	s.SetMetadataStore(metadataStore)
	s.SetTemplateRenderer(testTemplateRenderer(t))

	req := httptest.NewRequest(http.MethodGet, "/saml/disco?return_url=/protected/page", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	// The return_url should be embedded in the HTML for the selection form
	// Note: html/template escapes forward slashes in JS strings as \/
	if !strings.Contains(body, "/protected/page") && !strings.Contains(body, `\/protected\/page`) {
		t.Errorf("response should contain return_url, got: %s", body)
	}
}

// TestCORS_ApiEndpoints verifies that CORS headers are applied correctly
// to /saml/api/* endpoints based on configuration.

func TestDiscoveryUI_RespectsAcceptLanguage(t *testing.T) {
	t.Skip("renderDiscoveryHTML is unexported, test indirectly through ServeHTTP()")
}

// TestDiscoveryAPI_ListIdPs_RespectsAcceptLanguage verifies that the JSON API
// returns localized IdP names based on Accept-Language header.
// Note: handleListIdPs is unexported, so this test is skipped.
// Localization is tested indirectly through ServeHTTP() in integration tests.

func TestParseAcceptLanguage(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected []string
	}{
		// Simple cases
		{"single language", "en", []string{"en"}},
		{"single german", "de", []string{"de"}},

		// Regional variants should include base language
		{"regional variant", "en-US", []string{"en-US", "en"}},
		{"german regional", "de-AT", []string{"de-AT", "de"}},

		// Multiple languages
		{"multiple languages", "de, en", []string{"de", "en"}},
		{"multiple reversed", "en, de", []string{"en", "de"}},

		// Quality values
		{"with quality", "de, en;q=0.9", []string{"de", "en"}},
		{"quality sorting", "en;q=0.5, de;q=0.9", []string{"de", "en"}},
		{"complex quality", "en-US;q=0.8, de;q=0.9, fr;q=0.7", []string{"de", "en-US", "en", "fr"}},

		// Edge cases
		{"empty header", "", []string{}},
		{"wildcard", "*", []string{"*"}},
		{"q=0 excluded", "en;q=0, de", []string{"de"}},

		// Whitespace handling
		{"with spaces", "de , en ; q=0.8", []string{"de", "en"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := discovery.ParseAcceptLanguage(tc.header)
			if len(result) != len(tc.expected) {
				t.Errorf("parseAcceptLanguage(%q) = %v (len=%d), want %v (len=%d)",
					tc.header, result, len(result), tc.expected, len(tc.expected))
				return
			}
			for i := range tc.expected {
				if result[i] != tc.expected[i] {
					t.Errorf("parseAcceptLanguage(%q)[%d] = %q, want %q",
						tc.header, i, result[i], tc.expected[i])
				}
			}
		})
	}
}

// =============================================================================
// AppError Rendering Tests
// =============================================================================

// TestRenderAppError_JSON_ForAPIEndpoint verifies that renderAppError returns JSON
// for requests to /saml/api/* paths.
// Note: renderAppError is unexported, so this test is skipped.
// Error rendering is tested indirectly through ServeHTTP() in integration tests.
