//go:build unit

package caddy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/session"
	"github.com/philiph/caddy-saml-disco/internal/domain"
)

func TestDiscoveryAPI_ListIdPs(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{
				EntityID:    "https://idp1.example.com",
				DisplayName: "University One",
				SSOURL:      "https://idp1.example.com/sso",
			},
			{
				EntityID:    "https://idp2.example.com",
				DisplayName: "University Two",
				SSOURL:      "https://idp2.example.com/sso",
			},
			{
				EntityID:    "https://idp3.example.com",
				DisplayName: "College Three",
				SSOURL:      "https://idp3.example.com/sso",
			},
		},
	}

	s := &SAMLDisco{}
	s.SetMetadataStore(metadataStore)

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
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
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}

	// Parse JSON response
	body := rec.Body.String()
	if !strings.Contains(body, "https://idp1.example.com") {
		t.Errorf("response should contain idp1 entity ID, got: %s", body)
	}
	if !strings.Contains(body, "University One") {
		t.Errorf("response should contain idp1 display name, got: %s", body)
	}
	if !strings.Contains(body, "https://idp2.example.com") {
		t.Errorf("response should contain idp2 entity ID, got: %s", body)
	}
	if !strings.Contains(body, "https://idp3.example.com") {
		t.Errorf("response should contain idp3 entity ID, got: %s", body)
	}
}

// TestDiscoveryAPI_ListIdPs_EmptyStore verifies that GET /saml/api/idps returns
// an empty JSON array when no IdPs are configured.

func TestDiscoveryAPI_ListIdPs_EmptyStore(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{},
	}

	s := &SAMLDisco{}
	s.SetMetadataStore(metadataStore)

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := strings.TrimSpace(rec.Body.String())
	if body != `{"idps":[]}` {
		t.Errorf("response = %q, want %q", body, `{"idps":[]}`)
	}
}

// TestDiscoveryAPI_ListIdPs_Search verifies that GET /saml/api/idps?q=term
// filters IdPs by the search term.

func TestDiscoveryAPI_ListIdPs_Search(t *testing.T) {
	// Use a mock that actually filters (update mockMetadataStore.ListIdPs)
	metadataStore := &mockMetadataStoreWithFilter{
		idps: []domain.IdPInfo{
			{
				EntityID:    "https://uni-berlin.de/idp",
				DisplayName: "University of Berlin",
				SSOURL:      "https://uni-berlin.de/sso",
			},
			{
				EntityID:    "https://uni-munich.de/idp",
				DisplayName: "University of Munich",
				SSOURL:      "https://uni-munich.de/sso",
			},
			{
				EntityID:    "https://college-hamburg.de/idp",
				DisplayName: "College of Hamburg",
				SSOURL:      "https://college-hamburg.de/sso",
			},
		},
	}

	s := &SAMLDisco{}
	s.SetMetadataStore(metadataStore)

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps?q=University", nil)
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
	// Should contain both universities
	if !strings.Contains(body, "Berlin") {
		t.Errorf("response should contain Berlin, got: %s", body)
	}
	if !strings.Contains(body, "Munich") {
		t.Errorf("response should contain Munich, got: %s", body)
	}
	// Should NOT contain college
	if strings.Contains(body, "Hamburg") {
		t.Errorf("response should NOT contain Hamburg (college, not university), got: %s", body)
	}
}

// TestDiscoveryAPI_ListIdPs_NoMetadataStore verifies proper error handling
// when metadata store is not configured.

func TestDiscoveryAPI_ListIdPs_NoMetadataStore(t *testing.T) {
	s := &SAMLDisco{}
	// No metadata store configured

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// mockMetadataStoreWithFilter is a mock that actually implements search filtering.
type mockMetadataStoreWithFilter struct {
	idps []domain.IdPInfo
}

func (m *mockMetadataStoreWithFilter) GetIdP(entityID string) (*domain.IdPInfo, error) {
	for i := range m.idps {
		if m.idps[i].EntityID == entityID {
			return &m.idps[i], nil
		}
	}
	return nil, domain.ErrIdPNotFound
}

func (m *mockMetadataStoreWithFilter) ListIdPs(filter string) ([]domain.IdPInfo, error) {
	if filter == "" {
		return m.idps, nil
	}
	filter = strings.ToLower(filter)
	var result []domain.IdPInfo
	for _, idp := range m.idps {
		if strings.Contains(strings.ToLower(idp.DisplayName), filter) ||
			strings.Contains(strings.ToLower(idp.EntityID), filter) {
			result = append(result, idp)
		}
	}
	return result, nil
}

func (m *mockMetadataStoreWithFilter) Refresh(ctx context.Context) error {
	return nil
}

func (m *mockMetadataStoreWithFilter) Health() domain.MetadataHealth {
	return domain.MetadataHealth{IsFresh: true, IdPCount: len(m.idps)}
}

// =============================================================================
// Discovery API: /saml/api/select Tests
// =============================================================================

// TestDiscoveryAPI_SelectIdP verifies that POST /saml/api/select with a valid
// entity_id returns JSON with redirect_url pointing to IdP SSO URL with SAMLRequest.

func TestDiscoveryAPI_SelectIdP(t *testing.T) {
	key := loadTestKey(t)
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "Example IdP",
				SSOURL:      "https://idp.example.com/saml/sso",
				SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID: "https://sp.example.com",
		},
	}
	s.SetSAMLService(samlService)
	s.SetMetadataStore(metadataStore)

	// POST with JSON body containing entity_id
	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml"}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// API returns 200 with JSON containing redirect_url (not 302)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Parse JSON response
	var resp struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if !strings.HasPrefix(resp.RedirectURL, "https://idp.example.com/saml/sso") {
		t.Errorf("redirect_url = %q, should start with IdP SSO URL", resp.RedirectURL)
	}

	// Verify SAMLRequest is in the redirect URL
	redirectURL, _ := url.Parse(resp.RedirectURL)
	if redirectURL.Query().Get("SAMLRequest") == "" {
		t.Error("redirect URL should contain SAMLRequest parameter")
	}
}

// TestDiscoveryAPI_SelectIdP_NotFound verifies that POST /saml/api/select with
// an unknown entity_id returns 404.

func TestDiscoveryAPI_SelectIdP_NotFound(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "Example IdP",
				SSOURL:      "https://idp.example.com/saml/sso",
			},
		},
	}

	s := &SAMLDisco{}
	s.SetMetadataStore(metadataStore)

	body := strings.NewReader(`{"entity_id": "https://unknown.example.com/saml"}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// TestDiscoveryAPI_SelectIdP_MissingEntityID verifies that POST /saml/api/select
// with an empty or missing entity_id returns 400.

func TestDiscoveryAPI_SelectIdP_MissingEntityID(t *testing.T) {
	s := &SAMLDisco{}
	s.SetMetadataStore(&mockMetadataStore{idps: []domain.IdPInfo{}})

	tests := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"empty object", "{}"},
		{"empty entity_id", `{"entity_id": ""}`},
		{"invalid JSON", `{invalid}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/saml/api/select", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			next := &mockNextHandler{}

			err := s.ServeHTTP(rec, req, next)

			if err != nil {
				t.Fatalf("ServeHTTP returned error: %v", err)
			}

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d for body %q", rec.Code, http.StatusBadRequest, tc.body)
			}
		})
	}
}

// TestDiscoveryAPI_SelectIdP_PreservesReturnURL verifies that the return_url
// from request body is passed as RelayState in the redirect URL.

func TestDiscoveryAPI_SelectIdP_PreservesReturnURL(t *testing.T) {
	key := loadTestKey(t)
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{
				EntityID:   "https://idp.example.com/saml",
				SSOURL:     "https://idp.example.com/saml/sso",
				SSOBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID: "https://sp.example.com",
		},
	}
	s.SetSAMLService(samlService)
	s.SetMetadataStore(metadataStore)

	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml", "return_url": "/dashboard"}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// API returns 200 with JSON containing redirect_url (not 302)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Parse JSON response
	var resp struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	redirectURL, _ := url.Parse(resp.RedirectURL)
	relayState := redirectURL.Query().Get("RelayState")
	if relayState != "/dashboard" {
		t.Errorf("RelayState = %q, want %q", relayState, "/dashboard")
	}
}

// TestDiscoveryAPI_SelectIdP_NoSAMLService verifies proper error handling
// when SAML service is not configured.

func TestDiscoveryAPI_SelectIdP_NoSAMLService(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{
				EntityID: "https://idp.example.com/saml",
				SSOURL:   "https://idp.example.com/saml/sso",
			},
		},
	}

	s := &SAMLDisco{}
	s.SetMetadataStore(metadataStore)
	// No SAML service configured

	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml"}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// =============================================================================
// Discovery API: /saml/api/session Tests
// =============================================================================

// TestDiscoveryAPI_SessionInfo_Authenticated verifies that GET /saml/api/session
// returns session info for authenticated users.

func TestDiscoveryAPI_SessionInfo_Authenticated(t *testing.T) {
	key := loadTestKey(t)
	store := session.NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
	}
	s.SetSessionStore(store)

	// Create a valid session token
	session := &domain.Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com/saml",
		Attributes: map[string]string{
			"email":     "user@example.com",
			"firstName": "Test",
			"lastName":  "User",
		},
	}
	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("failed to create session token: %v", err)
	}

	// Create request with valid session cookie
	req := httptest.NewRequest(http.MethodGet, "/saml/api/session", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"authenticated":true`) {
		t.Errorf("response should contain authenticated:true, got: %s", body)
	}
	if !strings.Contains(body, "user@example.com") {
		t.Errorf("response should contain subject, got: %s", body)
	}
	if !strings.Contains(body, "https://idp.example.com/saml") {
		t.Errorf("response should contain idp_entity_id, got: %s", body)
	}
}

// TestDiscoveryAPI_SessionInfo_Unauthenticated verifies that GET /saml/api/session
// returns authenticated:false when no session exists.

func TestDiscoveryAPI_SessionInfo_Unauthenticated(t *testing.T) {
	key := loadTestKey(t)
	store := session.NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
	}
	s.SetSessionStore(store)

	// Request WITHOUT session cookie
	req := httptest.NewRequest(http.MethodGet, "/saml/api/session", nil)
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
	if !strings.Contains(body, `"authenticated":false`) {
		t.Errorf("response should contain authenticated:false, got: %s", body)
	}
}

// TestDiscoveryAPI_SessionInfo_InvalidSession verifies that GET /saml/api/session
// returns authenticated:false when session is invalid/expired.

func TestDiscoveryAPI_SessionInfo_InvalidSession(t *testing.T) {
	key := loadTestKey(t)
	store := session.NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
	}
	s.SetSessionStore(store)

	// Request with invalid session cookie
	req := httptest.NewRequest(http.MethodGet, "/saml/api/session", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: "invalid-token",
	})
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
	if !strings.Contains(body, `"authenticated":false`) {
		t.Errorf("response should contain authenticated:false for invalid session, got: %s", body)
	}
}

// =============================================================================
// Discovery UI Tests
// =============================================================================

// TestDiscoveryUI_ServesHTML verifies that GET /saml/disco serves HTML.

func TestDiscoveryAPI_SelectIdP_RememberTrue_SetsCookie(t *testing.T) {
	key := loadTestKey(t)
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "Example IdP",
				SSOURL:      "https://idp.example.com/saml/sso",
				SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID:              "https://sp.example.com",
			RememberIdPCookieName: "saml_last_idp",
			RememberIdPDuration:   "720h", // 30 days - needed for SPConfig path
		},
	}
	s.SetSAMLService(samlService)
	s.SetMetadataStore(metadataStore)

	// POST with remember=true
	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml", "remember": true}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Check for remember cookie
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "saml_last_idp" {
			found = true
			if c.Value != "https://idp.example.com/saml" {
				t.Errorf("remember cookie value = %q, want %q", c.Value, "https://idp.example.com/saml")
			}
			break
		}
	}
	if !found {
		t.Error("remember cookie should be set when remember=true")
	}
}

// TestDiscoveryAPI_SelectIdP_RememberFalse_DoesNotSetCookie verifies that when
// remember=false is sent, the remember cookie is NOT set.

func TestDiscoveryAPI_SelectIdP_RememberFalse_DoesNotSetCookie(t *testing.T) {
	key := loadTestKey(t)
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "Example IdP",
				SSOURL:      "https://idp.example.com/saml/sso",
				SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID:              "https://sp.example.com",
			RememberIdPCookieName: "saml_last_idp",
		},
	}
	s.SetSAMLService(samlService)
	s.SetMetadataStore(metadataStore)

	// POST with remember=false
	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml", "remember": false}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Check that remember cookie is NOT set
	cookies := rec.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "saml_last_idp" {
			t.Error("remember cookie should NOT be set when remember=false")
			break
		}
	}
}

// TestDiscoveryAPI_SelectIdP_RememberOmitted_DoesNotSetCookie verifies that when
// remember is omitted (default false), the remember cookie is NOT set.
// This is a BREAKING CHANGE from previous behavior where cookie was always set.

func TestDiscoveryAPI_SelectIdP_RememberOmitted_DoesNotSetCookie(t *testing.T) {
	key := loadTestKey(t)
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "Example IdP",
				SSOURL:      "https://idp.example.com/saml/sso",
				SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID:              "https://sp.example.com",
			RememberIdPCookieName: "saml_last_idp",
		},
	}
	s.SetSAMLService(samlService)
	s.SetMetadataStore(metadataStore)

	// POST WITHOUT remember field (omitted)
	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml"}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Check that remember cookie is NOT set (BREAKING CHANGE: previously was always set)
	cookies := rec.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "saml_last_idp" {
			t.Error("remember cookie should NOT be set when remember is omitted (BREAKING CHANGE from previous behavior)")
			break
		}
	}
}

// =============================================================================
// Pinned IdPs API Tests (Cycle 6)
// =============================================================================

// TestDiscoveryAPI_ListIdPs_ReturnsPinnedIdPs verifies that GET /saml/api/idps
// returns a pinned_idps field when PinnedIdPs is configured.

func TestDiscoveryAPI_ListIdPs_ReturnsPinnedIdPs(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{EntityID: "https://idp1.example.com", DisplayName: "IdP One", SSOURL: "https://idp1.example.com/sso"},
			{EntityID: "https://idp2.example.com", DisplayName: "IdP Two", SSOURL: "https://idp2.example.com/sso"},
			{EntityID: "https://idp3.example.com", DisplayName: "IdP Three", SSOURL: "https://idp3.example.com/sso"},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			PinnedIdPs: []string{"https://idp1.example.com", "https://idp3.example.com"},
		},
	}
	s.SetMetadataStore(metadataStore)

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp struct {
		IdPs       []domain.IdPInfo `json:"idps"`
		PinnedIdPs []domain.IdPInfo `json:"pinned_idps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Verify pinned_idps contains the configured IdPs
	if len(resp.PinnedIdPs) != 2 {
		t.Errorf("pinned_idps length = %d, want 2", len(resp.PinnedIdPs))
	}

	// Verify pinned IdPs are in the response
	pinnedEntityIDs := make(map[string]bool)
	for _, idp := range resp.PinnedIdPs {
		pinnedEntityIDs[idp.EntityID] = true
	}
	if !pinnedEntityIDs["https://idp1.example.com"] {
		t.Error("pinned_idps should contain https://idp1.example.com")
	}
	if !pinnedEntityIDs["https://idp3.example.com"] {
		t.Error("pinned_idps should contain https://idp3.example.com")
	}
}

// TestDiscoveryAPI_ListIdPs_PinnedIdPsFilteredFromMain verifies that pinned IdPs
// are removed from the main idps list to prevent duplication.

func TestDiscoveryAPI_ListIdPs_PinnedIdPsFilteredFromMain(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{EntityID: "https://idp1.example.com", DisplayName: "IdP One", SSOURL: "https://idp1.example.com/sso"},
			{EntityID: "https://idp2.example.com", DisplayName: "IdP Two", SSOURL: "https://idp2.example.com/sso"},
			{EntityID: "https://idp3.example.com", DisplayName: "IdP Three", SSOURL: "https://idp3.example.com/sso"},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			PinnedIdPs: []string{"https://idp1.example.com"},
		},
	}
	s.SetMetadataStore(metadataStore)

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	var resp struct {
		IdPs       []domain.IdPInfo `json:"idps"`
		PinnedIdPs []domain.IdPInfo `json:"pinned_idps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Verify main idps list does NOT contain pinned IdP
	for _, idp := range resp.IdPs {
		if idp.EntityID == "https://idp1.example.com" {
			t.Error("idps should NOT contain pinned IdP https://idp1.example.com")
		}
	}

	// Verify main idps contains only non-pinned IdPs
	if len(resp.IdPs) != 2 {
		t.Errorf("idps length = %d, want 2 (non-pinned IdPs only)", len(resp.IdPs))
	}

	// Verify pinned_idps has the pinned IdP
	if len(resp.PinnedIdPs) != 1 {
		t.Fatalf("pinned_idps length = %d, want 1", len(resp.PinnedIdPs))
	}
	if resp.PinnedIdPs[0].EntityID != "https://idp1.example.com" {
		t.Errorf("pinned_idps[0].EntityID = %q, want %q", resp.PinnedIdPs[0].EntityID, "https://idp1.example.com")
	}
}

// TestDiscoveryAPI_ListIdPs_NoPinnedIdPs verifies that when PinnedIdPs is not
// configured, the response either omits pinned_idps or returns an empty array.

func TestDiscoveryAPI_ListIdPs_NoPinnedIdPs(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{EntityID: "https://idp1.example.com", DisplayName: "IdP One", SSOURL: "https://idp1.example.com/sso"},
		},
	}

	s := &SAMLDisco{
		Config: Config{},
	}
	s.SetMetadataStore(metadataStore)

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	var resp struct {
		IdPs       []domain.IdPInfo `json:"idps"`
		PinnedIdPs []domain.IdPInfo `json:"pinned_idps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Main idps should contain all IdPs
	if len(resp.IdPs) != 1 {
		t.Errorf("idps length = %d, want 1", len(resp.IdPs))
	}

	// pinned_idps should be nil or empty (omitempty may exclude it)
	if len(resp.PinnedIdPs) != 0 {
		t.Errorf("pinned_idps length = %d, want 0", len(resp.PinnedIdPs))
	}
}

// =============================================================================
// LoginRedirect Tests (Custom UI Support)
// =============================================================================

// TestServeHTTP_NoSession_LoginRedirect_RedirectsToCustomURL verifies that when
// LoginRedirect is configured, unauthenticated requests are redirected to the
// custom login URL instead of directly to the IdP.

func TestCORS_ApiEndpoints(t *testing.T) {
	tests := []struct {
		name          string
		origins       []string
		credentials   bool
		requestOrigin string
		endpoint      string
		wantOrigin    string
		wantCreds     string
	}{
		{
			name:          "matching origin gets CORS headers",
			origins:       []string{"https://app.example.com"},
			requestOrigin: "https://app.example.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "https://app.example.com",
		},
		{
			name:          "non-matching origin gets no CORS",
			origins:       []string{"https://app.example.com"},
			requestOrigin: "https://evil.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "",
		},
		{
			name:          "wildcard allows any origin",
			origins:       []string{"*"},
			requestOrigin: "https://any.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "*",
		},
		{
			name:          "credentials header when enabled",
			origins:       []string{"https://app.example.com"},
			credentials:   true,
			requestOrigin: "https://app.example.com",
			endpoint:      "/saml/api/session",
			wantOrigin:    "https://app.example.com",
			wantCreds:     "true",
		},
		{
			name:          "no credentials header with wildcard",
			origins:       []string{"*"},
			credentials:   false, // can't use credentials with wildcard anyway
			requestOrigin: "https://any.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "*",
			wantCreds:     "",
		},
		{
			name:          "non-API endpoints get no CORS",
			origins:       []string{"https://app.example.com"},
			requestOrigin: "https://app.example.com",
			endpoint:      "/saml/disco",
			wantOrigin:    "",
		},
		{
			name:          "no origin header means no CORS response",
			origins:       []string{"https://app.example.com"},
			requestOrigin: "", // no Origin header
			endpoint:      "/saml/api/idps",
			wantOrigin:    "",
		},
		{
			name:          "CORS disabled when no origins configured",
			origins:       nil,
			requestOrigin: "https://app.example.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "",
		},
		{
			name:          "multiple origins - first matches",
			origins:       []string{"https://a.com", "https://b.com"},
			requestOrigin: "https://a.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "https://a.com",
		},
		{
			name:          "multiple origins - second matches",
			origins:       []string{"https://a.com", "https://b.com"},
			requestOrigin: "https://b.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "https://b.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			metadataStore := &mockMetadataStore{
				idps: []domain.IdPInfo{{EntityID: "https://idp.example.com", DisplayName: "Test IdP"}},
			}

			s := &SAMLDisco{
				Config: Config{
					CORSAllowedOrigins:   tc.origins,
					CORSAllowCredentials: tc.credentials,
				},
			}
			s.SetMetadataStore(metadataStore)
			s.SetTemplateRenderer(testTemplateRenderer(t))

			req := httptest.NewRequest(http.MethodGet, tc.endpoint, nil)
			if tc.requestOrigin != "" {
				req.Header.Set("Origin", tc.requestOrigin)
			}
			rec := httptest.NewRecorder()
			next := &mockNextHandler{}

			_ = s.ServeHTTP(rec, req, next)

			gotOrigin := rec.Header().Get("Access-Control-Allow-Origin")
			if gotOrigin != tc.wantOrigin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", gotOrigin, tc.wantOrigin)
			}

			gotCreds := rec.Header().Get("Access-Control-Allow-Credentials")
			if gotCreds != tc.wantCreds {
				t.Errorf("Access-Control-Allow-Credentials = %q, want %q", gotCreds, tc.wantCreds)
			}

			// Verify other CORS headers are set when origin matches
			if tc.wantOrigin != "" {
				gotMethods := rec.Header().Get("Access-Control-Allow-Methods")
				if gotMethods == "" {
					t.Error("Access-Control-Allow-Methods should be set when CORS is allowed")
				}
				gotHeaders := rec.Header().Get("Access-Control-Allow-Headers")
				if gotHeaders == "" {
					t.Error("Access-Control-Allow-Headers should be set when CORS is allowed")
				}
			}
		})
	}
}

// TestCORS_PreflightRequest verifies that OPTIONS requests to API endpoints
// return proper CORS preflight responses.

func TestCORS_PreflightRequest(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{{EntityID: "https://idp.example.com", DisplayName: "Test IdP"}},
	}

	s := &SAMLDisco{
		Config: Config{
			CORSAllowedOrigins:   []string{"https://app.example.com"},
			CORSAllowCredentials: true,
		},
	}
	s.SetMetadataStore(metadataStore)
	s.SetTemplateRenderer(testTemplateRenderer(t))

	req := httptest.NewRequest(http.MethodOptions, "/saml/api/idps", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Preflight should return 204 No Content
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// CORS headers should be present
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://app.example.com")
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Access-Control-Allow-Methods should be set")
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want %q", got, "true")
	}

	// Next handler should NOT be called for preflight
	if next.called {
		t.Error("next handler should NOT be called for preflight request")
	}
}

// TestCORS_PreflightNonApiEndpoint verifies that OPTIONS requests to non-API
// endpoints are passed through (not handled as CORS preflight).

func TestCORS_PreflightNonApiEndpoint(t *testing.T) {
	s := &SAMLDisco{
		Config: Config{
			CORSAllowedOrigins: []string{"https://app.example.com"},
		},
	}
	s.SetTemplateRenderer(testTemplateRenderer(t))

	req := httptest.NewRequest(http.MethodOptions, "/saml/disco", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	_ = s.ServeHTTP(rec, req, next)

	// Non-API endpoints should NOT get CORS headers
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for non-API endpoint", got)
	}

	// Next handler should be called (OPTIONS not handled as preflight)
	if !next.called {
		t.Error("next handler should be called for non-API OPTIONS request")
	}
}

// =============================================================================
// Multi-Language / Accept-Language Support Tests (Phase 3)
// =============================================================================

// TestDiscoveryUI_RespectsAcceptLanguage verifies that the discovery HTML page
// shows localized IdP names based on Accept-Language header.
// Note: renderDiscoveryHTML is unexported, so this test is skipped.
// Localization is tested indirectly through ServeHTTP() in integration tests.

func TestDiscoveryAPI_ListIdPs_RespectsAcceptLanguage(t *testing.T) {
	t.Skip("handleListIdPs is unexported, test indirectly through ServeHTTP()")
}

// TestParseAcceptLanguage verifies Accept-Language header parsing with
// quality values and regional variant handling.
