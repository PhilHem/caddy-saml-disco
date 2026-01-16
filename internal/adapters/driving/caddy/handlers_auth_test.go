//go:build unit

package caddy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/session"
)

// TestACSHandler_EmptySAMLResponse_Returns400 verifies that ACS handler returns
// 400 Bad Request when SAMLResponse POST parameter is empty.
func TestACSHandler_EmptySAMLResponse_Returns400(t *testing.T) {
	key := loadTestKey(t)
	cert, err := session.LoadCertificate("../../../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	store := session.NewCookieSessionStore(key, 8*time.Hour)
	samlService := NewSAMLService("https://sp.example.com", key, cert)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
	}
	s.SetSessionStore(store)
	s.SetSAMLService(samlService)

	// Create a metadata store mock with empty IdP list
	s.SetMetadataStore(&mockMetadataStore{idps: nil})

	// Send ACS request with empty SAMLResponse
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	req.PostForm = map[string][]string{
		"SAMLResponse": {""},
	}
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
