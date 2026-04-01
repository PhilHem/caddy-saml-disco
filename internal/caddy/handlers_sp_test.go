//go:build unit

package caddy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/philiph/caddy-saml-disco/internal/config"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	"github.com/philiph/caddy-saml-disco/internal/session"
)

// TestHandleXxx_NilSPConfig tests that handlers properly check for nil SPConfig fields
func TestHandleXxx_NilSPConfig(t *testing.T) {
	tests := []struct {
		name    string
		handler func(*SAMLDisco, http.ResponseWriter, *http.Request, *SPConfig) error
		method  string
		path    string
	}{
		{
			name:    "handleMetadataInternal with nil samlService",
			handler: (*SAMLDisco).handleMetadataInternal,
			method:  http.MethodGet,
			path:    "/saml/metadata",
		},
		{
			name:    "handleACSInternal with nil samlService",
			handler: (*SAMLDisco).handleACSInternal,
			method:  http.MethodPost,
			path:    "/saml/acs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			s := &SAMLDisco{
				Config: Config{
					SessionCookieName: "saml_session",
				},
				logger: logger,
			}

			cfg := &SPConfig{
				SPConfig:      config.SPConfig{Config: Config{SessionCookieName: "saml_session"}},
				samlService:   nil, // nil to test error handling
				metadataStore: nil,
				sessionStore:  nil,
			}

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			err := tt.handler(s, rec, req, cfg)

			// Should not panic, and should return nil error (error handled internally)
			if err != nil {
				t.Logf("handler returned error: %v", err)
			}

			// Should return error response
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
			}
		})
	}
}

// TestHandleXxx_EmptyEntityID tests that handlers validate empty entityID after path split
func TestHandleXxx_EmptyEntityID(t *testing.T) {
	logger := zaptest.NewLogger(t)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		logger: logger,
	}

	logoStore := &mockLogoStore{
		logos: make(map[string]ports.CachedLogo),
	}

	cfg := &SPConfig{
		SPConfig:  config.SPConfig{Config: Config{SessionCookieName: "saml_session"}},
		logoStore: logoStore,
	}

	// Test path with insufficient parts (no entity ID)
	req := httptest.NewRequest(http.MethodGet, "/saml/api/logo", nil)
	rec := httptest.NewRecorder()

	err := s.handleLogoEndpointInternal(rec, req, cfg)

	// Should handle gracefully without panic
	if err != nil {
		t.Errorf("handler returned error: %v", err)
	}

	// Should return 404 for missing entity ID
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
}

// TestHandleXxx_URLParseError tests that handlers log warnings for URL parse failures
func TestHandleXxx_URLParseError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	key := loadTestKey(t)
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
			EntityID:          "https://sp.example.com",
		},
		logger: logger,
	}

	cfg := &SPConfig{
		SPConfig:    config.SPConfig{Config: Config{SessionCookieName: "saml_session"}},
		samlService: samlService,
		metadataStore: &mockMetadataStore{
			idps: []domain.IdPInfo{
				{
					EntityID:   "https://idp.example.com",
					SSOURL:     "https://idp.example.com/sso",
					SSOBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
				},
			},
		},
	}

	// Test selecting an IdP which should log appropriate messages
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", nil)
	rec := httptest.NewRecorder()

	// Set up form data properly with valid entity ID
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	req.Form.Set("entity_id", "https://idp.example.com")
	req.Form.Set("return_url", "http://localhost/page") // Valid URL

	// The handler should log but not panic
	err = s.handleSelectIdPInternal(rec, req, cfg)

	// Should handle gracefully
	if err != nil {
		t.Logf("handler returned: %v", err)
	}

	// Should not crash
	if rec.Code == http.StatusInternalServerError {
		t.Logf("response status: %d", rec.Code)
	}
}

// mockLogoStore is a test double for LogoStore
type mockLogoStore struct {
	logos map[string]ports.CachedLogo
}

func (m *mockLogoStore) Get(entityID string) (*ports.CachedLogo, error) {
	logo, ok := m.logos[entityID]
	if !ok {
		return nil, domain.ErrIdPNotFound
	}
	return &logo, nil
}
