//go:build integration

package integration

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	caddysamldisco "github.com/philiph/caddy-saml-disco"
	caddyadapter "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/testfixtures/idp"
)

// TestMultiSP_EndToEndFlow tests that multiple SP configs route correctly
// based on hostname and return different metadata.
func TestMultiSP_EndToEndFlow(t *testing.T) {
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
	metadataStore := caddysamldisco.NewInMemoryMetadataStore([]caddysamldisco.IdPInfo{idpInfo})

	// Create session stores for each SP
	sessionStore1 := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)
	sessionStore2 := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	// Create SAML services for each SP
	service1 := caddysamldisco.NewSAMLService("https://app1.example.com/saml", key, cert)
	service2 := caddysamldisco.NewSAMLService("https://app2.example.com/saml", key, cert)

	// Create multi-SP plugin instance
	disco := &caddysamldisco.SAMLDisco{
		SPConfigs: []*caddyadapter.SPConfig{
			{
				Hostname: "app1.example.com",
				Config: caddysamldisco.Config{
					EntityID:          "https://app1.example.com/saml",
					SessionCookieName: "app1_session",
				},
			},
			{
				Hostname: "app2.example.com",
				Config: caddysamldisco.Config{
					EntityID:          "https://app2.example.com/saml",
					SessionCookieName: "app2_session",
				},
			},
		},
	}

	// Manually set up stores for each SP config (simulating Provision)
	disco.SPConfigs[0].SetMetadataStore(metadataStore)
	disco.SPConfigs[0].SetSessionStore(sessionStore1)
	disco.SPConfigs[0].SetSAMLService(service1)

	disco.SPConfigs[1].SetMetadataStore(metadataStore)
	disco.SPConfigs[1].SetSessionStore(sessionStore2)
	disco.SPConfigs[1].SetSAMLService(service2)

	// Manually initialize registry (simulating Provision)
	registry := caddyadapter.NewSPConfigRegistry()
	for _, spCfg := range disco.SPConfigs {
		if err := registry.Add(spCfg); err != nil {
			t.Fatalf("add SP config to registry: %v", err)
		}
	}
	disco.SetRegistry(registry)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Test 1: Verify SP1 metadata endpoint returns correct entity ID
	t.Run("SP1_Metadata_ReturnsCorrectEntityID", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/saml/metadata", nil)
		req.Host = "app1.example.com"

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /saml/metadata: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, _ := io.ReadAll(resp.Body)
		var metadata struct {
			XMLName  xml.Name `xml:"EntityDescriptor"`
			EntityID string   `xml:"entityID,attr"`
		}
		if err := xml.Unmarshal(body, &metadata); err != nil {
			t.Fatalf("parse metadata XML: %v", err)
		}

		if metadata.EntityID != "https://app1.example.com/saml" {
			t.Errorf("EntityID = %q, want %q", metadata.EntityID, "https://app1.example.com/saml")
		}
	})

	// Test 2: Verify SP2 metadata endpoint returns correct entity ID
	t.Run("SP2_Metadata_ReturnsCorrectEntityID", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/saml/metadata", nil)
		req.Host = "app2.example.com"

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /saml/metadata: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, _ := io.ReadAll(resp.Body)
		var metadata struct {
			XMLName  xml.Name `xml:"EntityDescriptor"`
			EntityID string   `xml:"entityID,attr"`
		}
		if err := xml.Unmarshal(body, &metadata); err != nil {
			t.Fatalf("parse metadata XML: %v", err)
		}

		if metadata.EntityID != "https://app2.example.com/saml" {
			t.Errorf("EntityID = %q, want %q", metadata.EntityID, "https://app2.example.com/saml")
		}
	})

	// Test 3: Verify unknown hostname returns 404
	t.Run("UnknownHostname_Returns404", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/saml/metadata", nil)
		req.Host = "unknown.example.com"

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /saml/metadata: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
	})

	// Test 4: Verify IdP list endpoint works for both SPs
	t.Run("BothSPs_ListIdPs_ReturnsIdPs", func(t *testing.T) {
		for _, hostname := range []string{"app1.example.com", "app2.example.com"} {
			req, _ := http.NewRequest("GET", server.URL+"/saml/api/idps", nil)
			req.Host = hostname

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("GET /saml/api/idps for %s: %v", hostname, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("status for %s = %d, want %d", hostname, resp.StatusCode, http.StatusOK)
			}

			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), testIdP.BaseURL()) {
				t.Errorf("response for %s should contain IdP entity ID", hostname)
			}
		}
	})
}

// TestMultiSP_SessionIsolation tests that sessions from one SP are not valid for another SP.
// This verifies that cookie names and session stores are properly isolated.
func TestMultiSP_SessionIsolation(t *testing.T) {
	// Load SP credentials
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	// Create session stores for each SP (with different cookie names)
	sessionStore1 := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)
	sessionStore2 := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	// Create sessions for each SP
	session1 := &caddysamldisco.Session{
		Subject:     "user1@example.com",
		IdPEntityID: "https://idp1.example.com",
		Attributes:  map[string]string{"mail": "user1@example.com"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	session2 := &caddysamldisco.Session{
		Subject:     "user2@example.com",
		IdPEntityID: "https://idp2.example.com",
		Attributes:  map[string]string{"mail": "user2@example.com"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	// Create session tokens
	token1, err := sessionStore1.Create(session1)
	if err != nil {
		t.Fatalf("create session1 token: %v", err)
	}

	token2, err := sessionStore2.Create(session2)
	if err != nil {
		t.Fatalf("create session2 token: %v", err)
	}

	// Create multi-SP plugin instance
	disco := &caddysamldisco.SAMLDisco{
		SPConfigs: []*caddyadapter.SPConfig{
			{
				Hostname: "app1.example.com",
				Config: caddysamldisco.Config{
					EntityID:          "https://app1.example.com/saml",
					SessionCookieName: "app1_session",
				},
			},
			{
				Hostname: "app2.example.com",
				Config: caddysamldisco.Config{
					EntityID:          "https://app2.example.com/saml",
					SessionCookieName: "app2_session",
				},
			},
		},
	}

	// Set up stores for each SP config
	disco.SPConfigs[0].SetSessionStore(sessionStore1)
	disco.SPConfigs[1].SetSessionStore(sessionStore2)

	// Initialize registry
	registry := caddyadapter.NewSPConfigRegistry()
	for _, spCfg := range disco.SPConfigs {
		if err := registry.Add(spCfg); err != nil {
			t.Fatalf("add SP config to registry: %v", err)
		}
	}
	disco.SetRegistry(registry)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Test 1: Session from SP1 should be valid for SP1
	t.Run("SP1_Session_ValidForSP1", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/saml/api/session", nil)
		req.Host = "app1.example.com"
		req.AddCookie(&http.Cookie{
			Name:  "app1_session",
			Value: token1,
		})

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /saml/api/session: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var result struct {
			Authenticated bool   `json:"authenticated"`
			Subject       string `json:"subject"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}

		if !result.Authenticated {
			t.Error("session should be authenticated for SP1")
		}
		if result.Subject != "user1@example.com" {
			t.Errorf("Subject = %q, want %q", result.Subject, "user1@example.com")
		}
	})

	// Test 2: Session from SP1 should NOT be valid for SP2 (different cookie name)
	t.Run("SP1_Session_InvalidForSP2", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/saml/api/session", nil)
		req.Host = "app2.example.com"
		req.AddCookie(&http.Cookie{
			Name:  "app1_session", // Wrong cookie name
			Value: token1,
		})

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /saml/api/session: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var result struct {
			Authenticated bool `json:"authenticated"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}

		if result.Authenticated {
			t.Error("SP1 session should NOT be authenticated for SP2")
		}
	})

	// Test 3: Session from SP2 should be valid for SP2
	t.Run("SP2_Session_ValidForSP2", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/saml/api/session", nil)
		req.Host = "app2.example.com"
		req.AddCookie(&http.Cookie{
			Name:  "app2_session",
			Value: token2,
		})

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /saml/api/session: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var result struct {
			Authenticated bool   `json:"authenticated"`
			Subject       string `json:"subject"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}

		if !result.Authenticated {
			t.Error("session should be authenticated for SP2")
		}
		if result.Subject != "user2@example.com" {
			t.Errorf("Subject = %q, want %q", result.Subject, "user2@example.com")
		}
	})

	// Test 4: Session from SP2 should NOT be valid for SP1
	t.Run("SP2_Session_InvalidForSP1", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/saml/api/session", nil)
		req.Host = "app1.example.com"
		req.AddCookie(&http.Cookie{
			Name:  "app2_session", // Wrong cookie name
			Value: token2,
		})

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /saml/api/session: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var result struct {
			Authenticated bool `json:"authenticated"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}

		if result.Authenticated {
			t.Error("SP2 session should NOT be authenticated for SP1")
		}
	})
}



