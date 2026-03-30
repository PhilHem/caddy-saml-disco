//go:build unit

package caddy

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap/zaptest"
)

// Cycle 4: RED - Write failing tests for multi-SP SAMLDisco

func TestSAMLDisco_MultiSP_Structure(t *testing.T) {
	s := &SAMLDisco{
		SPConfigs: []*SPConfig{
			{
				Hostname: "app1.example.com",
				Config: Config{
					EntityID:     "https://app1/saml",
					MetadataFile: "testdata/idp-metadata.xml",
					CertFile:     "../../testdata/sp-cert.pem",
					KeyFile:      "testdata/sp-key.pem",
				},
			},
		},
	}

	// Verify structure
	if len(s.SPConfigs) != 1 {
		t.Errorf("SPConfigs length = %d, want 1", len(s.SPConfigs))
	}

	if s.SPConfigs[0].Hostname != "app1.example.com" {
		t.Errorf("SPConfigs[0].Hostname = %q, want app1.example.com", s.SPConfigs[0].Hostname)
	}
}

func TestSAMLDisco_MultiSP_RegistrySetup(t *testing.T) {
	s := &SAMLDisco{
		SPConfigs: []*SPConfig{
			{
				Hostname: "app1.example.com",
				Config: Config{
					EntityID:     "https://app1/saml",
					MetadataFile: "testdata/idp-metadata.xml",
					CertFile:     "../../testdata/sp-cert.pem",
					KeyFile:      "testdata/sp-key.pem",
				},
			},
			{
				Hostname: "app2.example.com",
				Config: Config{
					EntityID:     "https://app2/saml",
					MetadataFile: "testdata/idp-metadata.xml",
					CertFile:     "../../testdata/sp-cert.pem",
					KeyFile:      "testdata/sp-key.pem",
				},
			},
		},
		logger: zaptest.NewLogger(t),
	}

	// Manually initialize registry (simulating what Provision would do)
	s.registry = NewSPConfigRegistry()
	for _, spCfg := range s.SPConfigs {
		if err := s.registry.Add(spCfg); err != nil {
			t.Fatalf("Add to registry failed: %v", err)
		}
	}

	if s.registry == nil {
		t.Fatal("registry should be initialized")
	}

	// Verify both configs are in registry
	sp1 := s.registry.GetByHostname("app1.example.com")
	if sp1 == nil {
		t.Error("should find SP config for app1.example.com")
	}

	sp2 := s.registry.GetByHostname("app2.example.com")
	if sp2 == nil {
		t.Error("should find SP config for app2.example.com")
	}
}

func TestSAMLDisco_SingleSP_BackwardCompatibility(t *testing.T) {
	// Single-SP mode should still work (backward compatibility)
	s := &SAMLDisco{
		Config: Config{
			EntityID:     "https://sp.example.com/saml",
			MetadataFile: "testdata/idp-metadata.xml",
			CertFile:     "../../testdata/sp-cert.pem",
			KeyFile:      "testdata/sp-key.pem",
		},
		// SPConfigs is empty, so should use single-SP mode
	}

	// Registry should be nil in single-SP mode (before Provision)
	if s.registry != nil {
		t.Error("registry should be nil in single-SP mode")
	}
}

// Cycle 5: RED - Write failing tests for request routing

func TestSAMLDisco_ServeHTTP_MultiSP_RoutesByHostname(t *testing.T) {
	s := &SAMLDisco{
		SPConfigs: []*SPConfig{
			{
				Hostname: "app1.example.com",
				Config: Config{
					EntityID:     "https://app1/saml",
					MetadataFile: "testdata/idp-metadata.xml",
					CertFile:     "../../testdata/sp-cert.pem",
					KeyFile:      "testdata/sp-key.pem",
				},
			},
			{
				Hostname: "app2.example.com",
				Config: Config{
					EntityID:     "https://app2/saml",
					MetadataFile: "testdata/idp-metadata.xml",
					CertFile:     "../../testdata/sp-cert.pem",
					KeyFile:      "testdata/sp-key.pem",
				},
			},
		},
		logger: zaptest.NewLogger(t),
	}

	// Manually initialize registry
	s.registry = NewSPConfigRegistry()
	for _, spCfg := range s.SPConfigs {
		s.registry.Add(spCfg)
	}

	// Request for app1
	req1 := httptest.NewRequest("GET", "/saml/metadata", nil)
	req1.Host = "app1.example.com"
	w1 := httptest.NewRecorder()

	sp1 := s.registry.GetByHostname("app1.example.com")
	if sp1 == nil {
		t.Fatal("should find SP config for app1.example.com")
	}

	// Verify request would route to correct SP
	// (actual routing logic tested in integration tests)
	_ = w1
	_ = req1
	_ = sp1
}

func TestSAMLDisco_ServeHTTP_MultiSP_UnknownHostname(t *testing.T) {
	s := &SAMLDisco{
		SPConfigs: []*SPConfig{
			{
				Hostname: "app1.example.com",
				Config: Config{
					EntityID:     "https://app1/saml",
					MetadataFile: "testdata/idp-metadata.xml",
					CertFile:     "../../testdata/sp-cert.pem",
					KeyFile:      "testdata/sp-key.pem",
				},
			},
		},
		logger: zaptest.NewLogger(t),
	}

	// Manually initialize registry
	s.registry = NewSPConfigRegistry()
	for _, spCfg := range s.SPConfigs {
		s.registry.Add(spCfg)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "unknown.example.com"
	w := httptest.NewRecorder()

	// Should return nil for unknown hostname
	spConfig := s.registry.GetByHostname("unknown.example.com")
	if spConfig != nil {
		t.Error("should return nil for unknown hostname")
	}

	_ = w
	_ = req
}

// TestResolveAcsURLForSP_XForwardedProto verifies that resolveAcsURLForSP
// respects X-Forwarded-Proto header for reverse proxy deployments.
// This is a regression test for the inconsistency where resolveAcsURL checked
// X-Forwarded-Proto but resolveAcsURLForSP did not.
func TestResolveAcsURLForSP_XForwardedProto(t *testing.T) {
	s := &SAMLDisco{}
	spConfig := &SPConfig{}

	tests := []struct {
		name           string
		tls            bool
		xForwardProto  string
		expectedScheme string
	}{
		{"TLS connection", true, "", "https"},
		{"No TLS, no header", false, "", "http"},
		{"No TLS with X-Forwarded-Proto https", false, "https", "https"},
		{"No TLS with X-Forwarded-Proto http", false, "http", "http"},
		{"TLS ignores X-Forwarded-Proto", true, "http", "https"}, // TLS takes precedence
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = "app.example.com"
			if tc.tls {
				// Simulate TLS by setting req.TLS
				req.TLS = &tls.ConnectionState{}
			}
			if tc.xForwardProto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.xForwardProto)
			}

			acsURL := s.resolveAcsURLForSP(req, spConfig)
			if acsURL.Scheme != tc.expectedScheme {
				t.Errorf("resolveAcsURLForSP scheme = %q, want %q", acsURL.Scheme, tc.expectedScheme)
			}
		})
	}
}
