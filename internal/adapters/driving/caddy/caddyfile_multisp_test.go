//go:build unit

package caddy

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// Cycle 8: RED - Write failing tests for Caddyfile parsing

func TestCaddyfile_MultiSP_ParseNestedBlocks(t *testing.T) {
	input := `saml_disco {
		sp app1.example.com {
			entity_id https://app1/saml
			metadata_file /path/to/metadata1.xml
			cert_file /path/to/cert1.pem
			key_file /path/to/key1.pem
			session_cookie_name app1_session
		}
		sp app2.example.com {
			entity_id https://app2/saml
			metadata_file /path/to/metadata2.xml
			cert_file /path/to/cert2.pem
			key_file /path/to/key2.pem
			session_cookie_name app2_session
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if len(s.SPConfigs) != 2 {
		t.Fatalf("SPConfigs length = %d, want 2", len(s.SPConfigs))
	}

	if s.SPConfigs[0].Hostname != "app1.example.com" {
		t.Errorf("SPConfigs[0].Hostname = %q, want app1.example.com", s.SPConfigs[0].Hostname)
	}

	if s.SPConfigs[0].EntityID != "https://app1/saml" {
		t.Errorf("SPConfigs[0].EntityID = %q, want https://app1/saml", s.SPConfigs[0].EntityID)
	}

	if s.SPConfigs[0].SessionCookieName != "app1_session" {
		t.Errorf("SPConfigs[0].SessionCookieName = %q, want app1_session", s.SPConfigs[0].SessionCookieName)
	}

	if s.SPConfigs[1].Hostname != "app2.example.com" {
		t.Errorf("SPConfigs[1].Hostname = %q, want app2.example.com", s.SPConfigs[1].Hostname)
	}

	if s.SPConfigs[1].EntityID != "https://app2/saml" {
		t.Errorf("SPConfigs[1].EntityID = %q, want https://app2/saml", s.SPConfigs[1].EntityID)
	}
}

func TestCaddyfile_MultiSP_BackwardCompatibility(t *testing.T) {
	// Single-SP mode should still work
	input := `saml_disco {
		entity_id https://sp.example.com/saml
		metadata_file /path/to/metadata.xml
		cert_file /path/to/cert.pem
		key_file /path/to/key.pem
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if len(s.SPConfigs) != 0 {
		t.Errorf("SPConfigs length = %d, want 0 (single-SP mode)", len(s.SPConfigs))
	}

	if s.EntityID != "https://sp.example.com/saml" {
		t.Errorf("EntityID = %q, want https://sp.example.com/saml", s.EntityID)
	}
}
