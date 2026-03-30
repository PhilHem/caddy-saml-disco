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

func TestCaddyfile_MultiSP_RememberIdP(t *testing.T) {
	input := `saml_disco {
		sp app.example.com {
			entity_id https://app/saml
			metadata_file /path/to/metadata.xml
			remember_idp_cookie_name app_remember
			remember_idp_duration 90d
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if len(s.SPConfigs) != 1 {
		t.Fatalf("SPConfigs length = %d, want 1", len(s.SPConfigs))
	}

	if s.SPConfigs[0].RememberIdPCookieName != "app_remember" {
		t.Errorf("SPConfigs[0].RememberIdPCookieName = %q, want app_remember", s.SPConfigs[0].RememberIdPCookieName)
	}

	if s.SPConfigs[0].RememberIdPDuration != "90d" {
		t.Errorf("SPConfigs[0].RememberIdPDuration = %q, want 90d", s.SPConfigs[0].RememberIdPDuration)
	}
}

func TestCaddyfile_MultiSP_Entitlements(t *testing.T) {
	input := `saml_disco {
		sp app.example.com {
			entity_id https://app/saml
			metadata_file /path/to/metadata.xml
			entitlements_file /path/to/entitlements.json
			entitlements_refresh_interval 10m
			require_entitlement admin
			entitlement_deny_redirect /access-denied
			entitlement_headers {
				roles X-User-Roles
				department X-User-Dept
			}
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if len(s.SPConfigs) != 1 {
		t.Fatalf("SPConfigs length = %d, want 1", len(s.SPConfigs))
	}

	sp := s.SPConfigs[0]

	if sp.EntitlementsFile != "/path/to/entitlements.json" {
		t.Errorf("EntitlementsFile = %q, want /path/to/entitlements.json", sp.EntitlementsFile)
	}

	if sp.EntitlementsRefreshInterval != "10m" {
		t.Errorf("EntitlementsRefreshInterval = %q, want 10m", sp.EntitlementsRefreshInterval)
	}

	if sp.RequireEntitlement != "admin" {
		t.Errorf("RequireEntitlement = %q, want admin", sp.RequireEntitlement)
	}

	if sp.EntitlementDenyRedirect != "/access-denied" {
		t.Errorf("EntitlementDenyRedirect = %q, want /access-denied", sp.EntitlementDenyRedirect)
	}

	if len(sp.EntitlementHeaders) != 2 {
		t.Fatalf("EntitlementHeaders length = %d, want 2", len(sp.EntitlementHeaders))
	}

	if sp.EntitlementHeaders[0].Field != "roles" || sp.EntitlementHeaders[0].HeaderName != "X-User-Roles" {
		t.Errorf("EntitlementHeaders[0] = %+v, want roles->X-User-Roles", sp.EntitlementHeaders[0])
	}
}
