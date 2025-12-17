//go:build unit

package caddy

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseCaddyfile_Entitlements(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /etc/metadata.xml
		cert_file /etc/cert.pem
		key_file /etc/key.pem
		entitlements_file /etc/entitlements.json
		entitlement_headers {
			roles X-Entitlement-Roles
			department X-Department
		}
		require_entitlement admin
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if s.EntitlementsFile != "/etc/entitlements.json" {
		t.Errorf("EntitlementsFile = %q, want /etc/entitlements.json", s.EntitlementsFile)
	}

	if len(s.EntitlementHeaders) != 2 {
		t.Fatalf("EntitlementHeaders length = %d, want 2", len(s.EntitlementHeaders))
	}

	if s.EntitlementHeaders[0].Field != "roles" {
		t.Errorf("EntitlementHeaders[0].Field = %q, want roles", s.EntitlementHeaders[0].Field)
	}
	if s.EntitlementHeaders[0].HeaderName != "X-Entitlement-Roles" {
		t.Errorf("EntitlementHeaders[0].HeaderName = %q, want X-Entitlement-Roles", s.EntitlementHeaders[0].HeaderName)
	}

	if s.RequireEntitlement != "admin" {
		t.Errorf("RequireEntitlement = %q, want admin", s.RequireEntitlement)
	}
}

func TestConfig_Validate_Entitlements(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid with entitlements file",
			cfg: Config{
				EntityID:           "https://sp.example.com",
				MetadataFile:       "/etc/metadata.xml",
				EntitlementsFile:   "/etc/entitlements.json",
				RequireEntitlement: "admin",
			},
			wantErr: false,
		},
		{
			name: "require_entitlement without entitlements_file",
			cfg: Config{
				EntityID:           "https://sp.example.com",
				MetadataFile:       "/etc/metadata.xml",
				RequireEntitlement: "admin",
			},
			wantErr: true,
		},
		{
			name: "valid entitlement headers",
			cfg: Config{
				EntityID:         "https://sp.example.com",
				MetadataFile:     "/etc/metadata.xml",
				EntitlementsFile: "/etc/entitlements.json",
				EntitlementHeaders: []EntitlementHeaderMapping{
					{Field: "roles", HeaderName: "X-Entitlement-Roles"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid entitlement header name",
			cfg: Config{
				EntityID:         "https://sp.example.com",
				MetadataFile:     "/etc/metadata.xml",
				EntitlementsFile: "/etc/entitlements.json",
				EntitlementHeaders: []EntitlementHeaderMapping{
					{Field: "roles", HeaderName: "Invalid-Header"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}



