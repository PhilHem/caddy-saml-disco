package caddysamldisco

import "testing"

func TestConfig_RememberIdP_Defaults(t *testing.T) {
	cfg := &Config{}
	cfg.SetDefaults()

	if cfg.RememberIdPCookieName != "saml_last_idp" {
		t.Errorf("RememberIdPCookieName = %q, want %q", cfg.RememberIdPCookieName, "saml_last_idp")
	}
	if cfg.RememberIdPDuration != "30d" {
		t.Errorf("RememberIdPDuration = %q, want %q", cfg.RememberIdPDuration, "30d")
	}
}

func TestConfig_ForceAuthn_Default(t *testing.T) {
	cfg := &Config{}
	cfg.SetDefaults()

	if cfg.ForceAuthn {
		t.Error("ForceAuthn should default to false")
	}
}

func TestConfig_ForceAuthnPaths_Default(t *testing.T) {
	cfg := &Config{}
	cfg.SetDefaults()

	if cfg.ForceAuthnPaths != nil && len(cfg.ForceAuthnPaths) != 0 {
		t.Errorf("ForceAuthnPaths should default to empty, got %v", cfg.ForceAuthnPaths)
	}
}

func TestConfig_DiscoveryTemplate_FieldExists(t *testing.T) {
	cfg := &Config{
		DiscoveryTemplate: "fels",
	}
	if cfg.DiscoveryTemplate != "fels" {
		t.Errorf("DiscoveryTemplate = %q, want %q", cfg.DiscoveryTemplate, "fels")
	}
}

func TestConfig_DiscoveryTemplate_DefaultsToEmpty(t *testing.T) {
	cfg := &Config{}
	cfg.SetDefaults()
	// DiscoveryTemplate should default to empty string (use default template)
	if cfg.DiscoveryTemplate != "" {
		t.Errorf("DiscoveryTemplate = %q, want empty string", cfg.DiscoveryTemplate)
	}
}

func TestConfig_ServiceName_FieldExists(t *testing.T) {
	cfg := &Config{
		ServiceName: "My Research Portal",
	}
	if cfg.ServiceName != "My Research Portal" {
		t.Errorf("ServiceName = %q, want %q", cfg.ServiceName, "My Research Portal")
	}
}

func TestConfig_PinnedIdPs_FieldExists(t *testing.T) {
	cfg := &Config{
		PinnedIdPs: []string{"https://idp1.edu", "https://idp2.edu"},
	}
	if len(cfg.PinnedIdPs) != 2 {
		t.Errorf("PinnedIdPs length = %d, want 2", len(cfg.PinnedIdPs))
	}
	if cfg.PinnedIdPs[0] != "https://idp1.edu" {
		t.Errorf("PinnedIdPs[0] = %q, want %q", cfg.PinnedIdPs[0], "https://idp1.edu")
	}
}

func TestConfig_AltLogins_FieldExists(t *testing.T) {
	cfg := &Config{
		AltLogins: []AltLoginConfig{
			{URL: "/local", Label: "Local Account"},
			{URL: "/guest", Label: "Guest Access"},
		},
	}
	if len(cfg.AltLogins) != 2 {
		t.Errorf("AltLogins length = %d, want 2", len(cfg.AltLogins))
	}
	if cfg.AltLogins[0].URL != "/local" {
		t.Errorf("AltLogins[0].URL = %q, want %q", cfg.AltLogins[0].URL, "/local")
	}
	if cfg.AltLogins[0].Label != "Local Account" {
		t.Errorf("AltLogins[0].Label = %q, want %q", cfg.AltLogins[0].Label, "Local Account")
	}
}

func TestConfig_CORSValidation(t *testing.T) {
	tests := []struct {
		name        string
		origins     []string
		credentials bool
		wantErr     bool
	}{
		{
			name:    "empty origins is valid",
			origins: nil,
			wantErr: false,
		},
		{
			name:    "wildcard alone is valid",
			origins: []string{"*"},
			wantErr: false,
		},
		{
			name:    "specific origin is valid",
			origins: []string{"https://app.example.com"},
			wantErr: false,
		},
		{
			name:    "multiple origins valid",
			origins: []string{"https://a.com", "https://b.com"},
			wantErr: false,
		},
		{
			name:    "wildcard with others is invalid",
			origins: []string{"*", "https://a.com"},
			wantErr: true,
		},
		{
			name:    "wildcard not first with others is invalid",
			origins: []string{"https://a.com", "*"},
			wantErr: true,
		},
		{
			name:    "http origin is valid",
			origins: []string{"http://localhost:3000"},
			wantErr: false,
		},
		{
			name:        "credentials with specific origin is valid",
			origins:     []string{"https://app.example.com"},
			credentials: true,
			wantErr:     false,
		},
		{
			name:        "credentials with wildcard is invalid",
			origins:     []string{"*"},
			credentials: true,
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				EntityID:             "https://sp.example.com",
				MetadataFile:         "/path/to/metadata.xml",
				CORSAllowedOrigins:   tc.origins,
				CORSAllowCredentials: tc.credentials,
			}

			err := cfg.Validate()

			if tc.wantErr && err == nil {
				t.Error("Validate() returned nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() returned error: %v, want nil", err)
			}
		})
	}
}

func TestConfig_Validate_HeaderPrefixMustStartWithX(t *testing.T) {
	c := &Config{
		EntityID:     "test",
		MetadataFile: "test.xml",
		HeaderPrefix: "Saml-", // Missing X-
		AttributeHeaders: []AttributeMapping{
			{SAMLAttribute: "mail", HeaderName: "User"},
		},
	}
	err := c.Validate()
	if err == nil {
		t.Error("expected error for prefix not starting with X-")
	}
}

func TestConfig_Validate_HeaderPrefixAllowsSimpleNames(t *testing.T) {
	c := &Config{
		EntityID:     "test",
		MetadataFile: "test.xml",
		HeaderPrefix: "X-Saml-",
		AttributeHeaders: []AttributeMapping{
			{SAMLAttribute: "mail", HeaderName: "User"}, // No X- needed
		},
	}
	err := c.Validate()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_HeaderPrefixValidatesFinalName(t *testing.T) {
	c := &Config{
		EntityID:     "test",
		MetadataFile: "test.xml",
		HeaderPrefix: "X-Saml-",
		AttributeHeaders: []AttributeMapping{
			{SAMLAttribute: "mail", HeaderName: "User-Header"}, // Valid when combined
		},
	}
	err := c.Validate()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_HeaderPrefixEmpty_RequiresXPrefix(t *testing.T) {
	// Without prefix, headers must start with X-
	c := &Config{
		EntityID:     "test",
		MetadataFile: "test.xml",
		HeaderPrefix: "", // Empty prefix
		AttributeHeaders: []AttributeMapping{
			{SAMLAttribute: "mail", HeaderName: "User"}, // Missing X- should fail
		},
	}
	err := c.Validate()
	if err == nil {
		t.Error("expected error for header without X- prefix when prefix is empty")
	}
}
