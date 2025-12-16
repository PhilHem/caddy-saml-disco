//go:build unit

package caddysamldisco

import (
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestExampleCaddyfileIsValid(t *testing.T) {
	// Read the example Caddyfile
	content, err := os.ReadFile("examples/Caddyfile")
	if err != nil {
		t.Fatalf("failed to read examples/Caddyfile: %v", err)
	}

	// Verify the example contains session_duration directive
	if !strings.Contains(string(content), "session_duration") {
		t.Error("example Caddyfile should contain session_duration directive")
	}
}

func TestCaddyfile_DiscoveryTemplate(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		discovery_template fels
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if s.DiscoveryTemplate != "fels" {
		t.Errorf("DiscoveryTemplate = %q, want %q", s.DiscoveryTemplate, "fels")
	}
}

func TestCaddyfile_ForceAuthn(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		force_authn
		force_authn_paths /admin/* /settings/security
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if !s.ForceAuthn {
		t.Error("ForceAuthn should be true")
	}
	if len(s.ForceAuthnPaths) != 2 {
		t.Errorf("ForceAuthnPaths = %v, want 2 paths", s.ForceAuthnPaths)
	}
	if s.ForceAuthnPaths[0] != "/admin/*" {
		t.Errorf("ForceAuthnPaths[0] = %q, want %q", s.ForceAuthnPaths[0], "/admin/*")
	}
	if s.ForceAuthnPaths[1] != "/settings/security" {
		t.Errorf("ForceAuthnPaths[1] = %q, want %q", s.ForceAuthnPaths[1], "/settings/security")
	}
}

func TestCaddyfile_AuthnContext(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		sp_key testdata/sp-key.pem
		sp_cert testdata/sp-cert.pem
		metadata_url https://idp.example.com/metadata
		authn_context urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract
		authn_context_comparison exact
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if len(s.AuthnContext) != 1 {
		t.Errorf("AuthnContext = %v, want 1 entry", s.AuthnContext)
	}
	if s.AuthnContext[0] != "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract" {
		t.Errorf("AuthnContext[0] = %q, want %q", s.AuthnContext[0], "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract")
	}
	if s.AuthnContextComparison != "exact" {
		t.Errorf("AuthnContextComparison = %q, want exact", s.AuthnContextComparison)
	}
}

func TestCaddyfile_ServiceName(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		service_name "My Research Portal"
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if s.ServiceName != "My Research Portal" {
		t.Errorf("ServiceName = %q, want %q", s.ServiceName, "My Research Portal")
	}
}

func TestCaddyfile_PinnedIdPs(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		pinned_idps https://idp1.edu https://idp2.edu https://idp3.edu
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if len(s.PinnedIdPs) != 3 {
		t.Fatalf("PinnedIdPs length = %d, want 3", len(s.PinnedIdPs))
	}
	want := []string{"https://idp1.edu", "https://idp2.edu", "https://idp3.edu"}
	for i, v := range want {
		if s.PinnedIdPs[i] != v {
			t.Errorf("PinnedIdPs[%d] = %q, want %q", i, s.PinnedIdPs[i], v)
		}
	}
}

func TestCaddyfile_AltLogin(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		alt_login /local "Local Account"
		alt_login /guest "Guest Access"
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if len(s.AltLogins) != 2 {
		t.Fatalf("AltLogins length = %d, want 2", len(s.AltLogins))
	}
	if s.AltLogins[0].URL != "/local" {
		t.Errorf("AltLogins[0].URL = %q, want %q", s.AltLogins[0].URL, "/local")
	}
	if s.AltLogins[0].Label != "Local Account" {
		t.Errorf("AltLogins[0].Label = %q, want %q", s.AltLogins[0].Label, "Local Account")
	}
	if s.AltLogins[1].URL != "/guest" {
		t.Errorf("AltLogins[1].URL = %q, want %q", s.AltLogins[1].URL, "/guest")
	}
}

func TestCaddyfile_CORSOrigins_Single(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		cors_origins https://app.example.com
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if len(s.CORSAllowedOrigins) != 1 {
		t.Fatalf("CORSAllowedOrigins length = %d, want 1", len(s.CORSAllowedOrigins))
	}
	if s.CORSAllowedOrigins[0] != "https://app.example.com" {
		t.Errorf("CORSAllowedOrigins[0] = %q, want %q", s.CORSAllowedOrigins[0], "https://app.example.com")
	}
}

func TestCaddyfile_CORSOrigins_Multiple(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		cors_origins https://a.com https://b.com https://c.com
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if len(s.CORSAllowedOrigins) != 3 {
		t.Fatalf("CORSAllowedOrigins length = %d, want 3", len(s.CORSAllowedOrigins))
	}
	want := []string{"https://a.com", "https://b.com", "https://c.com"}
	for i, v := range want {
		if s.CORSAllowedOrigins[i] != v {
			t.Errorf("CORSAllowedOrigins[%d] = %q, want %q", i, s.CORSAllowedOrigins[i], v)
		}
	}
}

func TestCaddyfile_CORSOrigins_Wildcard(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		cors_origins *
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if len(s.CORSAllowedOrigins) != 1 {
		t.Fatalf("CORSAllowedOrigins length = %d, want 1", len(s.CORSAllowedOrigins))
	}
	if s.CORSAllowedOrigins[0] != "*" {
		t.Errorf("CORSAllowedOrigins[0] = %q, want %q", s.CORSAllowedOrigins[0], "*")
	}
}

func TestCaddyfile_CORSAllowCredentials(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		cors_origins https://app.example.com
		cors_allow_credentials
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if !s.CORSAllowCredentials {
		t.Error("CORSAllowCredentials = false, want true")
	}
}

func TestCaddyfile_CORSOrigins_Empty_Error(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		cors_origins
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err == nil {
		t.Error("UnmarshalCaddyfile should error on empty cors_origins")
	}
}

func TestCaddyfile_DefaultLanguage(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		default_language de
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if s.DefaultLanguage != "de" {
		t.Errorf("DefaultLanguage = %q, want %q", s.DefaultLanguage, "de")
	}
}

func TestCaddyfile_DefaultLanguage_NotSet(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	// Empty string means "en" will be used at runtime
	if s.DefaultLanguage != "" {
		t.Errorf("DefaultLanguage = %q, want empty (defaults to 'en' at runtime)", s.DefaultLanguage)
	}
}

func TestCaddyfile_VerifyMetadataSignature(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		verify_metadata_signature
		metadata_signing_cert /path/to/cert.pem
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if !s.VerifyMetadataSignature {
		t.Error("VerifyMetadataSignature = false, want true")
	}
	if s.MetadataSigningCert != "/path/to/cert.pem" {
		t.Errorf("MetadataSigningCert = %q, want %q", s.MetadataSigningCert, "/path/to/cert.pem")
	}
}

func TestCaddyfile_MetadataSigningCert_RequiresArg(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		metadata_signing_cert
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err == nil {
		t.Error("UnmarshalCaddyfile should error on metadata_signing_cert without argument")
	}
}

func TestCaddyfile_BackgroundRefresh(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_url https://federation.example.com/metadata.xml
		background_refresh
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if !s.BackgroundRefresh {
		t.Error("BackgroundRefresh = false, want true")
	}
}

func TestCaddyfile_MetricsEnabled(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		metrics enabled
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if !s.MetricsEnabled {
		t.Error("MetricsEnabled = false, want true")
	}
}

func TestCaddyfile_MetricsDisabled(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		metrics off
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if s.MetricsEnabled {
		t.Error("MetricsEnabled = true, want false")
	}
}

func TestCaddyfile_MetricsDefault(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	// Default should be disabled
	if s.MetricsEnabled {
		t.Error("MetricsEnabled should default to false")
	}
}

func TestCaddyfile_SignMetadata(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		cert_file /path/to/cert.pem
		key_file /path/to/key.pem
		sign_metadata
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if !s.SignMetadata {
		t.Error("SignMetadata = false, want true")
	}
}

func TestCaddyfile_SignMetadata_Default(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	// Default should be disabled
	if s.SignMetadata {
		t.Error("SignMetadata should default to false")
	}
}

func TestCaddyfile_HeaderPrefix(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		header_prefix "X-Saml-"
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if s.HeaderPrefix != "X-Saml-" {
		t.Errorf("HeaderPrefix = %q, want %q", s.HeaderPrefix, "X-Saml-")
	}
}

func TestCaddyfile_HeaderPrefix_RequiresArg(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		header_prefix
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err == nil {
		t.Error("UnmarshalCaddyfile should error on header_prefix without argument")
	}
}

func TestCaddyfile_HeaderPrefix_Default(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	// Default should be empty string
	if s.HeaderPrefix != "" {
		t.Errorf("HeaderPrefix = %q, want empty string", s.HeaderPrefix)
	}
}
