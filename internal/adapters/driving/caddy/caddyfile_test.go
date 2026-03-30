//go:build unit

package caddy

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// Cycle 2: Test Caddyfile parsing for metadata_url and metadata_file blocks

func TestUnmarshalCaddyfile_MetadataURLBlock(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_url https://federation1.org/metadata.xml {
			idp_filter "*.uni-mannheim.de*"
			refresh_interval 1h
		}
		metadata_url https://federation2.org/metadata.xml {
			idp_filter "*.uni-tuebingen.de*"
		}
		cert_file /etc/cert.pem
		key_file /etc/key.pem
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if len(s.MetadataSources) != 2 {
		t.Fatalf("MetadataSources length = %d, want 2", len(s.MetadataSources))
	}

	// First source
	src1 := s.MetadataSources[0]
	if src1.URL != "https://federation1.org/metadata.xml" {
		t.Errorf("MetadataSources[0].URL = %q, want %q", src1.URL, "https://federation1.org/metadata.xml")
	}
	if src1.IdPFilter != "*.uni-mannheim.de*" {
		t.Errorf("MetadataSources[0].IdPFilter = %q, want %q", src1.IdPFilter, "*.uni-mannheim.de*")
	}
	if src1.RefreshInterval != 1*time.Hour {
		t.Errorf("MetadataSources[0].RefreshInterval = %v, want %v", src1.RefreshInterval, 1*time.Hour)
	}

	// Second source
	src2 := s.MetadataSources[1]
	if src2.URL != "https://federation2.org/metadata.xml" {
		t.Errorf("MetadataSources[1].URL = %q, want %q", src2.URL, "https://federation2.org/metadata.xml")
	}
	if src2.IdPFilter != "*.uni-tuebingen.de*" {
		t.Errorf("MetadataSources[1].IdPFilter = %q, want %q", src2.IdPFilter, "*.uni-tuebingen.de*")
	}
}

func TestUnmarshalCaddyfile_MetadataFileBlock(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/local1.xml {
			idp_filter "*.example.edu"
		}
		metadata_file /path/to/local2.xml
		cert_file /etc/cert.pem
		key_file /etc/key.pem
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if len(s.MetadataSources) != 2 {
		t.Fatalf("MetadataSources length = %d, want 2", len(s.MetadataSources))
	}

	// First file source with block options
	src1 := s.MetadataSources[0]
	if src1.File != "/path/to/local1.xml" {
		t.Errorf("MetadataSources[0].File = %q, want %q", src1.File, "/path/to/local1.xml")
	}
	if src1.IdPFilter != "*.example.edu" {
		t.Errorf("MetadataSources[0].IdPFilter = %q, want %q", src1.IdPFilter, "*.example.edu")
	}

	// Second file source without block (backward compat)
	src2 := s.MetadataSources[1]
	if src2.File != "/path/to/local2.xml" {
		t.Errorf("MetadataSources[1].File = %q, want %q", src2.File, "/path/to/local2.xml")
	}
}

func TestExampleCaddyfileIsValid(t *testing.T) {
	// Read the example Caddyfile
	content, err := os.ReadFile("../../../../examples/Caddyfile")
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
		key_file testdata/sp-key.pem
		cert_file testdata/sp-cert.pem
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

func TestCaddyfile_RememberIdPCookieName(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		remember_idp_cookie_name my_remember_idp
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if s.RememberIdPCookieName != "my_remember_idp" {
		t.Errorf("RememberIdPCookieName = %q, want %q", s.RememberIdPCookieName, "my_remember_idp")
	}
}

func TestCaddyfile_RememberIdPCookieName_RequiresArg(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		remember_idp_cookie_name
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err == nil {
		t.Error("UnmarshalCaddyfile should error on remember_idp_cookie_name without argument")
	}
}

func TestCaddyfile_RememberIdPDuration(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		remember_idp_duration 60d
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if s.RememberIdPDuration != "60d" {
		t.Errorf("RememberIdPDuration = %q, want %q", s.RememberIdPDuration, "60d")
	}
}

func TestCaddyfile_RememberIdPDuration_RequiresArg(t *testing.T) {
	input := `saml_disco {
		entity_id https://sp.example.com
		metadata_file /path/to/metadata.xml
		remember_idp_duration
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err == nil {
		t.Error("UnmarshalCaddyfile should error on remember_idp_duration without argument")
	}
}

func TestCaddyfile_RequestTTL(t *testing.T) {
	input := `saml_disco {
		entity_id https://example.com/saml
		metadata_file /path/to/metadata.xml
		cert_file /path/to/cert.pem
		key_file /path/to/key.pem
		request_ttl 30m
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	if s.RequestTTL != "30m" {
		t.Errorf("RequestTTL = %q, want %q", s.RequestTTL, "30m")
	}
}

func TestCaddyfile_RequestTTL_Default(t *testing.T) {
	input := `saml_disco {
		entity_id https://example.com/saml
		metadata_file /path/to/metadata.xml
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile error: %v", err)
	}

	// SetDefaults is called by UnmarshalCaddyfile; default should be "10m"
	if s.RequestTTL != "10m" {
		t.Errorf("RequestTTL = %q, want %q (default)", s.RequestTTL, "10m")
	}
}

func TestCaddyfile_RequestTTL_RequiresArg(t *testing.T) {
	input := `saml_disco {
		entity_id https://example.com/saml
		metadata_file /path/to/metadata.xml
		request_ttl
	}`

	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	if err == nil {
		t.Error("UnmarshalCaddyfile should error on request_ttl without argument")
	}
}

func TestCaddyfile_InvalidEntityID_RejectsAtParseTime(t *testing.T) {
	// Test that invalid entity_id values are rejected at parse time.
	// Note: Missing entity_id is validated in Config.Validate(), not parse time.
	tests := []struct {
		name     string
		entityID string
		wantErr  string
	}{
		{
			name:     "missing scheme",
			entityID: "sp.example.com/saml",
			wantErr:  "must have a scheme",
		},
		{
			name:     "invalid scheme",
			entityID: "ftp://sp.example.com/saml",
			wantErr:  "scheme must be http, https, or urn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := `saml_disco {
				entity_id ` + tt.entityID + `
				metadata_file /path/to/metadata.xml
			}`

			d := caddyfile.NewTestDispenser(input)
			var s SAMLDisco
			err := s.UnmarshalCaddyfile(d)

			// The test expects errors to be caught at parse time,
			// not deferred to Validate()
			if err == nil {
				t.Errorf("UnmarshalCaddyfile should reject invalid entity_id at parse time")
				return
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
