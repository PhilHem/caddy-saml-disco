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
