//go:build unit

package caddy

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func parseDisco(t *testing.T, input string) (*SAMLDisco, error) {
	t.Helper()
	d := caddyfile.NewTestDispenser(input)
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(d)
	return &s, err
}

// TestUnmarshalCaddyfile_GuestPasscode covers parsing of the guest_passcode
// directive: a non-empty value is stored, a present-but-empty value is rejected
// at parse time, and an omitted directive leaves the feature off without error.
func TestUnmarshalCaddyfile_GuestPasscode(t *testing.T) {
	base := func(passcodeLine string) string {
		return `saml_disco {
			entity_id https://sp.example.com
			metadata_url https://federation.org/metadata.xml
			guest_access "Rechtsberatung"
			` + passcodeLine + `
		}`
	}

	t.Run("non-empty value is stored", func(t *testing.T) {
		s, err := parseDisco(t, base(`guest_passcode "my password"`))
		if err != nil {
			t.Fatalf("UnmarshalCaddyfile() error = %v", err)
		}
		if s.GuestPasscode != "my password" {
			t.Errorf("GuestPasscode = %q, want %q", s.GuestPasscode, "my password")
		}
	})

	t.Run("present-but-empty value is rejected", func(t *testing.T) {
		_, err := parseDisco(t, base(`guest_passcode ""`))
		if err == nil {
			t.Fatal("expected an error for an empty guest_passcode, got nil")
		}
		if !strings.Contains(err.Error(), "guest_passcode must not be empty") {
			t.Errorf("error = %q, want it to contain %q", err.Error(), "guest_passcode must not be empty")
		}
	})

	t.Run("omitted directive leaves feature off", func(t *testing.T) {
		s, err := parseDisco(t, base(""))
		if err != nil {
			t.Fatalf("UnmarshalCaddyfile() error = %v", err)
		}
		if s.GuestPasscode != "" {
			t.Errorf("GuestPasscode = %q, want empty when directive omitted", s.GuestPasscode)
		}
		// Config must validate cleanly with the directive omitted.
		s.SetDefaults()
		if err := s.Validate(); err != nil {
			t.Errorf("Validate() with guest_passcode omitted returned error: %v", err)
		}
	})
}
