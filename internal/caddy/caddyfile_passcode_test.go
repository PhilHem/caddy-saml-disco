//go:build unit

package caddy

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/philiph/caddy-saml-disco/internal/config"
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

// TestUnmarshalCaddyfile_PerTargetPasscode covers the passcode subdirective in
// guest_access and bypass_idp blocks: each records a passcode under its own
// target entity ID, an empty value is rejected, and the two targets can carry
// distinct codes.
func TestUnmarshalCaddyfile_PerTargetPasscode(t *testing.T) {
	const bypassID = "https://idp.uni-tuebingen.de/shibboleth"

	t.Run("distinct per-target codes are stored under their entity IDs", func(t *testing.T) {
		input := `saml_disco {
			entity_id https://sp.example.com
			metadata_url https://federation.org/metadata.xml
			bypass_idp "` + bypassID + `" {
				passcode "bypass code"
			}
			guest_access "Rechtsberatung" {
				passcode "guest code"
			}
		}`
		s, err := parseDisco(t, input)
		if err != nil {
			t.Fatalf("UnmarshalCaddyfile() error = %v", err)
		}
		if got := s.GuestPasscodes[config.GuestEntityID]; got != "guest code" {
			t.Errorf("guest passcode = %q, want %q", got, "guest code")
		}
		if got := s.GuestPasscodes[bypassID]; got != "bypass code" {
			t.Errorf("bypass passcode = %q, want %q", got, "bypass code")
		}
		// The shared default stays unset when only per-target codes are given.
		if s.GuestPasscode != "" {
			t.Errorf("GuestPasscode = %q, want empty", s.GuestPasscode)
		}
	})

	t.Run("present-but-empty per-target passcode is rejected", func(t *testing.T) {
		input := `saml_disco {
			entity_id https://sp.example.com
			metadata_url https://federation.org/metadata.xml
			guest_access "Rechtsberatung" {
				passcode ""
			}
		}`
		_, err := parseDisco(t, input)
		if err == nil {
			t.Fatal("expected an error for an empty per-target passcode, got nil")
		}
		if !strings.Contains(err.Error(), "passcode must not be empty") {
			t.Errorf("error = %q, want it to contain %q", err.Error(), "passcode must not be empty")
		}
	})

	t.Run("guest_access without a block still works", func(t *testing.T) {
		input := `saml_disco {
			entity_id https://sp.example.com
			metadata_url https://federation.org/metadata.xml
			guest_access "Rechtsberatung"
		}`
		s, err := parseDisco(t, input)
		if err != nil {
			t.Fatalf("UnmarshalCaddyfile() error = %v", err)
		}
		if s.GuestAccessLabel != "Rechtsberatung" {
			t.Errorf("GuestAccessLabel = %q, want %q", s.GuestAccessLabel, "Rechtsberatung")
		}
		if len(s.GuestPasscodes) != 0 {
			t.Errorf("GuestPasscodes = %v, want empty when no block given", s.GuestPasscodes)
		}
	})
}
