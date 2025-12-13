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
