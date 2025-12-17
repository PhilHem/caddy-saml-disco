//go:build unit

package caddy

import (
	"testing"
)

// Cycle 1: RED - Write failing tests for SPConfig structure

func TestSPConfig_Validate(t *testing.T) {
	cfg := &SPConfig{
		Hostname: "app1.example.com",
		Config: Config{
			EntityID:     "https://app1.example.com/saml",
			MetadataFile: "/path/to/metadata.xml",
			CertFile:     "/path/to/cert.pem",
			KeyFile:      "/path/to/key.pem",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid config should pass: %v", err)
	}
}

func TestSPConfig_Validate_MissingHostname(t *testing.T) {
	cfg := &SPConfig{
		Config: Config{EntityID: "https://sp.example.com/saml"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("config without hostname should fail")
	}
}

func TestSPConfig_Validate_DuplicateCookieName(t *testing.T) {
	cfg1 := &SPConfig{
		Hostname: "app1.com",
		Config: Config{
			EntityID:         "https://app1.com/saml",
			MetadataFile:     "/path/to/metadata1.xml",
			CertFile:         "/path/to/cert1.pem",
			KeyFile:          "/path/to/key1.pem",
			SessionCookieName: "shared",
		},
	}
	cfg2 := &SPConfig{
		Hostname: "app2.com",
		Config: Config{
			EntityID:         "https://app2.com/saml",
			MetadataFile:     "/path/to/metadata2.xml",
			CertFile:         "/path/to/cert2.pem",
			KeyFile:          "/path/to/key2.pem",
			SessionCookieName: "shared",
		},
	}
	// Should detect duplicate cookie names
	if err := validateSPConfigs([]*SPConfig{cfg1, cfg2}); err == nil {
		t.Error("duplicate cookie names should fail")
	}
}

func TestSPConfig_Validate_UniqueCookieNames(t *testing.T) {
	cfg1 := &SPConfig{
		Hostname: "app1.com",
		Config: Config{
			EntityID:         "https://app1.com/saml",
			MetadataFile:     "/path/to/metadata1.xml",
			CertFile:         "/path/to/cert1.pem",
			KeyFile:          "/path/to/key1.pem",
			SessionCookieName: "app1_session",
		},
	}
	cfg2 := &SPConfig{
		Hostname: "app2.com",
		Config: Config{
			EntityID:         "https://app2.com/saml",
			MetadataFile:     "/path/to/metadata2.xml",
			CertFile:         "/path/to/cert2.pem",
			KeyFile:          "/path/to/key2.pem",
			SessionCookieName: "app2_session",
		},
	}
	// Should pass with unique cookie names
	if err := validateSPConfigs([]*SPConfig{cfg1, cfg2}); err != nil {
		t.Errorf("unique cookie names should pass: %v", err)
	}
}



