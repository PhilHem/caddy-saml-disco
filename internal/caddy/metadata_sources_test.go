//go:build unit

package caddy

import (
	"testing"
	"time"
)

// Cycle 1: Test MetadataSource struct with defaults

func TestMetadataSourceDefaults(t *testing.T) {
	src := &MetadataSource{}
	src.SetDefaults()

	expectedInterval := 30 * time.Minute
	if src.RefreshInterval != expectedInterval {
		t.Errorf("RefreshInterval = %v, want %v", src.RefreshInterval, expectedInterval)
	}
}

func TestConfigWithMultipleSources(t *testing.T) {
	cfg := &Config{
		EntityID: "https://sp.example.com/saml",
		MetadataSources: []MetadataSource{
			{
				URL:       "https://federation1.org/metadata.xml",
				IdPFilter: "*.uni-mannheim.de*",
			},
			{
				URL:       "https://federation2.org/metadata.xml",
				IdPFilter: "*.uni-tuebingen.de*",
			},
		},
	}

	if len(cfg.MetadataSources) != 2 {
		t.Errorf("MetadataSources length = %d, want 2", len(cfg.MetadataSources))
	}

	if cfg.MetadataSources[0].URL != "https://federation1.org/metadata.xml" {
		t.Errorf("MetadataSources[0].URL = %q, want %q", cfg.MetadataSources[0].URL, "https://federation1.org/metadata.xml")
	}

	if cfg.MetadataSources[1].IdPFilter != "*.uni-tuebingen.de*" {
		t.Errorf("MetadataSources[1].IdPFilter = %q, want %q", cfg.MetadataSources[1].IdPFilter, "*.uni-tuebingen.de*")
	}
}

func TestConfigBackwardCompatibility(t *testing.T) {
	tests := []struct {
		name        string
		metadataURL string
		metadataFile string
		wantErr     bool
	}{
		{
			name:        "old MetadataURL field still works",
			metadataURL: "https://federation.org/metadata.xml",
			wantErr:     false,
		},
		{
			name:         "old MetadataFile field still works",
			metadataFile: "/path/to/metadata.xml",
			wantErr:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				EntityID:     "https://sp.example.com/saml",
				MetadataURL:  tc.metadataURL,
				MetadataFile: tc.metadataFile,
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

func TestMetadataSourceValidation(t *testing.T) {
	tests := []struct {
		name            string
		metadataURL     string
		metadataFile    string
		metadataSources []MetadataSource
		wantErr         bool
	}{
		{
			name:        "at least one source via old MetadataURL",
			metadataURL: "https://federation.org/metadata.xml",
			wantErr:     false,
		},
		{
			name:         "at least one source via old MetadataFile",
			metadataFile: "/path/to/metadata.xml",
			wantErr:      false,
		},
		{
			name: "at least one source via MetadataSources",
			metadataSources: []MetadataSource{
				{URL: "https://federation.org/metadata.xml"},
			},
			wantErr: false,
		},
		{
			name:     "no sources should fail",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				EntityID:        "https://sp.example.com/saml",
				MetadataURL:     tc.metadataURL,
				MetadataFile:    tc.metadataFile,
				MetadataSources: tc.metadataSources,
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

func TestMetadataSourceOptionsApplied(t *testing.T) {
	cfg := &Config{
		EntityID: "https://sp.example.com/saml",
		MetadataSources: []MetadataSource{
			{
				URL:             "https://federation.org/metadata.xml",
				IdPFilter:       "*.example.edu",
				RefreshInterval: 2 * time.Hour,
			},
		},
	}

	src := cfg.MetadataSources[0]

	if src.IdPFilter != "*.example.edu" {
		t.Errorf("IdPFilter = %q, want %q", src.IdPFilter, "*.example.edu")
	}

	if src.RefreshInterval != 2*time.Hour {
		t.Errorf("RefreshInterval = %v, want %v", src.RefreshInterval, 2*time.Hour)
	}
}
