//go:build unit

package caddy

import (
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
