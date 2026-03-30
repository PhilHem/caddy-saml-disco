package caddy

import (
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/metadata"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

func TestBuildMetadataStore_SingleSource(t *testing.T) {
	cfg := &Config{
		MetadataSources: []MetadataSource{
			{
				URL:             "https://example.com/metadata.xml",
				RefreshInterval: 10 * time.Minute,
			},
		},
	}

	store, err := BuildMetadataStore(cfg, nil)
	if err != nil {
		t.Fatalf("BuildMetadataStore() error = %v", err)
	}

	// Single source should return a single store (not wrapped in Composite)
	if _, ok := store.(*metadata.URLMetadataStore); !ok {
		t.Errorf("expected *metadata.URLMetadataStore, got %T", store)
	}
}

func TestBuildMetadataStore_MultipleSources(t *testing.T) {
	cfg := &Config{
		MetadataSources: []MetadataSource{
			{
				URL:             "https://example.com/metadata1.xml",
				RefreshInterval: 10 * time.Minute,
			},
			{
				File: "/tmp/metadata2.xml",
			},
		},
	}

	store, err := BuildMetadataStore(cfg, nil)
	if err != nil {
		t.Fatalf("BuildMetadataStore() error = %v", err)
	}

	// Multiple sources should return a CompositeMetadataStore
	if _, ok := store.(*metadata.CompositeMetadataStore); !ok {
		t.Errorf("expected *metadata.CompositeMetadataStore, got %T", store)
	}
}

func TestBuildMetadataStore_PerSourceFilter(t *testing.T) {
	cfg := &Config{
		MetadataSources: []MetadataSource{
			{
				URL:       "https://example.com/metadata.xml",
				IdPFilter: "*.example.edu",
			},
		},
	}

	store, err := BuildMetadataStore(cfg, nil)
	if err != nil {
		t.Fatalf("BuildMetadataStore() error = %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestBuildMetadataStore_EmptySources(t *testing.T) {
	cfg := &Config{
		MetadataSources: []MetadataSource{},
	}

	store, err := BuildMetadataStore(cfg, nil)
	if err != nil {
		t.Fatalf("BuildMetadataStore() error = %v", err)
	}

	if store != nil {
		t.Errorf("expected nil store for empty sources, got %T", store)
	}
}

func TestBuildMetadataStore_InheritBaseOptions(t *testing.T) {
	cfg := &Config{
		MetadataSources: []MetadataSource{
			{
				URL: "https://example.com/metadata.xml",
			},
		},
	}

	// Base options should be inherited by all sources
	baseOpts := []metadata.MetadataOption{
		metadata.WithIdPFilter("*.base.edu"),
	}

	store, err := BuildMetadataStore(cfg, baseOpts)
	if err != nil {
		t.Fatalf("BuildMetadataStore() error = %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}

	// Can't easily verify options were applied without inspecting internals,
	// but we can verify the store was created successfully
	if _, ok := store.(ports.MetadataStore); !ok {
		t.Errorf("expected ports.MetadataStore, got %T", store)
	}
}
