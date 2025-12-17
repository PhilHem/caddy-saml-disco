//go:build unit

package caddy

import (
	"testing"
)

// Cycle 2: RED - Write failing tests for registry lookup

func TestSPConfigRegistry_GetByHostname(t *testing.T) {
	registry := NewSPConfigRegistry()

	cfg1 := &SPConfig{Hostname: "app1.example.com", Config: Config{EntityID: "https://app1/saml"}}
	cfg2 := &SPConfig{Hostname: "app2.example.com", Config: Config{EntityID: "https://app2/saml"}}

	registry.Add(cfg1)
	registry.Add(cfg2)

	found := registry.GetByHostname("app1.example.com")
	if found == nil {
		t.Fatal("should find config for app1.example.com")
	}
	if found.EntityID != "https://app1/saml" {
		t.Errorf("EntityID = %q, want https://app1/saml", found.EntityID)
	}

	notFound := registry.GetByHostname("unknown.com")
	if notFound != nil {
		t.Error("should return nil for unknown hostname")
	}
}

func TestSPConfigRegistry_GetByHostname_ExactMatch(t *testing.T) {
	registry := NewSPConfigRegistry()
	cfg := &SPConfig{Hostname: "app.example.com", Config: Config{EntityID: "https://app/saml"}}
	registry.Add(cfg)

	// Should match exactly, not by substring
	found := registry.GetByHostname("app.example.com")
	if found == nil {
		t.Error("should find exact match")
	}

	notFound := registry.GetByHostname("sub.app.example.com")
	if notFound != nil {
		t.Error("should not match subdomain")
	}
}

func TestSPConfigRegistry_GetByHostname_CaseSensitive(t *testing.T) {
	registry := NewSPConfigRegistry()
	cfg := &SPConfig{Hostname: "App.Example.COM", Config: Config{EntityID: "https://app/saml"}}
	registry.Add(cfg)

	// Hostname matching should be case-sensitive
	found := registry.GetByHostname("App.Example.COM")
	if found == nil {
		t.Error("should find exact case match")
	}

	notFound := registry.GetByHostname("app.example.com")
	if notFound != nil {
		t.Error("should not match different case")
	}
}



