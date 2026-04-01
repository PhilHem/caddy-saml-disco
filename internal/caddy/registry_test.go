//go:build unit

package caddy

import (
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/config"
)

// Cycle 2: RED - Write failing tests for registry lookup

func TestSPConfigRegistry_GetByHostname(t *testing.T) {
	registry := NewSPConfigRegistry()

	cfg1 := &SPConfig{SPConfig: config.SPConfig{Hostname: "app1.example.com", Config: Config{EntityID: "https://app1/saml"}}}
	cfg2 := &SPConfig{SPConfig: config.SPConfig{Hostname: "app2.example.com", Config: Config{EntityID: "https://app2/saml"}}}

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
	cfg := &SPConfig{SPConfig: config.SPConfig{Hostname: "app.example.com", Config: Config{EntityID: "https://app/saml"}}}
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
	cfg := &SPConfig{SPConfig: config.SPConfig{Hostname: "App.Example.COM", Config: Config{EntityID: "https://app/saml"}}}
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

func TestSPConfigRegistry_Add_SucceedsForUniqueHostname(t *testing.T) {
	registry := NewSPConfigRegistry()

	cfg1 := &SPConfig{SPConfig: config.SPConfig{Hostname: "app1.example.com", Config: Config{EntityID: "https://app1/saml"}}}
	cfg2 := &SPConfig{SPConfig: config.SPConfig{Hostname: "app2.example.com", Config: Config{EntityID: "https://app2/saml"}}}

	err := registry.Add(cfg1)
	if err != nil {
		t.Errorf("Add unique hostname should not error, got: %v", err)
	}

	err = registry.Add(cfg2)
	if err != nil {
		t.Errorf("Add second unique hostname should not error, got: %v", err)
	}

	// Verify both are in registry
	if registry.GetByHostname("app1.example.com") == nil {
		t.Error("app1.example.com should be in registry")
	}
	if registry.GetByHostname("app2.example.com") == nil {
		t.Error("app2.example.com should be in registry")
	}
}

func TestSPConfigRegistry_Add_ReturnsErrorOnCollision(t *testing.T) {
	registry := NewSPConfigRegistry()

	cfg1 := &SPConfig{SPConfig: config.SPConfig{Hostname: "app.example.com", Config: Config{EntityID: "https://app1/saml"}}}
	cfg2 := &SPConfig{SPConfig: config.SPConfig{Hostname: "app.example.com", Config: Config{EntityID: "https://app2/saml"}}}

	err := registry.Add(cfg1)
	if err != nil {
		t.Errorf("Add first config should not error, got: %v", err)
	}

	// Adding duplicate hostname should return error
	err = registry.Add(cfg2)
	if err == nil {
		t.Error("Add duplicate hostname should return error")
	}

	// Original config should still be in registry
	found := registry.GetByHostname("app.example.com")
	if found == nil || found.Config.EntityID != "https://app1/saml" {
		t.Error("original config should be unchanged after collision attempt")
	}
}
