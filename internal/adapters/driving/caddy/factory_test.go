package caddy

import (
	"testing"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// mockMetadataStoreForFactory is a minimal mock for testing factory injection.
type mockMetadataStoreForFactory struct {
	ports.MetadataStore
}

// mockSessionStoreForFactory is a minimal mock for testing factory injection.
type mockSessionStoreForFactory struct {
	ports.SessionStore
}

// mockLogoStoreForFactory is a minimal mock for testing factory injection.
type mockLogoStoreForFactory struct {
	ports.LogoStore
}

// mockEntitlementStoreForFactory is a minimal mock for testing factory injection.
type mockEntitlementStoreForFactory struct {
	ports.EntitlementStore
}

// mockMetricsRecorderForFactory is a minimal mock for testing factory injection.
type mockMetricsRecorderForFactory struct {
	ports.MetricsRecorder
}

func TestNewSAMLDisco_DefaultValues(t *testing.T) {
	s := NewSAMLDisco()

	if s == nil {
		t.Fatal("NewSAMLDisco returned nil")
	}

	// Default should have empty config
	if s.EntityID != "" {
		t.Errorf("expected empty EntityID, got %q", s.EntityID)
	}
}

func TestNewSAMLDisco_WithConfig(t *testing.T) {
	cfg := Config{
		EntityID:          "https://sp.example.com",
		SessionCookieName: "test_session",
	}

	s := NewSAMLDisco(WithConfig(cfg))

	if s.EntityID != "https://sp.example.com" {
		t.Errorf("EntityID = %q, want %q", s.EntityID, "https://sp.example.com")
	}
	if s.SessionCookieName != "test_session" {
		t.Errorf("SessionCookieName = %q, want %q", s.SessionCookieName, "test_session")
	}
}

func TestNewSAMLDisco_WithPinnedIdPs(t *testing.T) {
	pinned := []string{"https://idp1.example.com", "https://idp2.example.com"}

	s := NewSAMLDisco(WithPinnedIdPs(pinned))

	if len(s.PinnedIdPs) != 2 {
		t.Fatalf("PinnedIdPs length = %d, want 2", len(s.PinnedIdPs))
	}
	if s.PinnedIdPs[0] != "https://idp1.example.com" {
		t.Errorf("PinnedIdPs[0] = %q, want %q", s.PinnedIdPs[0], "https://idp1.example.com")
	}
	if s.PinnedIdPs[1] != "https://idp2.example.com" {
		t.Errorf("PinnedIdPs[1] = %q, want %q", s.PinnedIdPs[1], "https://idp2.example.com")
	}
}

func TestNewSAMLDisco_WithMetadataStore(t *testing.T) {
	store := &mockMetadataStoreForFactory{}

	s := NewSAMLDisco(WithMetadataStore(store))

	// The metadataStore field is unexported, but we can verify via the getter
	// or by checking that SetMetadataStore was called. For now we just verify
	// the function doesn't panic and returns a valid SAMLDisco.
	if s == nil {
		t.Fatal("NewSAMLDisco returned nil")
	}
}

func TestNewSAMLDisco_WithSessionStore(t *testing.T) {
	store := &mockSessionStoreForFactory{}

	s := NewSAMLDisco(WithSessionStore(store))

	if s == nil {
		t.Fatal("NewSAMLDisco returned nil")
	}
}

func TestNewSAMLDisco_WithLogoStore(t *testing.T) {
	store := &mockLogoStoreForFactory{}

	s := NewSAMLDisco(WithLogoStore(store))

	if s == nil {
		t.Fatal("NewSAMLDisco returned nil")
	}
}

func TestNewSAMLDisco_WithEntitlementStore(t *testing.T) {
	store := &mockEntitlementStoreForFactory{}

	s := NewSAMLDisco(WithEntitlementStore(store))

	if s == nil {
		t.Fatal("NewSAMLDisco returned nil")
	}
}

func TestNewSAMLDisco_WithMetricsRecorder(t *testing.T) {
	recorder := &mockMetricsRecorderForFactory{}

	s := NewSAMLDisco(WithMetricsRecorder(recorder))

	if s == nil {
		t.Fatal("NewSAMLDisco returned nil")
	}
}

func TestNewSAMLDisco_WithLogger(t *testing.T) {
	logger := zap.NewNop()

	s := NewSAMLDisco(WithLogger(logger))

	if s == nil {
		t.Fatal("NewSAMLDisco returned nil")
	}
}

func TestNewSAMLDisco_WithMultipleOptions(t *testing.T) {
	cfg := Config{
		EntityID: "https://sp.example.com",
	}
	pinned := []string{"https://idp1.example.com"}
	store := &mockMetadataStoreForFactory{}
	logger := zap.NewNop()

	s := NewSAMLDisco(
		WithConfig(cfg),
		WithPinnedIdPs(pinned),
		WithMetadataStore(store),
		WithLogger(logger),
	)

	if s.EntityID != "https://sp.example.com" {
		t.Errorf("EntityID = %q, want %q", s.EntityID, "https://sp.example.com")
	}
	if len(s.PinnedIdPs) != 1 {
		t.Errorf("PinnedIdPs length = %d, want 1", len(s.PinnedIdPs))
	}
}

func TestNewSAMLDisco_OptionsCompose(t *testing.T) {
	// Test that later options override earlier ones for the same field
	s := NewSAMLDisco(
		WithConfig(Config{EntityID: "first"}),
		WithConfig(Config{EntityID: "second"}),
	)

	if s.EntityID != "second" {
		t.Errorf("EntityID = %q, want %q (later option should win)", s.EntityID, "second")
	}
}

func TestNewSAMLDisco_WithSAMLService(t *testing.T) {
	// We can't easily create a SAMLService without keys, so just test nil handling
	s := NewSAMLDisco(WithSAMLService(nil))

	if s == nil {
		t.Fatal("NewSAMLDisco returned nil")
	}
}
