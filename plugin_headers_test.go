//go:build unit

package caddysamldisco

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// =============================================================================
// SAML Attribute Header Mapping Tests
// =============================================================================

// TestApplyAttributeHeaders_StripsSpoofedValues verifies that spoofed header values
// are replaced with values from SAML attributes. Tested indirectly through ServeHTTP()
// since applyAttributeHeaders() is unexported.
func TestApplyAttributeHeaders_StripsSpoofedValues(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	// Create session with attributes
	session := &Session{
		Subject:     "user@example.com",
		Attributes:  map[string]string{"role": "member"},
		IdPEntityID: "https://idp.example.com",
	}
	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("failed to create session token: %v", err)
	}

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "role", HeaderName: "X-Role"},
			},
		},
	}
	s.SetSessionStore(store)

	// Create request with spoofed header and valid session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Role", "evil-admin")
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})

	// Capture headers in downstream handler
	captured := &capturedHeaders{}
	rec := httptest.NewRecorder()

	err = s.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if !captured.called {
		t.Fatal("downstream handler was not called")
	}

	// Verify spoofed value was replaced
	if got := captured.headers.Get("X-Role"); got != "member" {
		t.Fatalf("X-Role header = %q, want %q", got, "member")
	}
}

// TestApplyAttributeHeaders_StripsWhenAttributeMissing verifies that headers are
// stripped when the corresponding SAML attribute is missing. Tested indirectly through
// ServeHTTP() since applyAttributeHeaders() is unexported.
func TestApplyAttributeHeaders_StripsWhenAttributeMissing(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	// Create session without the attribute
	session := &Session{
		Subject:     "user@example.com",
		Attributes:  map[string]string{},
		IdPEntityID: "https://idp.example.com",
	}
	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("failed to create session token: %v", err)
	}

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "role", HeaderName: "X-Role"},
			},
		},
	}
	s.SetSessionStore(store)

	// Create request with spoofed header and valid session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Role", "evil-admin")
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})

	// Capture headers in downstream handler
	captured := &capturedHeaders{}
	rec := httptest.NewRecorder()

	err = s.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if !captured.called {
		t.Fatal("downstream handler was not called")
	}

	// Verify header was stripped
	if got := captured.headers.Get("X-Role"); got != "" {
		t.Fatalf("X-Role header should be stripped, got %q", got)
	}
}

// TestApplyAttributeHeaders_DisabledPreservesIncoming verifies that when header
// stripping is disabled, incoming header values are preserved. Tested indirectly
// through ServeHTTP() since applyAttributeHeaders() is unexported.
func TestApplyAttributeHeaders_DisabledPreservesIncoming(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	// Create session without the attribute
	session := &Session{
		Subject:     "user@example.com",
		Attributes:  map[string]string{},
		IdPEntityID: "https://idp.example.com",
	}
	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("failed to create session token: %v", err)
	}

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "role", HeaderName: "X-Role"},
			},
			StripAttributeHeaders: boolPtr(false),
		},
	}
	s.SetSessionStore(store)

	// Create request with spoofed header and valid session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Role", "evil-admin")
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})

	// Capture headers in downstream handler
	captured := &capturedHeaders{}
	rec := httptest.NewRecorder()

	err = s.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if !captured.called {
		t.Fatal("downstream handler was not called")
	}

	// Verify spoofed value was preserved when stripping is disabled
	if got := captured.headers.Get("X-Role"); got != "evil-admin" {
		t.Fatalf("X-Role header should remain spoofed when stripping disabled, got %q", got)
	}
}
