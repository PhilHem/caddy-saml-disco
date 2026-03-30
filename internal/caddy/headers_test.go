//go:build unit

package caddy

import (
	"net/http"
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"go.uber.org/zap"
)

// TestApplyAttributeHeadersCore_BasicMapping verifies the core function correctly maps
// attributes to headers with the given config.
func TestApplyAttributeHeadersCore_BasicMapping(t *testing.T) {
	// Setup
	req := &http.Request{Header: http.Header{}}
	session := &domain.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"email":       "user@example.com",
			"displayName": "Test User",
		},
	}

	cfg := HeaderConfig{
		AttributeHeaders: []AttributeMapping{
			{SAMLAttribute: "email", HeaderName: "X-User-Email"},
			{SAMLAttribute: "displayName", HeaderName: "X-User-Name"},
		},
		HeaderPrefix: "",
		StripHeaders: false,
	}

	logger := zap.NewNop()

	// Execute
	applyAttributeHeadersCore(req, session, cfg, logger)

	// Verify
	if got := req.Header.Get("X-User-Email"); got != "user@example.com" {
		t.Errorf("X-User-Email = %q, want %q", got, "user@example.com")
	}
	if got := req.Header.Get("X-User-Name"); got != "Test User" {
		t.Errorf("X-User-Name = %q, want %q", got, "Test User")
	}
}

// TestApplyAttributeHeadersCore_StripsExisting verifies the core function strips
// existing headers when strip=true.
func TestApplyAttributeHeadersCore_StripsExisting(t *testing.T) {
	// Setup - request has pre-existing headers
	req := &http.Request{Header: http.Header{
		"X-User-Email": []string{"attacker@evil.com"},
		"X-User-Name":  []string{"Evil User"},
	}}

	session := &domain.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"email":       "user@example.com",
			"displayName": "Test User",
		},
	}

	cfg := HeaderConfig{
		AttributeHeaders: []AttributeMapping{
			{SAMLAttribute: "email", HeaderName: "X-User-Email"},
			{SAMLAttribute: "displayName", HeaderName: "X-User-Name"},
		},
		HeaderPrefix: "",
		StripHeaders: true, // Should strip existing headers
	}

	logger := zap.NewNop()

	// Execute
	applyAttributeHeadersCore(req, session, cfg, logger)

	// Verify - should have session values, not the pre-existing ones
	if got := req.Header.Get("X-User-Email"); got != "user@example.com" {
		t.Errorf("X-User-Email = %q, want %q", got, "user@example.com")
	}
	if got := req.Header.Get("X-User-Name"); got != "Test User" {
		t.Errorf("X-User-Name = %q, want %q", got, "Test User")
	}
}

// TestApplyAttributeHeadersCore_PreservesExisting verifies the core function preserves
// existing headers when strip=false.
func TestApplyAttributeHeadersCore_PreservesExisting(t *testing.T) {
	// Setup - request has pre-existing headers
	req := &http.Request{Header: http.Header{
		"X-User-Email": []string{"existing@example.com"},
		"X-Other":      []string{"preserved"},
	}}

	session := &domain.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"email": "user@example.com",
		},
	}

	cfg := HeaderConfig{
		AttributeHeaders: []AttributeMapping{
			{SAMLAttribute: "email", HeaderName: "X-User-Email"},
		},
		HeaderPrefix: "",
		StripHeaders: false, // Should preserve existing headers
	}

	logger := zap.NewNop()

	// Execute
	applyAttributeHeadersCore(req, session, cfg, logger)

	// Verify - session value should overwrite X-User-Email
	if got := req.Header.Get("X-User-Email"); got != "user@example.com" {
		t.Errorf("X-User-Email = %q, want %q", got, "user@example.com")
	}
	// X-Other should remain untouched
	if got := req.Header.Get("X-Other"); got != "preserved" {
		t.Errorf("X-Other = %q, want %q", got, "preserved")
	}
}
