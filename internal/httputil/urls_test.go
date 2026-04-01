//go:build unit

package httputil

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestResolveScheme_Direct(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{}

	if got := ResolveScheme(req); got != "https" {
		t.Errorf("expected 'https', got %q", got)
	}
}

func TestResolveScheme_XForwardedProto(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.TLS = nil
	req.Header.Set("X-Forwarded-Proto", "https")

	if got := ResolveScheme(req); got != "https" {
		t.Errorf("expected 'https', got %q", got)
	}
}

func TestResolveScheme_NoTLS_NoHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.TLS = nil

	if got := ResolveScheme(req); got != "http" {
		t.Errorf("expected 'http', got %q", got)
	}
}
