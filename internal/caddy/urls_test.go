//go:build unit

package caddy

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/httputil"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

func TestResolveScheme_Direct(t *testing.T) {
	tra.Require(t, "Adapter.ResolveSchemeDirectTLS")

	// Create a request with TLS
	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{}

	scheme := httputil.ResolveScheme(req)
	if scheme != "https" {
		t.Errorf("expected 'https', got %q", scheme)
	}
}

func TestResolveScheme_XForwardedProto(t *testing.T) {
	tra.Require(t, "Adapter.ResolveSchemeXForwardedProto")

	// Create a request without TLS but with X-Forwarded-Proto header
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.TLS = nil
	req.Header.Set("X-Forwarded-Proto", "https")

	scheme := httputil.ResolveScheme(req)
	if scheme != "https" {
		t.Errorf("expected 'https', got %q", scheme)
	}
}

func TestResolveScheme_NoTLS_NoHeader(t *testing.T) {
	tra.Require(t, "Adapter.ResolveSchemePlainHTTP")

	// Create a request without TLS and without X-Forwarded-Proto header
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.TLS = nil

	scheme := httputil.ResolveScheme(req)
	if scheme != "http" {
		t.Errorf("expected 'http', got %q", scheme)
	}
}
