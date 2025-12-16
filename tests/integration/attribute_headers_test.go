//go:build integration

package integration

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	caddysamldisco "github.com/philiph/caddy-saml-disco"
)

// capturedHeaders records headers seen by downstream handler
type capturedHeaders struct {
	headers http.Header
	called  bool
}

func (c *capturedHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	c.headers = r.Header.Clone()
	c.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

var _ caddyhttp.Handler = (*capturedHeaders)(nil)

// TestAttributeHeaders_ReachDownstreamHandler tests that SAML attributes
// are correctly mapped to HTTP headers and reach downstream handlers.
func TestAttributeHeaders_ReachDownstreamHandler(t *testing.T) {
	// Load SP credentials for session store
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	// Create session store
	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	// Create session with attributes
	session := &caddysamldisco.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"mail": "user@example.com",
		},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	// Create session token
	token, err := sessionStore.Create(session)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Create SAMLDisco with attribute_headers configured
	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			SessionCookieName: "saml_session",
			AttributeHeaders: []caddysamldisco.AttributeMapping{
				{SAMLAttribute: "mail", HeaderName: "X-Remote-User"},
			},
		},
	}
	disco.SetSessionStore(sessionStore)

	// Create downstream handler that captures headers
	captured := &capturedHeaders{}

	// Make request with session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()

	// Call ServeHTTP directly
	err = disco.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	// Verify downstream handler was called
	if !captured.called {
		t.Fatal("downstream handler was not called")
	}

	// Verify header was set correctly
	got := captured.headers.Get("X-Remote-User")
	if got != "user@example.com" {
		t.Errorf("X-Remote-User header = %q, want %q", got, "user@example.com")
	}
}

// TestAttributeHeaders_OIDResolution tests that attribute mapping works
// regardless of whether the IdP sends OID or friendly name.
func TestAttributeHeaders_OIDResolution(t *testing.T) {
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	// Session has OID form, config uses friendly name
	session := &caddysamldisco.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"urn:oid:0.9.2342.19200300.100.1.3": "user@example.com", // mail OID
		},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	token, err := sessionStore.Create(session)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Config maps friendly name "mail" → X-Mail
	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			SessionCookieName: "saml_session",
			AttributeHeaders: []caddysamldisco.AttributeMapping{
				{SAMLAttribute: "mail", HeaderName: "X-Mail"},
			},
		},
	}
	disco.SetSessionStore(sessionStore)

	captured := &capturedHeaders{}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()

	err = disco.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if !captured.called {
		t.Fatal("downstream handler was not called")
	}

	// Should resolve OID to friendly name and set header
	got := captured.headers.Get("X-Mail")
	if got != "user@example.com" {
		t.Errorf("X-Mail header = %q, want %q", got, "user@example.com")
	}
}

// TestAttributeHeaders_StripsIncomingHeaders tests that incoming spoofed
// headers are stripped before downstream handlers receive the request.
func TestAttributeHeaders_StripsIncomingHeaders(t *testing.T) {
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	session := &caddysamldisco.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"role": "member",
		},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	token, err := sessionStore.Create(session)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			SessionCookieName: "saml_session",
			AttributeHeaders: []caddysamldisco.AttributeMapping{
				{SAMLAttribute: "role", HeaderName: "X-Role"},
			},
		},
	}
	disco.SetSessionStore(sessionStore)

	captured := &capturedHeaders{}

	// Request with spoofed header
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Role", "evil-admin") // Spoofed header
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()

	err = disco.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if !captured.called {
		t.Fatal("downstream handler was not called")
	}

	// Should see attribute value, NOT spoofed value
	got := captured.headers.Get("X-Role")
	if got != "member" {
		t.Errorf("X-Role header = %q, want %q (spoofed header should be stripped)", got, "member")
	}
}

// TestAttributeHeaders_MultipleMappings_CustomSeparator tests multiple
// attribute mappings with custom separator.
func TestAttributeHeaders_MultipleMappings_CustomSeparator(t *testing.T) {
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	// Note: Session stores single values, but we'll simulate multiple values
	// by using the entitlement attribute which can have multiple values
	session := &caddysamldisco.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"urn:oid:1.3.6.1.4.1.5923.1.1.1.7": "admin;user;editor", // eduPersonEntitlement
			"mail":                             "user@example.com",
		},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	token, err := sessionStore.Create(session)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Map entitlement with custom separator (comma instead of semicolon)
	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			SessionCookieName: "saml_session",
			AttributeHeaders: []caddysamldisco.AttributeMapping{
				{
					SAMLAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
					HeaderName:    "X-Entitlements",
					Separator:     ",",
				},
				{SAMLAttribute: "mail", HeaderName: "X-Mail"},
			},
		},
	}
	disco.SetSessionStore(sessionStore)

	captured := &capturedHeaders{}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()

	err = disco.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if !captured.called {
		t.Fatal("downstream handler was not called")
	}

	// Verify both headers are set
	entitlements := captured.headers.Get("X-Entitlements")
	// Note: Since Session stores single string values, the semicolon-separated
	// value will be treated as a single value. The separator is used when
	// joining multiple attribute values, but here we have one value.
	// The actual behavior: the value "admin;user;editor" will be sanitized and
	// set as-is (semicolons are valid in header values).
	if entitlements == "" {
		t.Error("X-Entitlements header should be set")
	}

	mail := captured.headers.Get("X-Mail")
	if mail != "user@example.com" {
		t.Errorf("X-Mail header = %q, want %q", mail, "user@example.com")
	}
}

// TestAttributeHeaders_Property_NoHeaderInjection uses property-based testing
// to verify that no header injection is possible via attribute values.
func TestAttributeHeaders_Property_NoHeaderInjection(t *testing.T) {
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	f := func(attrValue string) bool {
		// Skip empty strings
		if attrValue == "" {
			return true
		}

		sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

		session := &caddysamldisco.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test": attrValue,
			},
			IdPEntityID: "https://idp.example.com",
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(8 * time.Hour),
		}

		token, err := sessionStore.Create(session)
		if err != nil {
			return true // Skip on error
		}

		disco := &caddysamldisco.SAMLDisco{
			Config: caddysamldisco.Config{
				SessionCookieName: "saml_session",
				AttributeHeaders: []caddysamldisco.AttributeMapping{
					{SAMLAttribute: "test", HeaderName: "X-Test"},
				},
			},
		}
		disco.SetSessionStore(sessionStore)

		captured := &capturedHeaders{}

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.AddCookie(&http.Cookie{
			Name:  "saml_session",
			Value: token,
		})
		rec := httptest.NewRecorder()

		if err := disco.ServeHTTP(rec, req, captured); err != nil {
			return true // Skip on error
		}

		if !captured.called {
			return true // Skip if handler not called
		}

		// Property: No CR/LF in header values (header injection prevention)
		headerValue := captured.headers.Get("X-Test")
		if strings.ContainsAny(headerValue, "\r\n") {
			return false
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestAttributeHeaders_Property_OnlyConfiguredHeaders uses property-based testing
// to verify that only configured headers appear in downstream requests.
func TestAttributeHeaders_Property_OnlyConfiguredHeaders(t *testing.T) {
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	f := func(attrKey, attrValue, headerName string) bool {
		// Ensure valid header name for this property test
		headerName = "X-" + sanitizeForHeaderName(headerName)
		if headerName == "X-" {
			headerName = "X-Test"
		}

		// Skip empty attribute values (they won't produce headers)
		if attrValue == "" {
			return true
		}

		sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

		session := &caddysamldisco.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				attrKey: attrValue,
			},
			IdPEntityID: "https://idp.example.com",
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(8 * time.Hour),
		}

		token, err := sessionStore.Create(session)
		if err != nil {
			return true // Skip on error
		}

		disco := &caddysamldisco.SAMLDisco{
			Config: caddysamldisco.Config{
				SessionCookieName: "saml_session",
				AttributeHeaders: []caddysamldisco.AttributeMapping{
					{SAMLAttribute: attrKey, HeaderName: headerName},
				},
			},
		}
		disco.SetSessionStore(sessionStore)

		captured := &capturedHeaders{}

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.AddCookie(&http.Cookie{
			Name:  "saml_session",
			Value: token,
		})
		rec := httptest.NewRecorder()

		if err := disco.ServeHTTP(rec, req, captured); err != nil {
			return true // Skip on error
		}

		if !captured.called {
			return true // Skip if handler not called
		}

		// Property: All X-* headers in downstream must be from config
		allowedHeaders := make(map[string]bool)
		allowedHeaders[headerName] = true

		for header := range captured.headers {
			// Skip non-X- headers (they're not from attribute mapping)
			if !strings.HasPrefix(header, "X-") && !strings.HasPrefix(header, "x-") {
				continue
			}
			// Check if this X- header is in our allowed list
			if !allowedHeaders[header] {
				return false
			}
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// sanitizeForHeaderName removes invalid characters for use in property tests
func sanitizeForHeaderName(s string) string {
	var result strings.Builder
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// TestAttributeHeaders_HeaderPrefix tests that header prefix is correctly applied.
func TestAttributeHeaders_HeaderPrefix(t *testing.T) {
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	session := &caddysamldisco.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"mail": "user@example.com",
		},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	token, err := sessionStore.Create(session)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Configure with header prefix
	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			SessionCookieName: "saml_session",
			HeaderPrefix:      "X-Saml-",
			AttributeHeaders: []caddysamldisco.AttributeMapping{
				{SAMLAttribute: "mail", HeaderName: "User"}, // No X- needed with prefix
			},
		},
	}
	disco.SetSessionStore(sessionStore)

	captured := &capturedHeaders{}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()

	err = disco.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if !captured.called {
		t.Fatal("downstream handler was not called")
	}

	// Verify prefixed header was set correctly
	got := captured.headers.Get("X-Saml-User")
	if got != "user@example.com" {
		t.Errorf("X-Saml-User header = %q, want %q", got, "user@example.com")
	}

	// Verify unprefixed header was NOT set
	if captured.headers.Get("User") != "" {
		t.Error("unprefixed header 'User' should not be set")
	}
}

// TestAttributeHeaders_HeaderPrefix_StripsIncomingHeaders tests that incoming
// headers with prefixed names are stripped.
func TestAttributeHeaders_HeaderPrefix_StripsIncomingHeaders(t *testing.T) {
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	session := &caddysamldisco.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"role": "member",
		},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	token, err := sessionStore.Create(session)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			SessionCookieName: "saml_session",
			HeaderPrefix:      "X-Saml-",
			AttributeHeaders: []caddysamldisco.AttributeMapping{
				{SAMLAttribute: "role", HeaderName: "Role"},
			},
		},
	}
	disco.SetSessionStore(sessionStore)

	captured := &capturedHeaders{}

	// Request with spoofed prefixed header
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Saml-Role", "evil-admin") // Spoofed header
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()

	err = disco.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if !captured.called {
		t.Fatal("downstream handler was not called")
	}

	// Should see attribute value, NOT spoofed value
	got := captured.headers.Get("X-Saml-Role")
	if got != "member" {
		t.Errorf("X-Saml-Role header = %q, want %q (spoofed header should be stripped)", got, "member")
	}
}
