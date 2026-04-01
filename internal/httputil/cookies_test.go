//go:build unit

package httputil

import (
	cryptotls "crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testCookieConfig is a test implementation of CookieConfig.
type testCookieConfig struct {
	sessionCookieName     string
	sessionCookieDomain   string
	sessionDuration       time.Duration
	rememberIdPCookieName string
	rememberIdPDuration   time.Duration
	cookieSecureMode      string
}

func (c *testCookieConfig) SessionCookieName() string          { return c.sessionCookieName }
func (c *testCookieConfig) SessionCookieDomain() string        { return c.sessionCookieDomain }
func (c *testCookieConfig) SessionDuration() time.Duration     { return c.sessionDuration }
func (c *testCookieConfig) RememberIdPCookieName() string      { return c.rememberIdPCookieName }
func (c *testCookieConfig) RememberIdPDuration() time.Duration { return c.rememberIdPDuration }
func (c *testCookieConfig) CookieSecureMode() string           { return c.cookieSecureMode }

func TestSetSessionCookieWithConfig(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	config := &testCookieConfig{
		sessionCookieName: "saml_session",
		sessionDuration:   8 * time.Hour,
	}

	SetSessionCookieWithConfig(w, r, config, "token123")

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "saml_session" {
		t.Errorf("Name = %q, want saml_session", c.Name)
	}
	if c.Value != "token123" {
		t.Errorf("Value = %q, want token123", c.Value)
	}
	if c.MaxAge != int((8 * time.Hour).Seconds()) {
		t.Errorf("MaxAge = %d, want %d", c.MaxAge, int((8*time.Hour).Seconds()))
	}
	if !c.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
}

func TestClearSessionCookieWithConfig(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	config := &testCookieConfig{sessionCookieName: "saml_session"}
	ClearSessionCookieWithConfig(w, r, config)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "saml_session" {
		t.Errorf("Name = %q, want saml_session", c.Name)
	}
	if c.Value != "" {
		t.Errorf("Value should be empty, got %q", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", c.MaxAge)
	}
}

func TestSetRememberIdPCookieWithConfig(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	config := &testCookieConfig{
		rememberIdPCookieName: "saml_last_idp",
		rememberIdPDuration:   30 * 24 * time.Hour,
	}

	SetRememberIdPCookieWithConfig(w, r, config, "https://idp.example.com/saml")

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "saml_last_idp" {
		t.Errorf("Name = %q, want saml_last_idp", c.Name)
	}
	if c.Value != "https://idp.example.com/saml" {
		t.Errorf("Value = %q, want https://idp.example.com/saml", c.Value)
	}
}

func TestClearRememberIdPCookieWithConfig(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	config := &testCookieConfig{rememberIdPCookieName: "saml_last_idp"}
	ClearRememberIdPCookieWithConfig(w, r, config)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", c.MaxAge)
	}
}

func TestResolveSecure(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		hasTLS   bool
		wantSecure bool
	}{
		{"auto without TLS", "auto", false, false},
		{"auto with TLS", "auto", true, true},
		{"empty defaults to auto without TLS", "", false, false},
		{"empty defaults to auto with TLS", "", true, true},
		{"always without TLS", "always", false, true},
		{"always with TLS", "always", true, true},
		{"never without TLS", "never", false, false},
		{"never with TLS", "never", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			if tt.hasTLS {
				r.TLS = &cryptotls.ConnectionState{}
			}

			config := &testCookieConfig{
				sessionCookieName:  "saml_session",
				sessionDuration:    time.Hour,
				cookieSecureMode:   tt.mode,
			}
			SetSessionCookieWithConfig(w, r, config, "tok")

			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("expected 1 cookie, got %d", len(cookies))
			}
			if cookies[0].Secure != tt.wantSecure {
				t.Errorf("Secure = %v, want %v", cookies[0].Secure, tt.wantSecure)
			}
		})
	}
}
