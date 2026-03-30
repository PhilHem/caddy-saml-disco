//go:build unit

package caddy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCookieHelper_SetSessionCookie works for both single-SP and multi-SP
func TestCookieHelper_SetSessionCookie(t *testing.T) {
	tests := []struct {
		name           string
		cookieName     string
		cookieDomain   string
		duration       time.Duration
		token          string
		expectedName   string
		expectedValue  string
		expectedMaxAge int
	}{
		{
			name:           "single-SP mode",
			cookieName:     "saml_session",
			cookieDomain:   "",
			duration:       8 * time.Hour,
			token:          "token123",
			expectedName:   "saml_session",
			expectedValue:  "token123",
			expectedMaxAge: int((8 * time.Hour).Seconds()),
		},
		{
			name:           "multi-SP mode",
			cookieName:     "app1_session",
			cookieDomain:   "app1.example.com",
			duration:       4 * time.Hour,
			token:          "tokenABC",
			expectedName:   "app1_session",
			expectedValue:  "tokenABC",
			expectedMaxAge: int((4 * time.Hour).Seconds()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)

			config := &testCookieConfig{
				sessionCookieName:   tt.cookieName,
				sessionCookieDomain: tt.cookieDomain,
				sessionDuration:     tt.duration,
			}

			setSessionCookieWithConfig(w, r, config, tt.token)

			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("expected 1 cookie, got %d", len(cookies))
			}

			cookie := cookies[0]
			if cookie.Name != tt.expectedName {
				t.Errorf("cookie name: got %q, want %q", cookie.Name, tt.expectedName)
			}
			if cookie.Value != tt.expectedValue {
				t.Errorf("cookie value: got %q, want %q", cookie.Value, tt.expectedValue)
			}
			if cookie.MaxAge != tt.expectedMaxAge {
				t.Errorf("cookie MaxAge: got %d, want %d", cookie.MaxAge, tt.expectedMaxAge)
			}
			if !cookie.HttpOnly {
				t.Error("cookie should be HttpOnly")
			}
			if cookie.SameSite != http.SameSiteLaxMode {
				t.Errorf("cookie SameSite: got %v, want %v", cookie.SameSite, http.SameSiteLaxMode)
			}
		})
	}
}

// TestCookieHelper_ClearSessionCookie works for both modes
func TestCookieHelper_ClearSessionCookie(t *testing.T) {
	tests := []struct {
		name         string
		cookieName   string
		cookieDomain string
	}{
		{
			name:         "single-SP mode",
			cookieName:   "saml_session",
			cookieDomain: "",
		},
		{
			name:         "multi-SP mode",
			cookieName:   "app2_session",
			cookieDomain: "app2.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)

			config := &testCookieConfig{
				sessionCookieName:   tt.cookieName,
				sessionCookieDomain: tt.cookieDomain,
			}

			clearSessionCookieWithConfig(w, r, config)

			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("expected 1 cookie, got %d", len(cookies))
			}

			cookie := cookies[0]
			if cookie.Name != tt.cookieName {
				t.Errorf("cookie name: got %q, want %q", cookie.Name, tt.cookieName)
			}
			if cookie.Value != "" {
				t.Errorf("cookie value should be empty, got %q", cookie.Value)
			}
			if cookie.MaxAge != -1 {
				t.Errorf("cookie MaxAge: got %d, want -1", cookie.MaxAge)
			}
		})
	}
}

// TestCookieHelper_SetRememberIdPCookie works for both modes
func TestCookieHelper_SetRememberIdPCookie(t *testing.T) {
	tests := []struct {
		name           string
		cookieName     string
		cookieDomain   string
		duration       time.Duration
		entityID       string
		expectedName   string
		expectedValue  string
		expectedMaxAge int
	}{
		{
			name:           "single-SP mode",
			cookieName:     "saml_last_idp",
			cookieDomain:   "",
			duration:       30 * 24 * time.Hour,
			entityID:       "https://idp.example.com/saml",
			expectedName:   "saml_last_idp",
			expectedValue:  "https://idp.example.com/saml",
			expectedMaxAge: int((30 * 24 * time.Hour).Seconds()),
		},
		{
			name:           "multi-SP mode",
			cookieName:     "app1_last_idp",
			cookieDomain:   "app1.example.com",
			duration:       7 * 24 * time.Hour,
			entityID:       "https://idp2.example.org/saml",
			expectedName:   "app1_last_idp",
			expectedValue:  "https://idp2.example.org/saml",
			expectedMaxAge: int((7 * 24 * time.Hour).Seconds()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)

			config := &testCookieConfig{
				rememberIdPCookieName: tt.cookieName,
				rememberIdPDuration:   tt.duration,
			}

			setRememberIdPCookieWithConfig(w, r, config, tt.entityID)

			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("expected 1 cookie, got %d", len(cookies))
			}

			cookie := cookies[0]
			if cookie.Name != tt.expectedName {
				t.Errorf("cookie name: got %q, want %q", cookie.Name, tt.expectedName)
			}
			if cookie.Value != tt.expectedValue {
				t.Errorf("cookie value: got %q, want %q", cookie.Value, tt.expectedValue)
			}
			if cookie.MaxAge != tt.expectedMaxAge {
				t.Errorf("cookie MaxAge: got %d, want %d", cookie.MaxAge, tt.expectedMaxAge)
			}
		})
	}
}

// testCookieConfig is a test implementation of CookieConfig
type testCookieConfig struct {
	sessionCookieName     string
	sessionCookieDomain   string
	sessionDuration       time.Duration
	rememberIdPCookieName string
	rememberIdPDuration   time.Duration
}

func (c *testCookieConfig) SessionCookieName() string {
	return c.sessionCookieName
}

func (c *testCookieConfig) SessionCookieDomain() string {
	return c.sessionCookieDomain
}

func (c *testCookieConfig) SessionDuration() time.Duration {
	return c.sessionDuration
}

func (c *testCookieConfig) RememberIdPCookieName() string {
	return c.rememberIdPCookieName
}

func (c *testCookieConfig) RememberIdPDuration() time.Duration {
	return c.rememberIdPDuration
}
