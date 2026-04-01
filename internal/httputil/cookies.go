package httputil

import (
	"net/http"
	"time"
)

// CookieConfig defines the interface for cookie configuration.
// Both SAMLDisco and SPConfig can implement this interface to provide
// cookie settings for session and "remember IdP" cookies.
type CookieConfig interface {
	SessionCookieName() string
	SessionCookieDomain() string
	SessionDuration() time.Duration
	RememberIdPCookieName() string
	RememberIdPDuration() time.Duration
	// CookieSecureMode controls when the Secure flag is set on cookies.
	// Valid values: "auto" (default, uses r.TLS != nil), "always", "never".
	CookieSecureMode() string
}

// resolveSecure determines whether the Secure flag should be set on a cookie.
// mode values: "always" → true, "never" → false, anything else → r.TLS != nil.
func resolveSecure(r *http.Request, mode string) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	default:
		return r.TLS != nil
	}
}

// SetSessionCookieWithConfig sets a session cookie using the provided config.
func SetSessionCookieWithConfig(w http.ResponseWriter, r *http.Request, config CookieConfig, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     config.SessionCookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   resolveSecure(r, config.CookieSecureMode()),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(config.SessionDuration().Seconds()),
	})
}

// ClearSessionCookieWithConfig clears the session cookie using the provided config.
func ClearSessionCookieWithConfig(w http.ResponseWriter, r *http.Request, config CookieConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     config.SessionCookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   resolveSecure(r, config.CookieSecureMode()),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete cookie
	})
}

// SetRememberIdPCookieWithConfig sets a "remember IdP" cookie using the provided config.
func SetRememberIdPCookieWithConfig(w http.ResponseWriter, r *http.Request, config CookieConfig, entityID string) {
	if config.RememberIdPCookieName() == "" || config.RememberIdPDuration() == 0 {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     config.RememberIdPCookieName(),
		Value:    entityID,
		Path:     "/",
		HttpOnly: true,
		Secure:   resolveSecure(r, config.CookieSecureMode()),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(config.RememberIdPDuration().Seconds()),
	})
}

// ClearRememberIdPCookieWithConfig clears the "remember IdP" cookie using the provided config.
func ClearRememberIdPCookieWithConfig(w http.ResponseWriter, r *http.Request, config CookieConfig) {
	if config.RememberIdPCookieName() == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     config.RememberIdPCookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   resolveSecure(r, config.CookieSecureMode()),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete cookie
	})
}
