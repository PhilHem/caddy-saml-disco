package caddy

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
}

// setSessionCookieWithConfig sets a session cookie using the provided config.
func setSessionCookieWithConfig(w http.ResponseWriter, r *http.Request, config CookieConfig, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     config.SessionCookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(config.SessionDuration().Seconds()),
	})
}

// clearSessionCookieWithConfig clears the session cookie using the provided config.
func clearSessionCookieWithConfig(w http.ResponseWriter, r *http.Request, config CookieConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     config.SessionCookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete cookie
	})
}

// setRememberIdPCookieWithConfig sets a "remember IdP" cookie using the provided config.
func setRememberIdPCookieWithConfig(w http.ResponseWriter, r *http.Request, config CookieConfig, entityID string) {
	if config.RememberIdPCookieName() == "" || config.RememberIdPDuration() == 0 {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     config.RememberIdPCookieName(),
		Value:    entityID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(config.RememberIdPDuration().Seconds()),
	})
}

// clearRememberIdPCookieWithConfig clears the "remember IdP" cookie using the provided config.
func clearRememberIdPCookieWithConfig(w http.ResponseWriter, r *http.Request, config CookieConfig) {
	if config.RememberIdPCookieName() == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     config.RememberIdPCookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete cookie
	})
}
