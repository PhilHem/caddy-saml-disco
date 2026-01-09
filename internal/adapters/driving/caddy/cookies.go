package caddy

import (
	"net/http"

	"go.uber.org/zap"
)

// Cookie management methods for SAMLDisco.
// These methods handle session and "remember IdP" cookies for both
// global configuration and per-SP configuration.

// setSessionCookie sets the session cookie with the given token.
func (s *SAMLDisco) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.sessionDuration.Seconds()),
	})
}

// clearSessionCookies clears both session and remember IdP cookies.
func (s *SAMLDisco) clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete cookie
	})
	s.clearRememberIdPCookie(w, r)
}

// setRememberIdPCookie sets a cookie to remember the user's last-used IdP.
func (s *SAMLDisco) setRememberIdPCookie(w http.ResponseWriter, r *http.Request, entityID string) {
	if s.RememberIdPCookieName == "" || s.rememberIdPDuration == 0 {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.RememberIdPCookieName,
		Value:    entityID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.rememberIdPDuration.Seconds()),
	})
}

// getRememberIdPCookie reads the remembered IdP entity ID from the cookie.
func (s *SAMLDisco) getRememberIdPCookie(r *http.Request) string {
	if s.RememberIdPCookieName == "" {
		return ""
	}
	cookie, err := r.Cookie(s.RememberIdPCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	return cookie.Value
}

// clearRememberIdPCookie deletes the remembered IdP cookie.
func (s *SAMLDisco) clearRememberIdPCookie(w http.ResponseWriter, r *http.Request) {
	if s.RememberIdPCookieName == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.RememberIdPCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete cookie
	})
}

// setSessionCookieForSP sets the session cookie for a specific SP config.
func (s *SAMLDisco) setSessionCookieForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     spConfig.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(spConfig.sessionDuration.Seconds()),
	})
}

// clearSessionCookiesForSP clears both session and remember IdP cookies for a specific SP config.
func (s *SAMLDisco) clearSessionCookiesForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     spConfig.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete cookie
	})
	s.clearRememberIdPCookieForSP(w, r, spConfig)
}

// setRememberIdPCookieForSP sets a cookie to remember the user's last-used IdP for a specific SP config.
func (s *SAMLDisco) setRememberIdPCookieForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig, entityID string) {
	if spConfig.RememberIdPCookieName == "" || spConfig.RememberIdPDuration == "" {
		return
	}
	duration, err := ParseDuration(spConfig.RememberIdPDuration)
	if err != nil {
		s.getLogger().Warn("invalid remember IdP duration, skipping cookie",
			zap.String("duration", spConfig.RememberIdPDuration),
			zap.Error(err))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     spConfig.RememberIdPCookieName,
		Value:    entityID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(duration.Seconds()),
	})
}

// getRememberIdPCookieForSP reads the remembered IdP entity ID from the cookie for a specific SP config.
func (s *SAMLDisco) getRememberIdPCookieForSP(r *http.Request, spConfig *SPConfig) string {
	if spConfig.RememberIdPCookieName == "" {
		return ""
	}
	cookie, err := r.Cookie(spConfig.RememberIdPCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	return cookie.Value
}

// clearRememberIdPCookieForSP deletes the remembered IdP cookie for a specific SP config.
func (s *SAMLDisco) clearRememberIdPCookieForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) {
	if spConfig.RememberIdPCookieName == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     spConfig.RememberIdPCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete cookie
	})
}
