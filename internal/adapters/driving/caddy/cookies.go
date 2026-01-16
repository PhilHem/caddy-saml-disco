package caddy

import (
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Cookie management methods for SAMLDisco.
// These methods handle session and "remember IdP" cookies for both
// global configuration and per-SP configuration.

// CookieConfig interface implementations using wrapper types to avoid shadowing fields.

// globalCookieConfig wraps SAMLDisco to implement CookieConfig.
type globalCookieConfig struct {
	disco *SAMLDisco
}

func (c *globalCookieConfig) SessionCookieName() string {
	return c.disco.Config.SessionCookieName
}

func (c *globalCookieConfig) SessionCookieDomain() string {
	return ""
}

func (c *globalCookieConfig) SessionDuration() time.Duration {
	return c.disco.sessionDuration
}

func (c *globalCookieConfig) RememberIdPCookieName() string {
	return c.disco.Config.RememberIdPCookieName
}

func (c *globalCookieConfig) RememberIdPDuration() time.Duration {
	return c.disco.rememberIdPDuration
}

// spCookieConfig wraps SPConfig to implement CookieConfig.
type spCookieConfig struct {
	sp *SPConfig
}

func (c *spCookieConfig) SessionCookieName() string {
	return c.sp.Config.SessionCookieName
}

func (c *spCookieConfig) SessionCookieDomain() string {
	return c.sp.Hostname
}

func (c *spCookieConfig) SessionDuration() time.Duration {
	return c.sp.sessionDuration
}

func (c *spCookieConfig) RememberIdPCookieName() string {
	return c.sp.Config.RememberIdPCookieName
}

func (c *spCookieConfig) RememberIdPDuration() time.Duration {
	if c.sp.Config.RememberIdPDuration == "" {
		return 0
	}
	duration, err := ParseDuration(c.sp.Config.RememberIdPDuration)
	if err != nil {
		return 0
	}
	return duration
}

// setSessionCookie sets the session cookie with the given token.
func (s *SAMLDisco) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	setSessionCookieWithConfig(w, r, &globalCookieConfig{disco: s}, token)
}

// clearSessionCookies clears both session and remember IdP cookies.
func (s *SAMLDisco) clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	clearSessionCookieWithConfig(w, r, &globalCookieConfig{disco: s})
	s.clearRememberIdPCookie(w, r)
}

// setRememberIdPCookie sets a cookie to remember the user's last-used IdP.
func (s *SAMLDisco) setRememberIdPCookie(w http.ResponseWriter, r *http.Request, entityID string) {
	setRememberIdPCookieWithConfig(w, r, &globalCookieConfig{disco: s}, entityID)
}

// getRememberIdPCookie reads the remembered IdP entity ID from the cookie.
func (s *SAMLDisco) getRememberIdPCookie(r *http.Request) string {
	cookieName := s.Config.RememberIdPCookieName
	if cookieName == "" {
		return ""
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	return cookie.Value
}

// clearRememberIdPCookie deletes the remembered IdP cookie.
func (s *SAMLDisco) clearRememberIdPCookie(w http.ResponseWriter, r *http.Request) {
	clearRememberIdPCookieWithConfig(w, r, &globalCookieConfig{disco: s})
}

// setSessionCookieForSP sets the session cookie for a specific SP config.
func (s *SAMLDisco) setSessionCookieForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig, token string) {
	setSessionCookieWithConfig(w, r, &spCookieConfig{sp: spConfig}, token)
}

// clearSessionCookiesForSP clears both session and remember IdP cookies for a specific SP config.
func (s *SAMLDisco) clearSessionCookiesForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) {
	clearSessionCookieWithConfig(w, r, &spCookieConfig{sp: spConfig})
	s.clearRememberIdPCookieForSP(w, r, spConfig)
}

// setRememberIdPCookieForSP sets a cookie to remember the user's last-used IdP for a specific SP config.
func (s *SAMLDisco) setRememberIdPCookieForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig, entityID string) {
	spCfg := &spCookieConfig{sp: spConfig}
	duration := spCfg.RememberIdPDuration()
	if duration == 0 && spConfig.Config.RememberIdPDuration != "" {
		s.getLogger().Warn("invalid remember IdP duration, skipping cookie",
			zap.String("duration", spConfig.Config.RememberIdPDuration))
		return
	}
	setRememberIdPCookieWithConfig(w, r, spCfg, entityID)
}

// getRememberIdPCookieForSP reads the remembered IdP entity ID from the cookie for a specific SP config.
func (s *SAMLDisco) getRememberIdPCookieForSP(r *http.Request, spConfig *SPConfig) string {
	cookieName := spConfig.Config.RememberIdPCookieName
	if cookieName == "" {
		return ""
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	return cookie.Value
}

// clearRememberIdPCookieForSP deletes the remembered IdP cookie for a specific SP config.
func (s *SAMLDisco) clearRememberIdPCookieForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) {
	clearRememberIdPCookieWithConfig(w, r, &spCookieConfig{sp: spConfig})
}
