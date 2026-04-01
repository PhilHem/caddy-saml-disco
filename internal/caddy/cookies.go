package caddy

import (
	"net/http"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

// spCookieConfig wraps SPConfig to implement httputil.CookieConfig.
type spCookieConfig struct {
	sp *SPConfig
}

func (c *spCookieConfig) SessionCookieName() string  { return c.sp.Config.SessionCookieName }
func (c *spCookieConfig) SessionCookieDomain() string { return c.sp.Hostname }
func (c *spCookieConfig) SessionDuration() time.Duration { return c.sp.sessionDuration }
func (c *spCookieConfig) RememberIdPCookieName() string { return c.sp.Config.RememberIdPCookieName }
func (c *spCookieConfig) CookieSecureMode() string    { return c.sp.Config.CookieSecure }

func (c *spCookieConfig) RememberIdPDuration() time.Duration {
	if c.sp.Config.RememberIdPDuration == "" {
		return 0
	}
	duration, err := httputil.ParseDuration(c.sp.Config.RememberIdPDuration)
	if err != nil {
		return 0
	}
	return duration
}

func (s *SAMLDisco) setSessionCookie(w http.ResponseWriter, r *http.Request, spConfig *SPConfig, token string) {
	httputil.SetSessionCookieWithConfig(w, r, &spCookieConfig{sp: spConfig}, token)
}

func (s *SAMLDisco) clearSessionCookies(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) {
	httputil.ClearSessionCookieWithConfig(w, r, &spCookieConfig{sp: spConfig})
	httputil.ClearRememberIdPCookieWithConfig(w, r, &spCookieConfig{sp: spConfig})
}
