package discovery

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

// setSessionCookie sets the session cookie with the given token.
func (h *DiscoveryHandler) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	httputil.SetSessionCookieWithConfig(w, r, cookieConfig{cfg: h.Config}, token)
}

// setRememberIdPCookie sets a cookie to remember the user's last-used IdP.
// Skips if RememberIdPDuration is zero.
func (h *DiscoveryHandler) setRememberIdPCookie(w http.ResponseWriter, r *http.Request, entityID string) {
	if h.Config.RememberIdPDuration == 0 && h.Config.RememberIdPCookieName != "" {
		h.getLogger().Warn("remember IdP duration is zero, skipping cookie",
			zap.String("cookie_name", h.Config.RememberIdPCookieName))
		return
	}
	httputil.SetRememberIdPCookieWithConfig(w, r, cookieConfig{cfg: h.Config}, entityID)
}

// getRememberIdPCookie reads the remembered IdP entity ID from the cookie.
func (h *DiscoveryHandler) getRememberIdPCookie(r *http.Request) string {
	name := h.Config.RememberIdPCookieName
	if name == "" {
		return ""
	}
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return ""
	}
	return cookie.Value
}
