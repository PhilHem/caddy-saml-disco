package discovery

import (
	"net/http"
	"net/url"

	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

// resolveAcsURL computes the ACS URL from the request and configuration.
func (h *DiscoveryHandler) resolveAcsURL(r *http.Request) *url.URL {
	if h.Config.AcsURL != "" {
		u, _ := url.Parse(h.Config.AcsURL)
		return u
	}
	return &url.URL{
		Scheme: httputil.ResolveScheme(r),
		Host:   r.Host,
		Path:   "/saml/acs",
	}
}
