//go:build unit

package caddy

import (
	"net/http"
	"net/url"

	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

// resolveAcsURL computes the ACS URL from the request and SP config.
// Used in tests to verify ACS URL resolution behavior.
func (s *SAMLDisco) resolveAcsURL(r *http.Request, spConfig *SPConfig) *url.URL {
	if spConfig.AcsURL != "" {
		acsURL, err := url.Parse(spConfig.AcsURL)
		if err == nil {
			return acsURL
		}
	}

	return &url.URL{
		Scheme: httputil.ResolveScheme(r),
		Host:   r.Host,
		Path:   "/saml/acs",
	}
}
