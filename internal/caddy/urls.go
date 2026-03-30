package caddy

import (
	"net/http"
	"net/url"
)

// URL resolution methods for SAMLDisco.
// These methods compute ACS and SLO URLs from request context and configuration.

// @tra: Adapter.ResolveSchemeDirectTLS
// @tra: Adapter.ResolveSchemeXForwardedProto
// @tra: Adapter.ResolveSchemePlainHTTP
// resolveScheme extracts the scheme from an HTTP request.
// Returns "https" if r.TLS is set, otherwise checks X-Forwarded-Proto header,
// falling back to "http" if neither is available.
func resolveScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	// Check X-Forwarded-Proto header
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

// resolveAcsURL computes the ACS URL from the request and configuration.
func (s *SAMLDisco) resolveAcsURL(r *http.Request) *url.URL {
	if s.AcsURL != "" {
		u, _ := url.Parse(s.AcsURL)
		return u
	}

	// Compute from request
	return &url.URL{
		Scheme: resolveScheme(r),
		Host:   r.Host,
		Path:   "/saml/acs",
	}
}

// resolveSLOURL computes the SLO URL from the request.
func (s *SAMLDisco) resolveSLOURL(r *http.Request) *url.URL {
	return &url.URL{
		Scheme: resolveScheme(r),
		Host:   r.Host,
		Path:   "/saml/slo",
	}
}

// resolveAcsURLForSP computes the ACS URL from the request and SP config.
func (s *SAMLDisco) resolveAcsURLForSP(r *http.Request, spConfig *SPConfig) *url.URL {
	if spConfig.AcsURL != "" {
		acsURL, err := url.Parse(spConfig.AcsURL)
		if err == nil {
			return acsURL
		}
	}

	// Default: construct from request
	return &url.URL{
		Scheme: resolveScheme(r),
		Host:   r.Host,
		Path:   "/saml/acs",
	}
}

// resolveSLOURLForSP computes the SLO URL from the request and SP config.
func (s *SAMLDisco) resolveSLOURLForSP(r *http.Request, spConfig *SPConfig) *url.URL {
	return &url.URL{
		Scheme: resolveScheme(r),
		Host:   r.Host,
		Path:   "/saml/slo",
	}
}
