package caddy

import (
	"net/http"
	"net/url"
)

// URL resolution methods for SAMLDisco.
// These methods compute ACS and SLO URLs from request context and configuration.

// resolveAcsURL computes the ACS URL from the request and configuration.
func (s *SAMLDisco) resolveAcsURL(r *http.Request) *url.URL {
	if s.AcsURL != "" {
		u, _ := url.Parse(s.AcsURL)
		return u
	}

	// Compute from request
	scheme := "https"
	if r.TLS == nil {
		// Check X-Forwarded-Proto header
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}

	return &url.URL{
		Scheme: scheme,
		Host:   r.Host,
		Path:   "/saml/acs",
	}
}

// resolveSLOURL computes the SLO URL from the request.
func (s *SAMLDisco) resolveSLOURL(r *http.Request) *url.URL {
	// Compute from request (similar to resolveAcsURL)
	scheme := "https"
	if r.TLS == nil {
		// Check X-Forwarded-Proto header
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}

	return &url.URL{
		Scheme: scheme,
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
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return &url.URL{
		Scheme: scheme,
		Host:   r.Host,
		Path:   "/saml/acs",
	}
}

// resolveSLOURLForSP computes the SLO URL from the request and SP config.
func (s *SAMLDisco) resolveSLOURLForSP(r *http.Request, spConfig *SPConfig) *url.URL {
	// Compute from request (similar to resolveAcsURLForSP)
	scheme := "https"
	if r.TLS == nil {
		// Check X-Forwarded-Proto header
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}

	return &url.URL{
		Scheme: scheme,
		Host:   r.Host,
		Path:   "/saml/slo",
	}
}
