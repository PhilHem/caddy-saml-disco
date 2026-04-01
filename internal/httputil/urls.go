package httputil

import (
	"net/http"
)

// ResolveScheme extracts the scheme from an HTTP request.
// Returns "https" if r.TLS is set, otherwise checks X-Forwarded-Proto header,
// falling back to "http" if neither is available.
func ResolveScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	// Check X-Forwarded-Proto header
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

// ApplyCORSHeaders sets CORS headers if the request origin is allowed.
// Returns true if CORS headers were applied.
func ApplyCORSHeaders(w http.ResponseWriter, r *http.Request, allowedOrigins []string, allowCredentials bool) bool {
	if len(allowedOrigins) == 0 {
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}

	allowed := false
	responseOrigin := ""

	if len(allowedOrigins) == 1 && allowedOrigins[0] == "*" {
		allowed = true
		responseOrigin = "*"
	} else {
		for _, o := range allowedOrigins {
			if o == origin {
				allowed = true
				responseOrigin = origin
				break
			}
		}
	}

	if !allowed {
		return false
	}

	w.Header().Set("Access-Control-Allow-Origin", responseOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if allowCredentials && responseOrigin != "*" {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	return true
}
