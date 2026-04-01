package discovery

import "github.com/philiph/caddy-saml-disco/internal/httputil"

// ValidateRelayState ensures the RelayState is a safe relative path.
// Returns "/" for any invalid, absolute, or potentially dangerous URLs.
// This prevents open redirect vulnerabilities.
func ValidateRelayState(relayState string) string {
	return httputil.ValidateRelayState(relayState)
}

// MatchesForceAuthnPath checks if the request path matches any force_authn_paths pattern.
// Patterns support wildcard suffix (e.g., "/admin/*" matches "/admin/settings").
func MatchesForceAuthnPath(requestPath string, patterns []string) bool {
	return httputil.MatchesForceAuthnPath(requestPath, patterns)
}
