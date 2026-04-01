package httputil

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ValidateRelayState ensures the RelayState is a safe relative path.
// Returns "/" for any invalid, absolute, or potentially dangerous URLs.
// This prevents open redirect vulnerabilities.
func ValidateRelayState(relayState string) string {
	relayState = strings.TrimSpace(relayState)
	if relayState == "" {
		return "/"
	}

	// Must start with single forward slash (relative path).
	// Reject protocol-relative URLs (//evil.com).
	if !strings.HasPrefix(relayState, "/") || strings.HasPrefix(relayState, "//") {
		return "/"
	}

	parsed, err := url.Parse(relayState)
	if err != nil {
		return "/"
	}

	// Reject if it has a scheme (http:, javascript:, data:, etc.)
	if parsed.Scheme != "" {
		return "/"
	}

	// Reject if it has a host.
	if parsed.Host != "" {
		return "/"
	}

	// Reject paths with newlines (header injection).
	if strings.ContainsAny(relayState, "\r\n") {
		return "/"
	}

	// Check for encoded characters that could bypass validation.
	// Decode in a loop to catch double/triple encoding attacks (e.g., /%2f%2f or /%252f%252f).
	decoded := relayState
	for i := 0; i < 10; i++ {
		newDecoded, err := url.QueryUnescape(decoded)
		if err != nil {
			return "/"
		}
		if newDecoded == decoded {
			break
		}
		decoded = newDecoded

		if strings.Contains(decoded, "//") || strings.Contains(decoded, "://") {
			return "/"
		}
	}

	if strings.Contains(decoded, "//") || strings.Contains(decoded, "://") {
		return "/"
	}

	return relayState
}

// ParseDuration parses a duration string, supporting "d" suffix for days.
// Examples: "30d" (30 days), "8h" (8 hours), "1h30m" (1.5 hours)
func ParseDuration(s string) (time.Duration, error) {
	// Handle day suffix (not supported by time.ParseDuration)
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		var d int64
		if _, err := fmt.Sscanf(days, "%d", &d); err != nil {
			return 0, fmt.Errorf("invalid day format: %s", s)
		}
		// Prevent integer overflow: max safe days is ~106,751 (~292 years)
		// time.Duration is int64 nanoseconds, 24*time.Hour = 86,400,000,000,000 ns
		// Max int64 / (24*time.Hour) ≈ 106,751
		if d < 0 || d > 106751 {
			return 0, fmt.Errorf("day value out of range: %s (max 106751 days)", s)
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// ValidateDenyRedirect validates a deny redirect URL.
// Returns the URL if valid, empty string if invalid.
// Allows relative paths or absolute HTTPS URLs.
// Empty string is valid (means use 403, not redirect).
// This prevents open redirect vulnerabilities.
func ValidateDenyRedirect(redirectURL string) string {
	// Empty string is valid (means use 403, not redirect)
	redirectURL = strings.TrimSpace(redirectURL)
	if redirectURL == "" {
		return ""
	}

	// Parse to detect schemes and other tricks
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		return ""
	}

	// If it has a scheme, must be https
	if parsed.Scheme != "" {
		if parsed.Scheme != "https" {
			return ""
		}
		// Must have a host for absolute URLs
		if parsed.Host == "" {
			return ""
		}
		return redirectURL
	}

	// No scheme means relative path - validate like RelayState
	// Must start with single forward slash (relative path)
	// Reject protocol-relative URLs (//evil.com)
	if !strings.HasPrefix(redirectURL, "/") || strings.HasPrefix(redirectURL, "//") {
		return ""
	}

	// Reject if parsed URL has a host (shouldn't happen with leading / but be safe)
	if parsed.Host != "" {
		return ""
	}

	// Reject paths with newlines (header injection)
	if strings.ContainsAny(redirectURL, "\r\n") {
		return ""
	}

	// Check for encoded characters that could bypass validation
	// Decode and re-check for protocol-relative URLs
	decoded, err := url.QueryUnescape(redirectURL)
	if err != nil {
		return ""
	}
	if strings.HasPrefix(decoded, "//") {
		return ""
	}

	return redirectURL
}

// MatchesForceAuthnPath checks if the request path matches any force_authn_paths pattern.
// Patterns support wildcard suffix (e.g., "/admin/*" matches "/admin/settings").
func MatchesForceAuthnPath(requestPath string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(requestPath, prefix+"/") {
				return true
			}
		} else if pattern == requestPath {
			return true
		}
	}
	return false
}
