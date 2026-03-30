package caddy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// HealthResponse is the JSON response for /saml/api/health
type HealthResponse struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
	domain.MetadataHealth
}

// sessionContextKey is the context key for storing session data.
type sessionContextKey struct{}

// GetSession retrieves the authenticated session from the request context.
// Returns nil if no session is present (unauthenticated request).
func GetSession(r *http.Request) *domain.Session {
	session, _ := r.Context().Value(sessionContextKey{}).(*domain.Session)
	return session
}

// SAMLDisco is a Caddy HTTP handler module that provides SAML SP authentication
// with IdP discovery service support.
type SAMLDisco struct {
	// Configuration embedded directly (for backward compatibility with single-SP mode)
	Config

	// Multi-SP support
	// If SPConfigs is non-empty, the instance operates in multi-SP mode.
	// Otherwise, it uses the embedded Config (single-SP mode).
	SPConfigs []*SPConfig `json:"sp_configs,omitempty"`

	// Runtime state (not serialized)
	registry            *SPConfigRegistry
	metadataStore       ports.MetadataStore
	sessionStore        ports.SessionStore
	logoStore           ports.LogoStore
	entitlementStore    ports.EntitlementStore
	samlService         *SAMLService
	sessionDuration     time.Duration
	rememberIdPDuration time.Duration
	templateRenderer    *TemplateRenderer
	logger              *zap.Logger
	metricsRecorder     ports.MetricsRecorder

	// Config snapshots (immutable copies taken during Provision to prevent mutation)
	// These are used in applyAttributeHeaders() to ensure header names match validation-time expectations.
	headerPrefixSnapshot       string
	attributeHeadersSnapshot   []AttributeMapping
	entitlementHeadersSnapshot []EntitlementHeaderMapping
}

// SPConfigRegistry manages multiple SP configurations keyed by hostname.
type SPConfigRegistry struct {
	configs map[string]*SPConfig // hostname -> config
	mu      sync.RWMutex
}

// NewSPConfigRegistry creates a new SP config registry.
func NewSPConfigRegistry() *SPConfigRegistry {
	return &SPConfigRegistry{
		configs: make(map[string]*SPConfig),
	}
}

// Add adds an SP config to the registry.
// Returns an error if a config with the same hostname already exists.
func (r *SPConfigRegistry) Add(cfg *SPConfig) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if cfg.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.configs[cfg.Hostname]; exists {
		return fmt.Errorf("SP config with hostname %q already exists", cfg.Hostname)
	}
	r.configs[cfg.Hostname] = cfg
	return nil
}

// GetByHostname retrieves an SP config by hostname.
// Returns nil if no config is found for the hostname.
func (r *SPConfigRegistry) GetByHostname(hostname string) *SPConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.configs[hostname]
}

// ParseDuration parses a duration string, supporting "d" suffix for days.
// Examples: "30d" (30 days), "8h" (8 hours), "1h30m" (1.5 hours)
// Exported for testing purposes.
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

// ValidateRelayState ensures the RelayState is a safe relative path.
// Returns "/" for any invalid, absolute, or potentially dangerous URLs.
// This prevents open redirect vulnerabilities.
// Exported for testing purposes.
func ValidateRelayState(relayState string) string {
	// Empty or whitespace-only defaults to root
	relayState = strings.TrimSpace(relayState)
	if relayState == "" {
		return "/"
	}

	// Must start with single forward slash (relative path)
	// Reject protocol-relative URLs (//evil.com)
	if !strings.HasPrefix(relayState, "/") || strings.HasPrefix(relayState, "//") {
		return "/"
	}

	// Parse to detect schemes and other tricks
	parsed, err := url.Parse(relayState)
	if err != nil {
		return "/"
	}

	// Reject if it has a scheme (http:, javascript:, data:, etc.)
	if parsed.Scheme != "" {
		return "/"
	}

	// Reject if it has a host (shouldn't happen with leading / but be safe)
	if parsed.Host != "" {
		return "/"
	}

	// Reject paths with newlines (header injection)
	if strings.ContainsAny(relayState, "\r\n") {
		return "/"
	}

	// Check for encoded characters that could bypass validation
	// Decode in a loop to catch double/triple encoding attacks (e.g., /%2f%2f or /%252f%252f)
	// Check after each decode for protocol markers and double-slashes
	decoded := relayState
	for i := 0; i < 10; i++ { // Max 10 iterations to prevent infinite loops
		newDecoded, err := url.QueryUnescape(decoded)
		if err != nil {
			return "/"
		}
		if newDecoded == decoded {
			break // No more decoding needed
		}
		decoded = newDecoded

		// Check decoded value for dangerous patterns
		if strings.Contains(decoded, "//") || strings.Contains(decoded, "://") {
			return "/"
		}
	}

	// Final check on fully decoded value
	if strings.Contains(decoded, "//") || strings.Contains(decoded, "://") {
		return "/"
	}

	return relayState
}

// ValidateDenyRedirect validates a deny redirect URL.
// Returns the URL if valid, empty string if invalid.
// Allows relative paths or absolute HTTPS URLs.
// Empty string is valid (means use 403, not redirect).
// This prevents open redirect vulnerabilities.
// Exported for testing purposes.
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

// Version getters - these are set via ldflags in the root package
// We access them via a function pointer to avoid import cycles
var (
	// Protect version getters with sync.Once to ensure thread-safe one-time initialization
	versionSetOnce sync.Once

	getVersion   = func() string { return "dev" }
	getGitCommit = func() string { return "" }
	getBuildTime = func() string { return "" }
)

// SetVersionGetters sets the version getter functions.
// Called from root package init to inject version info.
// Thread-safe via sync.Once to ensure one-time initialization.
func SetVersionGetters(version, gitCommit, buildTime func() string) {
	versionSetOnce.Do(func() {
		getVersion = version
		getGitCommit = gitCommit
		getBuildTime = buildTime
	})
}
