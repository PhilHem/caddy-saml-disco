package caddy

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (s *SAMLDisco) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Determine which SP config to use
	var spConfig *SPConfig
	if s.registry != nil && len(s.SPConfigs) > 0 {
		// Multi-SP mode: route by hostname
		spConfig = s.registry.GetByHostname(r.Host)
		if spConfig == nil {
			return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("no SP config for hostname %q", r.Host))
		}
	} else {
		// Single-SP mode: use embedded Config (backward compatibility)
		spConfig = &SPConfig{
			Hostname: r.Host, // Use request hostname for single-SP mode
			Config:   s.Config,
			// Copy instance-level stores/services
			metadataStore:    s.metadataStore,
			sessionStore:     s.sessionStore,
			entitlementStore: s.entitlementStore,
			logoStore:        s.logoStore,
			samlService:      s.samlService,
			sessionDuration:  s.sessionDuration,
			templateRenderer: s.templateRenderer,
		}
	}

	// Delegate to SP-specific handler
	return s.serveSPRequest(w, r, next, spConfig)
}

// serveSPRequest handles a request for a specific SP config.
func (s *SAMLDisco) serveSPRequest(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, spConfig *SPConfig) error {
	// Handle CORS for API endpoints
	if strings.HasPrefix(r.URL.Path, "/saml/api/") {
		s.applyCORSHeaders(w, r)

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return nil
		}
	}

	// Handle logo endpoint (path prefix pattern)
	if strings.HasPrefix(r.URL.Path, "/saml/api/logo/") && r.Method == http.MethodGet {
		return s.handleLogoEndpointInternal(w, r, spConfig)
	}

	// Route SAML endpoints
	switch r.URL.Path {
	case "/saml/metadata":
		if r.Method == http.MethodGet {
			return s.handleMetadataInternal(w, r, spConfig)
		}
	case "/saml/acs":
		if r.Method == http.MethodPost {
			return s.handleACSInternal(w, r, spConfig)
		}
	case "/saml/logout":
		if r.Method == http.MethodGet {
			return s.handleLogoutInternal(w, r, spConfig)
		}
	case "/saml/slo":
		if r.Method == http.MethodGet || r.Method == http.MethodPost {
			return s.handleSLOInternal(w, r, spConfig)
		}
	case "/saml/api/idps":
		if r.Method == http.MethodGet {
			return s.handleListIdPsInternal(w, r, spConfig)
		}
	case "/saml/api/select":
		if r.Method == http.MethodPost {
			return s.handleSelectIdPInternal(w, r, spConfig)
		}
	case "/saml/api/session":
		if r.Method == http.MethodGet {
			return s.handleSessionInfoInternal(w, r, spConfig)
		}
	case "/saml/api/health":
		if r.Method == http.MethodGet {
			return s.handleHealthInternal(w, r, spConfig)
		}
	case "/saml/health":
		if r.Method == http.MethodGet {
			return s.handleSimpleHealthInternal(w, r, spConfig)
		}
	case "/saml/disco":
		if r.Method == http.MethodGet {
			return s.handleDiscoveryUIInternal(w, r, spConfig)
		}
	}

	// Check session for protected routes (skip SAML endpoints)
	if spConfig.sessionStore != nil && !strings.HasPrefix(r.URL.Path, "/saml/") {
		cookie, err := r.Cookie(spConfig.Config.SessionCookieName)
		if err != nil || cookie.Value == "" {
			s.redirectToIdPInternal(w, r, spConfig)
			return nil
		}

		// Validate session token
		session, err := spConfig.sessionStore.Get(cookie.Value)
		if err != nil {
			s.getMetricsRecorder().RecordSessionValidation(false)
			s.redirectToIdPInternal(w, r, spConfig)
			return nil
		}
		s.getMetricsRecorder().RecordSessionValidation(true)

		// Store session in context for downstream handlers
		ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
		r = r.WithContext(ctx)

		// Apply attribute-to-header mapping if configured
		// Check both AttributeHeaders and EntitlementHeaders
		if len(spConfig.AttributeHeaders) > 0 || len(spConfig.EntitlementHeaders) > 0 {
			s.applyAttributeHeadersForSP(r, session, spConfig)
		}
	}

	// Pass through to next handler
	return next.ServeHTTP(w, r)
}

// getDefaultLanguage returns the configured default language, falling back to "en".
func (s *SAMLDisco) getDefaultLanguage() string {
	if s.DefaultLanguage != "" {
		return s.DefaultLanguage
	}
	return "en"
}

// getLogger returns the logger, or a no-op logger if not set.
// This allows tests to run without calling Provision().
func (s *SAMLDisco) getLogger() *zap.Logger {
	if s.logger != nil {
		return s.logger
	}
	return zap.NewNop()
}

// selectIdPRequest is the JSON request body for POST /saml/api/select.
type selectIdPRequest struct {
	EntityID  string `json:"entity_id"`
	ReturnURL string `json:"return_url"`
	Remember  bool   `json:"remember"` // Explicit opt-in required for remember cookie
}

// sessionInfoResponse is the JSON response for GET /saml/api/session.
type sessionInfoResponse struct {
	Authenticated bool              `json:"authenticated"`
	Subject       string            `json:"subject,omitempty"`
	IdPEntityID   string            `json:"idp_entity_id,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// idpListResponse is the JSON response for GET /saml/api/idps.
type idpListResponse struct {
	IdPs          []domain.IdPInfo `json:"idps"`
	PinnedIdPs    []domain.IdPInfo `json:"pinned_idps,omitempty"`
	RememberedIdP string           `json:"remembered_idp_id,omitempty"`
}

// separatePinnedIdPs separates configured pinned IdPs from the main list.
// Returns (pinnedIdPs, remainingIdPs). Pinned IdPs are returned in the order
// specified in the configuration, not in their original order in the list.
func (s *SAMLDisco) separatePinnedIdPs(idps []domain.IdPInfo) ([]domain.IdPInfo, []domain.IdPInfo) {
	return domain.SeparatePinnedIdPs(idps, s.PinnedIdPs)
}

// applyCORSHeaders sets CORS headers if the request origin is allowed.
// Returns true if CORS headers were applied.
func (s *SAMLDisco) applyCORSHeaders(w http.ResponseWriter, r *http.Request) bool {
	if len(s.CORSAllowedOrigins) == 0 {
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}

	// Check if origin is allowed
	allowed := false
	responseOrigin := ""

	if len(s.CORSAllowedOrigins) == 1 && s.CORSAllowedOrigins[0] == "*" {
		allowed = true
		responseOrigin = "*"
	} else {
		for _, o := range s.CORSAllowedOrigins {
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

	if s.CORSAllowCredentials && responseOrigin != "*" {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	return true
}

// localizeIdPList applies localization to a slice of IdPInfo based on
// language preferences.
func localizeIdPList(idps []domain.IdPInfo, prefs []string, defaultLang string) []domain.IdPInfo {
	if len(idps) == 0 {
		return idps
	}
	localized := make([]domain.IdPInfo, len(idps))
	for i, idp := range idps {
		localized[i] = domain.LocalizeIdPInfo(idp, prefs, defaultLang)
	}
	return localized
}

// ParseAcceptLanguage parses the Accept-Language header and returns
// language tags sorted by quality value (highest first).
// For language tags with region (e.g., "en-US"), the base language
// is also included (e.g., "en") as a fallback.
// Exported for testing purposes.
func ParseAcceptLanguage(header string) []string {
	if header == "" {
		return []string{}
	}

	type langQ struct {
		lang string
		q    float64
	}

	var langs []langQ

	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		lang := part
		q := 1.0

		if idx := strings.Index(part, ";"); idx != -1 {
			lang = strings.TrimSpace(part[:idx])
			qPart := strings.TrimSpace(part[idx+1:])
			if strings.HasPrefix(qPart, "q=") {
				if parsed, err := strconv.ParseFloat(qPart[2:], 64); err == nil {
					q = parsed
				}
			}
		}

		// Skip empty language strings
		if lang == "" {
			continue
		}

		if q > 0 {
			langs = append(langs, langQ{lang: lang, q: q})
			// Add base language for regional variants (en-US -> en)
			if idx := strings.Index(lang, "-"); idx != -1 {
				base := lang[:idx]
				langs = append(langs, langQ{lang: base, q: q - 0.0001}) // Slightly lower
			}
		}
	}

	// Sort by quality descending
	sort.Slice(langs, func(i, j int) bool {
		return langs[i].q > langs[j].q
	})

	// Deduplicate while preserving order
	seen := make(map[string]bool)
	result := []string{}
	for _, lq := range langs {
		if !seen[lq.lang] {
			seen[lq.lang] = true
			result = append(result, lq.lang)
		}
	}

	return result
}

// MatchesForceAuthnPath checks if the request path matches any force_authn_paths pattern.
// Patterns support wildcard suffix (e.g., "/admin/*" matches "/admin/settings").
// Returns true if the path matches any pattern, false otherwise.
// Exported for testing purposes.
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
