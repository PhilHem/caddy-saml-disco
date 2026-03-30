package attributes

import (
	"errors"
	"net/http"
	"strings"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
	"go.uber.org/zap"
)

// HeaderConfig encapsulates configuration for applying attribute headers.
// It captures: attributeHeaders, entitlementHeaders, headerPrefix, stripHeaders, entitlementStore.
type HeaderConfig struct {
	AttributeHeaders   []domain.AttributeMapping
	EntitlementHeaders []EntitlementHeaderMapping
	HeaderPrefix       string
	StripHeaders       bool
	EntitlementStore   ports.EntitlementStore
	// RestoreOnEntitlementError controls whether headers should be restored when
	// entitlement lookup fails. Set to true for SP mode (strict), false for non-SP mode (lenient).
	RestoreOnEntitlementError bool
}

// ApplyAttributeHeadersCore applies SAML attributes and entitlements as HTTP headers
// using the provided configuration. This is the shared logic used by both
// applyAttributeHeaders and applyAttributeHeadersForSP.
func ApplyAttributeHeadersCore(r *http.Request, session *domain.Session, cfg HeaderConfig, logger *zap.Logger) {
	if len(cfg.AttributeHeaders) == 0 && len(cfg.EntitlementHeaders) == 0 {
		return
	}

	// Store original header values before stripping (for rollback on error)
	var originalHeaders map[string][]string
	if cfg.StripHeaders {
		// Save state before stripping
		originalHeaders = make(map[string][]string)
		for _, mapping := range cfg.AttributeHeaders {
			headerToStrip := domain.ApplyHeaderPrefix(cfg.HeaderPrefix, mapping.HeaderName)
			canonical := http.CanonicalHeaderKey(headerToStrip)
			// Find the actual key in the map (may differ in case, especially for non-ASCII)
			// Iterate through all headers to find case-insensitive match
			for key := range r.Header {
				// Use EqualFold for Unicode-aware case-insensitive matching
				if strings.EqualFold(key, headerToStrip) || http.CanonicalHeaderKey(key) == canonical {
					// Save original value before deletion
					originalHeaders[canonical] = r.Header[key]
					// Delete header case-insensitively
					DeleteHeaderCaseInsensitive(r, headerToStrip)
					break
				}
			}
		}
		for _, mapping := range cfg.EntitlementHeaders {
			headerToStrip := domain.ApplyHeaderPrefix(cfg.HeaderPrefix, mapping.HeaderName)
			canonical := http.CanonicalHeaderKey(headerToStrip)
			// Find the actual key in the map (may differ in case, especially for non-ASCII)
			// Iterate through all headers to find case-insensitive match
			for key := range r.Header {
				// Use EqualFold for Unicode-aware case-insensitive matching
				if strings.EqualFold(key, headerToStrip) || http.CanonicalHeaderKey(key) == canonical {
					// Save original value before deletion
					originalHeaders[canonical] = r.Header[key]
					// Delete header case-insensitively
					DeleteHeaderCaseInsensitive(r, headerToStrip)
					break
				}
			}
		}
	}

	if session == nil {
		return
	}

	// Convert single-valued session attributes to multi-valued format
	// (Session stores map[string]string for backward compatibility,
	// but MapAttributesToHeaders accepts map[string][]string)
	var multiAttrs map[string][]string
	if len(session.Attributes) > 0 {
		multiAttrs = make(map[string][]string, len(session.Attributes))
		for k, v := range session.Attributes {
			multiAttrs[k] = []string{v}
		}
	}

	// Look up entitlements if configured
	var entitlementResult *domain.EntitlementResult
	if cfg.EntitlementStore != nil {
		result, err := cfg.EntitlementStore.Lookup(session.Subject)
		if err != nil {
			// Log error but continue - entitlements are supplementary
			// ErrEntitlementNotFound is expected for users not in entitlements file
			if !errors.Is(err, domain.ErrEntitlementNotFound) {
				logger.Warn("entitlement lookup failed during header mapping",
					zap.Error(err),
					zap.String("subject", session.Subject),
				)
				// If RestoreOnEntitlementError is set (SP mode) and EntitlementHeaders are configured,
				// restore headers before returning (consistent with mapping error behavior - HEADER-012)
				if cfg.RestoreOnEntitlementError && len(cfg.EntitlementHeaders) > 0 && originalHeaders != nil {
					RestoreHeaderState(r, originalHeaders)
					return
				}
				// Otherwise continue to apply SAML attributes even when entitlement lookup fails
				// (HEADER-015: Entitlements are supplementary, not blocking)
				// entitlementResult remains nil, so entitlement headers won't be set
			}
		} else {
			entitlementResult = result
		}
	}

	// Combine SAML attributes with local entitlements
	combined := domain.CombineAttributes(multiAttrs, entitlementResult)

	// Map SAML attributes to headers (if AttributeHeaders configured)
	if len(cfg.AttributeHeaders) > 0 && len(combined.SAMLAttributes) > 0 {
		// Convert domain.AttributeMapping to ports.AttributeMapping
		portMappings := make([]ports.AttributeMapping, len(cfg.AttributeHeaders))
		for i, m := range cfg.AttributeHeaders {
			portMappings[i] = ports.AttributeMapping{
				SAMLAttribute: m.SAMLAttribute,
				HeaderName:    m.HeaderName,
				Separator:     m.Separator,
			}
		}
		headers, err := domain.MapAttributesToHeadersWithPrefix(combined.SAMLAttributes, portMappings, cfg.HeaderPrefix)
		if err != nil {
			// Configuration error - should have been caught at startup
			// Restore original headers before returning
			if originalHeaders != nil {
				RestoreHeaderState(r, originalHeaders)
			}
			logger.Error("failed to map attributes to headers",
				zap.Error(err),
				zap.String("subject", session.Subject),
			)
			return
		}

		// Set headers on the request
		for header, value := range headers {
			canonicalHeader := http.CanonicalHeaderKey(header)
			r.Header.Set(canonicalHeader, value)
		}
	}

	// Map entitlements to headers (if EntitlementHeaders configured)
	if len(cfg.EntitlementHeaders) > 0 && entitlementResult != nil {
		mappedEntitlementHeaders, err := MapEntitlementsToHeaders(entitlementResult, cfg.EntitlementHeaders)
		if err != nil {
			// Restore original headers before returning
			if originalHeaders != nil {
				RestoreHeaderState(r, originalHeaders)
			}
			logger.Error("failed to map entitlements to headers",
				zap.Error(err),
				zap.String("subject", session.Subject),
			)
			return
		}

		// Apply prefix to entitlement headers
		for header, value := range mappedEntitlementHeaders {
			finalHeader := domain.ApplyHeaderPrefix(cfg.HeaderPrefix, header)
			finalHeader = http.CanonicalHeaderKey(finalHeader)
			r.Header.Set(finalHeader, value)
		}
	}
}

// SaveHeaderState stores original header values before stripping for rollback on error.
// Returns a map of canonical header names to their original values (preserving multiple values).
func SaveHeaderState(r *http.Request, mappings []domain.AttributeMapping, prefix string) map[string][]string {
	originalHeaders := make(map[string][]string)
	for _, mapping := range mappings {
		headerName := domain.ApplyHeaderPrefix(prefix, mapping.HeaderName)
		headerName = http.CanonicalHeaderKey(headerName)
		if values := r.Header[headerName]; len(values) > 0 {
			originalHeaders[headerName] = values
		}
	}
	return originalHeaders
}

// RestoreHeaderState restores original header values from the saved state.
// Deletes existing values first to prevent accumulation (HEADER-016).
func RestoreHeaderState(r *http.Request, originalHeaders map[string][]string) {
	// Delete current values before restoring to prevent accumulation
	for name := range originalHeaders {
		r.Header.Del(name)
	}
	// Restore original values
	for name, values := range originalHeaders {
		for _, value := range values {
			r.Header.Add(name, value)
		}
	}
}

// DeleteHeaderCaseInsensitive deletes a header from the request using case-insensitive matching.
// This is necessary because http.Header.Del() is case-sensitive for the map key, but HTTP headers
// are case-insensitive. For non-ASCII characters, http.CanonicalHeaderKey may not normalize
// correctly, so we need to find the actual key in the map using case-insensitive comparison.
func DeleteHeaderCaseInsensitive(r *http.Request, headerName string) {
	// Use http.Header.Get to check if header exists (case-insensitive)
	// Then find and delete the actual key in the map
	canonical := http.CanonicalHeaderKey(headerName)
	if r.Header.Get(canonical) == "" {
		return // Header doesn't exist
	}

	// Find the actual key(s) in the map that match case-insensitively
	// Use strings.EqualFold for Unicode-aware case-insensitive comparison
	keysToDelete := make([]string, 0)
	for key := range r.Header {
		// Compare using EqualFold for Unicode-aware case-insensitive matching
		// Also check canonical forms in case EqualFold doesn't work for all cases
		if strings.EqualFold(key, headerName) || http.CanonicalHeaderKey(key) == canonical {
			keysToDelete = append(keysToDelete, key)
		}
	}

	// Delete all matching keys
	for _, key := range keysToDelete {
		delete(r.Header, key)
	}
}
