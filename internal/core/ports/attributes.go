package ports

import (
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// AttributeMapping is an alias for domain.AttributeMapping for backward compatibility.
// New code should use domain.AttributeMapping directly.
type AttributeMapping = domain.AttributeMapping

// AttributeMapper is the port interface for mapping SAML attributes to HTTP headers.
// Implementations must be thread-safe (safe for concurrent use).
type AttributeMapper interface {
	// MapAttributesToHeaders transforms SAML attributes to HTTP headers.
	// This is a pure function with no side effects or I/O.
	//
	// Security guarantees:
	//   - All header names must start with "X-" (prevents overwriting standard headers)
	//   - All header names contain only valid characters (A-Za-z0-9-)
	//   - Output values are sanitized (no CR/LF, bounded length, no null bytes)
	//   - Missing attributes produce no header (not an empty string)
	//
	// Returns an error if any header name is invalid.
	MapAttributesToHeaders(attrs map[string][]string, mappings []domain.AttributeMapping) (map[string]string, error)

	// MapAttributesToHeadersWithPrefix transforms SAML attributes to HTTP headers with optional prefix.
	// This is a wrapper around MapAttributesToHeaders that applies a prefix to header names.
	// If prefix is set, header names don't need to start with "X-" (the final combined name must be valid).
	// If prefix is empty, existing validation applies (headers must start with "X-").
	MapAttributesToHeadersWithPrefix(attrs map[string][]string, mappings []domain.AttributeMapping, prefix string) (map[string]string, error)
}










