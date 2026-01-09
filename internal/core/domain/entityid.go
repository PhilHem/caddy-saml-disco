package domain

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateEntityID validates a SAML EntityID string.
// Per SAML 2.0 spec, EntityID must be a valid URI with http, https, or urn scheme.
// Returns nil if valid, error otherwise.
func ValidateEntityID(id string) error {
	if id == "" {
		return fmt.Errorf("entity_id is required")
	}
	if len(id) > 1024 {
		return fmt.Errorf("entity_id too long: %d chars (max 1024)", len(id))
	}
	u, err := url.Parse(id)
	if err != nil {
		return fmt.Errorf("entity_id must be a valid URI: %w", err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("entity_id must have a scheme (e.g., https:// or urn:)")
	}
	validSchemes := map[string]bool{"http": true, "https": true, "urn": true}
	if !validSchemes[strings.ToLower(u.Scheme)] {
		return fmt.Errorf("entity_id scheme must be http, https, or urn; got %q", u.Scheme)
	}
	return nil
}
