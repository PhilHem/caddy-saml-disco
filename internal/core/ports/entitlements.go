package ports

import (
	"context"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// EntitlementStore is the port interface for entitlement lookup.
type EntitlementStore interface {
	// Lookup returns entitlements for a subject (SAML NameID, email, etc.).
	// Returns ErrEntitlementNotFound if not found AND default_action is deny.
	// Returns empty EntitlementResult with Matched=false if default_action is allow.
	Lookup(subject string) (*domain.EntitlementResult, error)

	// Refresh reloads entitlements from the source.
	Refresh(ctx context.Context) error
}
