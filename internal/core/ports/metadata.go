package ports

import (
	"context"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// MetadataStore is the port interface for accessing IdP metadata.
type MetadataStore interface {
	// GetIdP returns information about a specific IdP by entity ID.
	GetIdP(entityID string) (*domain.IdPInfo, error)

	// ListIdPs returns all IdPs, optionally filtered by a search term.
	ListIdPs(filter string) ([]domain.IdPInfo, error)

	// Refresh reloads metadata from the source.
	Refresh(ctx context.Context) error

	// Health returns the health status of the metadata store.
	Health() domain.MetadataHealth
}



