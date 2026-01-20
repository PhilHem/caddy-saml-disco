package metadata

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// joinErrors combines multiple errors into a single error.
// Returns nil if the errors slice is empty.
func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return fmt.Errorf("multiple refresh errors: %v", errors.Join(errs...))
}

// CompositeMetadataStore aggregates multiple MetadataStore instances.
// It queries stores in order and combines results, deduplicating by EntityID.
type CompositeMetadataStore struct {
	stores []ports.MetadataStore
	mu     sync.RWMutex
}

// NewCompositeMetadataStore creates a new CompositeMetadataStore wrapping the given stores.
func NewCompositeMetadataStore(stores []ports.MetadataStore) *CompositeMetadataStore {
	return &CompositeMetadataStore{
		stores: stores,
	}
}

// GetIdP returns information about a specific IdP by entity ID.
// Queries stores in order and returns the first match.
// Returns ErrIdPNotFound if no store contains the IdP.
func (c *CompositeMetadataStore) GetIdP(entityID string) (*domain.IdPInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, store := range c.stores {
		idp, err := store.GetIdP(entityID)
		if err == nil {
			return idp, nil
		}
		// Continue to next store on any error (including NotFound)
	}
	return nil, domain.ErrIdPNotFound
}

// ListIdPs returns all IdPs from all stores, deduplicated by EntityID.
// First occurrence of an EntityID wins if duplicates exist across stores.
func (c *CompositeMetadataStore) ListIdPs(filter string) ([]domain.IdPInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	seen := make(map[string]bool)
	result := make([]domain.IdPInfo, 0)

	for _, store := range c.stores {
		idps, err := store.ListIdPs(filter)
		if err != nil {
			// Continue to next store on error
			continue
		}

		for _, idp := range idps {
			if !seen[idp.EntityID] {
				seen[idp.EntityID] = true
				result = append(result, idp)
			}
		}
	}

	return result, nil
}

// Load performs initial metadata load from all wrapped stores.
// This is called during provisioning to ensure metadata is available at startup.
// Continues on failure, collecting all errors and returning a combined error.
func (c *CompositeMetadataStore) Load() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var errors []error

	for _, store := range c.stores {
		// Check if this store implements Load()
		if loader, ok := store.(interface{ Load() error }); ok {
			if err := loader.Load(); err != nil {
				errors = append(errors, err)
			}
		}
	}

	if len(errors) > 0 {
		return joinErrors(errors)
	}
	return nil
}

// Refresh reloads metadata from all wrapped stores.
// Continues on failure, collecting all errors and returning a combined error.
func (c *CompositeMetadataStore) Refresh(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var errors []error

	for _, store := range c.stores {
		if err := store.Refresh(ctx); err != nil {
			errors = append(errors, err)
		}
	}

	// Return combined error if any store failed
	if len(errors) > 0 {
		return joinErrors(errors)
	}
	return nil
}

// Health returns aggregated health status from all wrapped stores.
// Combines IdP counts and reports the most recent success time.
// IsFresh is true only if all stores are fresh (worst status wins).
func (c *CompositeMetadataStore) Health() domain.MetadataHealth {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.stores) == 0 {
		return domain.MetadataHealth{}
	}

	// Start with the first store's fresh status
	health := domain.MetadataHealth{IsFresh: true}

	for _, store := range c.stores {
		storeHealth := store.Health()
		health.IdPCount += storeHealth.IdPCount

		// Worst status wins: if any store is stale, result is stale
		if !storeHealth.IsFresh {
			health.IsFresh = false
		}

		// Track the most recent success time
		if !storeHealth.LastSuccessTime.IsZero() {
			if health.LastSuccessTime.IsZero() || storeHealth.LastSuccessTime.After(health.LastSuccessTime) {
				health.LastSuccessTime = storeHealth.LastSuccessTime
			}
		}
	}

	return health
}

// Ensure CompositeMetadataStore implements ports.MetadataStore
var _ ports.MetadataStore = (*CompositeMetadataStore)(nil)
