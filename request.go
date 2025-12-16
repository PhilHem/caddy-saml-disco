package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/core/ports"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/request"
)

// Re-export RequestStore interface from ports
type RequestStore = ports.RequestStore

// Re-export request adapter
type InMemoryRequestStore = request.InMemoryRequestStore

var (
	NewInMemoryRequestStore            = request.NewInMemoryRequestStore
	NewInMemoryRequestStoreWithCleanup = request.NewInMemoryRequestStoreWithCleanup
	WithOnCleanup                      = request.WithOnCleanup
)
