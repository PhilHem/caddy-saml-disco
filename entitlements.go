package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// Re-export domain entitlement types
type Entitlement = domain.Entitlement
type EntitlementResult = domain.EntitlementResult
type DefaultAction = domain.DefaultAction

// Re-export domain entitlement constants
const (
	DefaultActionDeny  = domain.DefaultActionDeny
	DefaultActionAllow = domain.DefaultActionAllow
)

// Re-export domain entitlement errors
var (
	ErrEntitlementNotFound = domain.ErrEntitlementNotFound
	ErrAccessDenied        = domain.ErrAccessDenied
)

// Re-export domain entitlement functions
var MatchesSubjectPattern = domain.MatchesSubjectPattern

// Re-export port interface
type EntitlementStore = ports.EntitlementStore

// Re-export adapter types
type EntitlementsFile = entitlements.EntitlementsFile
type FileEntitlementStore = entitlements.FileEntitlementStore
type InMemoryEntitlementStore = entitlements.InMemoryEntitlementStore

// Re-export adapter constructors
var (
	NewFileEntitlementStore     = entitlements.NewFileEntitlementStore
	NewInMemoryEntitlementStore = entitlements.NewInMemoryEntitlementStore
)
