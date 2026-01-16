// Package caddysamldisco provides a Caddy v2 plugin for SAML Service Provider
// authentication with Discovery Service support.
//
// This file consolidates all type re-exports from internal packages.
package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/logo"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metrics"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/request"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/session"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/signature"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// =============================================================================
// Domain Types
// =============================================================================

// Session represents an authenticated user session.
type Session = domain.Session

// IdPInfo contains identity provider information.
type IdPInfo = domain.IdPInfo

// UIInfo contains user interface information for an IdP.
type UIInfo = domain.UIInfo

// LocalizedValue represents a value with language variants.
type LocalizedValue = domain.LocalizedValue

// Logo represents an IdP logo with dimensions and URL.
type Logo = domain.Logo

// RegistrationInfo contains IdP registration metadata.
type RegistrationInfo = domain.RegistrationInfo

// MetadataHealth represents the health status of metadata.
type MetadataHealth = domain.MetadataHealth

// ScopeInfo contains scope validation information.
type ScopeInfo = domain.ScopeInfo

// ErrorCode represents error categories.
type ErrorCode = domain.ErrorCode

// AppError is an application-level error with code and details.
type AppError = domain.AppError

// Entitlement represents an access control rule.
type Entitlement = domain.Entitlement

// EntitlementResult contains the result of an entitlement check.
type EntitlementResult = domain.EntitlementResult

// DefaultAction specifies the default action when no rules match.
type DefaultAction = domain.DefaultAction

// SAMLErrorCategory categorizes SAML-related errors.
type SAMLErrorCategory = domain.SAMLErrorCategory

// AuthnOptions contains SAML authentication request options.
type AuthnOptions = domain.AuthnOptions

// =============================================================================
// Port Interfaces
// =============================================================================

// MetadataStore provides access to IdP metadata.
type MetadataStore = ports.MetadataStore

// SessionStore manages user sessions.
type SessionStore = ports.SessionStore

// LogoStore caches and serves IdP logos.
type LogoStore = ports.LogoStore

// CachedLogo represents a cached logo with content type.
type CachedLogo = ports.CachedLogo

// RequestStore stores SAML request state.
type RequestStore = ports.RequestStore

// SignatureVerifier verifies XML signatures.
type SignatureVerifier = ports.SignatureVerifier

// MetadataSigner signs metadata XML.
type MetadataSigner = ports.MetadataSigner

// MetricsRecorder records application metrics.
type MetricsRecorder = ports.MetricsRecorder

// EntitlementStore provides access to entitlements.
type EntitlementStore = ports.EntitlementStore

// PortAttributeMapping is the port-level attribute mapping type.
type PortAttributeMapping = ports.AttributeMapping

// AttributeMapper maps SAML attributes to headers.
type AttributeMapper = ports.AttributeMapper

// =============================================================================
// Adapter Types - Caddy
// =============================================================================

// SAMLDisco is the main Caddy module for SAML authentication.
type SAMLDisco = caddy.SAMLDisco

// Config contains SAML configuration for Caddy.
type Config = caddy.Config

// AltLoginConfig configures alternative login options.
type AltLoginConfig = caddy.AltLoginConfig

// AttributeMapping maps SAML attributes to HTTP headers.
type AttributeMapping = caddy.AttributeMapping

// SAMLService handles SAML authentication flows.
type SAMLService = caddy.SAMLService

// AuthResult contains the result of SAML authentication.
type AuthResult = caddy.AuthResult

// TemplateRenderer renders HTML templates.
type TemplateRenderer = caddy.TemplateRenderer

// DiscoData contains data for the discovery page template.
type DiscoData = caddy.DiscoData

// AltLoginOption represents an alternative login option.
type AltLoginOption = caddy.AltLoginOption

// ErrorData contains data for error page templates.
type ErrorData = caddy.ErrorData

// JSONErrorResponse is the JSON format for error responses.
type JSONErrorResponse = caddy.JSONErrorResponse

// JSONErrorDetail contains error details in JSON format.
type JSONErrorDetail = caddy.JSONErrorDetail

// HealthResponse is the JSON format for health check responses.
type HealthResponse = caddy.HealthResponse

// =============================================================================
// Adapter Types - Metadata
// =============================================================================

// MetadataOption configures metadata store behavior.
type MetadataOption = metadata.MetadataOption

// Clock provides time for metadata expiration checks.
type Clock = metadata.Clock

// RealClock uses the system clock.
type RealClock = metadata.RealClock

// InMemoryMetadataStore stores metadata in memory.
type InMemoryMetadataStore = metadata.InMemoryMetadataStore

// FileMetadataStore loads metadata from a file.
type FileMetadataStore = metadata.FileMetadataStore

// URLMetadataStore loads metadata from a URL.
type URLMetadataStore = metadata.URLMetadataStore

// =============================================================================
// Adapter Types - Session
// =============================================================================

// CookieSessionStore stores sessions in cookies.
type CookieSessionStore = session.CookieSessionStore

// =============================================================================
// Adapter Types - Request
// =============================================================================

// InMemoryRequestStore stores SAML request state in memory.
type InMemoryRequestStore = request.InMemoryRequestStore

// =============================================================================
// Adapter Types - Logo
// =============================================================================

// InMemoryLogoStore stores logos in memory.
type InMemoryLogoStore = logo.InMemoryLogoStore

// CachingLogoStore caches logos fetched from URLs.
type CachingLogoStore = logo.CachingLogoStore

// =============================================================================
// Adapter Types - Signature
// =============================================================================

// NoopVerifier is a no-op signature verifier for testing.
type NoopVerifier = signature.NoopVerifier

// NoopSigner is a no-op metadata signer for testing.
type NoopSigner = signature.NoopSigner

// XMLDsigVerifier verifies XML digital signatures.
type XMLDsigVerifier = signature.XMLDsigVerifier

// XMLDsigSigner signs XML metadata.
type XMLDsigSigner = signature.XMLDsigSigner

// VerificationDetails contains signature verification results.
type VerificationDetails = signature.VerificationDetails

// =============================================================================
// Adapter Types - Metrics
// =============================================================================

// NoopMetricsRecorder is a no-op metrics recorder.
type NoopMetricsRecorder = metrics.NoopMetricsRecorder

// PrometheusMetricsRecorder records metrics to Prometheus.
type PrometheusMetricsRecorder = metrics.PrometheusMetricsRecorder

// =============================================================================
// Adapter Types - Entitlements
// =============================================================================

// EntitlementsFile represents the entitlements configuration file format.
type EntitlementsFile = entitlements.EntitlementsFile

// FileEntitlementStore loads entitlements from a file.
type FileEntitlementStore = entitlements.FileEntitlementStore

// InMemoryEntitlementStore stores entitlements in memory.
type InMemoryEntitlementStore = entitlements.InMemoryEntitlementStore
