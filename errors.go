package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// Re-export error types from domain package for backward compatibility
type ErrorCode = domain.ErrorCode
type AppError = domain.AppError

// Re-export HTTP-related error types from adapter
type JSONErrorResponse = caddy.JSONErrorResponse
type JSONErrorDetail = caddy.JSONErrorDetail

// Re-export error code constants
const (
	ErrCodeConfigMissing    = domain.ErrCodeConfigMissing
	ErrCodeIdPNotFound      = domain.ErrCodeIdPNotFound
	ErrCodeAuthFailed       = domain.ErrCodeAuthFailed
	ErrCodeSessionInvalid   = domain.ErrCodeSessionInvalid
	ErrCodeServiceError     = domain.ErrCodeServiceError
	ErrCodeBadRequest       = domain.ErrCodeBadRequest
	ErrCodeSignatureInvalid = domain.ErrCodeSignatureInvalid
)

// Re-export error constructors
var (
	ConfigError          = domain.ConfigError
	IdPNotFoundError     = domain.IdPNotFoundError
	BadRequestError      = domain.BadRequestError
	AuthError            = domain.AuthError
	ServiceError         = domain.ServiceError
	NewJSONErrorResponse = caddy.NewJSONErrorResponse
)
