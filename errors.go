package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// Re-export error types from domain package for backward compatibility
type ErrorCode = domain.ErrorCode
type AppError = domain.AppError
type JSONErrorResponse = domain.JSONErrorResponse
type JSONErrorDetail = domain.JSONErrorDetail

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
	ConfigError      = domain.ConfigError
	IdPNotFoundError = domain.IdPNotFoundError
	BadRequestError  = domain.BadRequestError
	AuthError        = domain.AuthError
	ServiceError     = domain.ServiceError
	NewJSONErrorResponse = domain.NewJSONErrorResponse
)
