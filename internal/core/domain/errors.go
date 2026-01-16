package domain

import (
	"fmt"
)

// ErrorCode represents categorized error types.
// These codes are stable and can be used for programmatic error handling.
type ErrorCode string

const (
	ErrCodeConfigMissing    ErrorCode = "config_missing"
	ErrCodeIdPNotFound      ErrorCode = "idp_not_found"
	ErrCodeAuthFailed       ErrorCode = "auth_failed"
	ErrCodeSessionInvalid   ErrorCode = "session_invalid"
	ErrCodeServiceError     ErrorCode = "service_error"
	ErrCodeBadRequest       ErrorCode = "bad_request"
	ErrCodeSignatureInvalid ErrorCode = "signature_invalid"
)

// String returns the error code as a string.
func (c ErrorCode) String() string {
	return string(c)
}

// SAMLErrorCategory categorizes SAML authentication failures.
// Used for metrics and structured logging.
type SAMLErrorCategory string

const (
	SAMLErrSignatureVerification SAMLErrorCategory = "signature_verification"
	SAMLErrDecryptionFailed      SAMLErrorCategory = "decryption_failed"
	SAMLErrTimeConstraint        SAMLErrorCategory = "time_constraint"
	SAMLErrIdPStatus             SAMLErrorCategory = "idp_status"
	SAMLErrUnknown               SAMLErrorCategory = "unknown"
)

// String returns the category as a string.
func (c SAMLErrorCategory) String() string {
	return string(c)
}

// AppError is a structured error with code, message, and optional cause.
type AppError struct {
	Code    ErrorCode
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *AppError) Error() string {
	return e.Message
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *AppError) Unwrap() error {
	return e.Cause
}

// ConfigError creates a configuration error.
func ConfigError(message string) *AppError {
	return &AppError{Code: ErrCodeConfigMissing, Message: message}
}

// IdPNotFoundError creates an IdP not found error.
func IdPNotFoundError(entityID string) *AppError {
	return &AppError{
		Code:    ErrCodeIdPNotFound,
		Message: fmt.Sprintf("The identity provider %q was not found", entityID),
	}
}

// BadRequestError creates a bad request error.
func BadRequestError(message string) *AppError {
	return &AppError{Code: ErrCodeBadRequest, Message: message}
}

// AuthError creates an authentication error with optional cause.
func AuthError(message string, cause error) *AppError {
	return &AppError{Code: ErrCodeAuthFailed, Message: message, Cause: cause}
}

// ServiceError creates a service error.
func ServiceError(message string) *AppError {
	return &AppError{Code: ErrCodeServiceError, Message: message}
}
