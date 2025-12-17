package domain

import (
	"fmt"
	"net/http"
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

// HTTPStatus returns the HTTP status code for this error code.
func (c ErrorCode) HTTPStatus() int {
	switch c {
	case ErrCodeIdPNotFound:
		return http.StatusNotFound
	case ErrCodeAuthFailed, ErrCodeSessionInvalid:
		return http.StatusUnauthorized
	case ErrCodeBadRequest, ErrCodeSignatureInvalid:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// Title returns a user-friendly title for this error code.
func (c ErrorCode) Title() string {
	switch c {
	case ErrCodeConfigMissing:
		return "Configuration Error"
	case ErrCodeIdPNotFound:
		return "Not Found"
	case ErrCodeAuthFailed:
		return "Authentication Failed"
	case ErrCodeSessionInvalid:
		return "Session Invalid"
	case ErrCodeServiceError:
		return "Service Error"
	case ErrCodeBadRequest:
		return "Invalid Request"
	case ErrCodeSignatureInvalid:
		return "Signature Invalid"
	default:
		return "Error"
	}
}

// JSONErrorResponse is the standard JSON error format for API endpoints.
type JSONErrorResponse struct {
	Error JSONErrorDetail `json:"error"`
}

// JSONErrorDetail contains error details.
type JSONErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NewJSONErrorResponse creates a JSON error response from an AppError.
func NewJSONErrorResponse(err *AppError) JSONErrorResponse {
	return JSONErrorResponse{
		Error: JSONErrorDetail{
			Code:    err.Code.String(),
			Message: err.Message,
		},
	}
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



