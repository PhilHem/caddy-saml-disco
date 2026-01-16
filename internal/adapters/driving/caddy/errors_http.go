package caddy

import (
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

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
func NewJSONErrorResponse(err *domain.AppError) JSONErrorResponse {
	return JSONErrorResponse{
		Error: JSONErrorDetail{
			Code:    err.Code.String(),
			Message: err.Message,
		},
	}
}

// HTTPStatusForCode returns the HTTP status code for an error code.
// Uses plain integers to maintain framework independence.
func HTTPStatusForCode(code domain.ErrorCode) int {
	switch code {
	case domain.ErrCodeIdPNotFound:
		return 404 // Not Found
	case domain.ErrCodeAuthFailed, domain.ErrCodeSessionInvalid:
		return 401 // Unauthorized
	case domain.ErrCodeBadRequest, domain.ErrCodeSignatureInvalid:
		return 400 // Bad Request
	default:
		return 500 // Internal Server Error
	}
}

// TitleForCode returns a user-friendly title for an error code.
func TitleForCode(code domain.ErrorCode) string {
	switch code {
	case domain.ErrCodeConfigMissing:
		return "Configuration Error"
	case domain.ErrCodeIdPNotFound:
		return "Not Found"
	case domain.ErrCodeAuthFailed:
		return "Authentication Failed"
	case domain.ErrCodeSessionInvalid:
		return "Session Invalid"
	case domain.ErrCodeServiceError:
		return "Service Error"
	case domain.ErrCodeBadRequest:
		return "Invalid Request"
	case domain.ErrCodeSignatureInvalid:
		return "Signature Invalid"
	default:
		return "Error"
	}
}
