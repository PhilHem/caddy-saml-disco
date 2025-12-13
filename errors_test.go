//go:build unit

package caddysamldisco

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestErrorCode_String(t *testing.T) {
	tests := []struct {
		code ErrorCode
		want string
	}{
		{ErrCodeConfigMissing, "config_missing"},
		{ErrCodeIdPNotFound, "idp_not_found"},
		{ErrCodeAuthFailed, "auth_failed"},
		{ErrCodeSessionInvalid, "session_invalid"},
		{ErrCodeServiceError, "service_error"},
		{ErrCodeBadRequest, "bad_request"},
	}
	for _, tt := range tests {
		if got := tt.code.String(); got != tt.want {
			t.Errorf("ErrorCode.String() = %q, want %q", got, tt.want)
		}
	}
}

func TestAppError_Error(t *testing.T) {
	err := &AppError{
		Code:    ErrCodeIdPNotFound,
		Message: "IdP not found",
	}
	if err.Error() != "IdP not found" {
		t.Errorf("AppError.Error() = %q, want %q", err.Error(), "IdP not found")
	}
}

func TestAppError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &AppError{
		Code:    ErrCodeServiceError,
		Message: "Service error",
		Cause:   cause,
	}
	if err.Unwrap() != cause {
		t.Error("AppError.Unwrap() should return cause")
	}
}

func TestAppError_Unwrap_Nil(t *testing.T) {
	err := &AppError{
		Code:    ErrCodeBadRequest,
		Message: "Bad request",
	}
	if err.Unwrap() != nil {
		t.Error("AppError.Unwrap() should return nil when no cause")
	}
}

func TestErrorCode_HTTPStatus(t *testing.T) {
	tests := []struct {
		code   ErrorCode
		status int
	}{
		{ErrCodeConfigMissing, 500},
		{ErrCodeIdPNotFound, 404},
		{ErrCodeAuthFailed, 401},
		{ErrCodeSessionInvalid, 401},
		{ErrCodeServiceError, 500},
		{ErrCodeBadRequest, 400},
	}
	for _, tt := range tests {
		if got := tt.code.HTTPStatus(); got != tt.status {
			t.Errorf("%s.HTTPStatus() = %d, want %d", tt.code, got, tt.status)
		}
	}
}

func TestErrorCode_Title(t *testing.T) {
	tests := []struct {
		code  ErrorCode
		title string
	}{
		{ErrCodeConfigMissing, "Configuration Error"},
		{ErrCodeIdPNotFound, "Not Found"},
		{ErrCodeAuthFailed, "Authentication Failed"},
		{ErrCodeSessionInvalid, "Session Invalid"},
		{ErrCodeServiceError, "Service Error"},
		{ErrCodeBadRequest, "Invalid Request"},
	}
	for _, tt := range tests {
		if got := tt.code.Title(); got != tt.title {
			t.Errorf("%s.Title() = %q, want %q", tt.code, got, tt.title)
		}
	}
}

func TestJSONErrorResponse_Marshal(t *testing.T) {
	resp := JSONErrorResponse{
		Error: JSONErrorDetail{
			Code:    "idp_not_found",
			Message: "The requested identity provider was not found",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	want := `{"error":{"code":"idp_not_found","message":"The requested identity provider was not found"}}`
	if string(data) != want {
		t.Errorf("json = %s, want %s", data, want)
	}
}

func TestNewJSONErrorResponse(t *testing.T) {
	appErr := &AppError{
		Code:    ErrCodeIdPNotFound,
		Message: "IdP xyz not found",
	}

	resp := NewJSONErrorResponse(appErr)

	if resp.Error.Code != "idp_not_found" {
		t.Errorf("Code = %q, want %q", resp.Error.Code, "idp_not_found")
	}
	if resp.Error.Message != "IdP xyz not found" {
		t.Errorf("Message = %q, want %q", resp.Error.Message, "IdP xyz not found")
	}
}

func TestConfigError(t *testing.T) {
	err := ConfigError("SAML service is not configured")

	if err.Code != ErrCodeConfigMissing {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeConfigMissing)
	}
	if err.Message != "SAML service is not configured" {
		t.Errorf("Message = %q", err.Message)
	}
}

func TestIdPNotFoundError(t *testing.T) {
	err := IdPNotFoundError("https://idp.example.com")

	if err.Code != ErrCodeIdPNotFound {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeIdPNotFound)
	}
	if !strings.Contains(err.Message, "https://idp.example.com") {
		t.Errorf("Message should contain entity ID: %q", err.Message)
	}
}

func TestBadRequestError(t *testing.T) {
	err := BadRequestError("entity_id is required")

	if err.Code != ErrCodeBadRequest {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeBadRequest)
	}
	if err.Message != "entity_id is required" {
		t.Errorf("Message = %q", err.Message)
	}
}

func TestAuthError(t *testing.T) {
	cause := errors.New("signature mismatch")
	err := AuthError("SAML authentication failed", cause)

	if err.Code != ErrCodeAuthFailed {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeAuthFailed)
	}
	if err.Cause != cause {
		t.Error("Cause should be preserved")
	}
}

func TestServiceError(t *testing.T) {
	err := ServiceError("Failed to refresh metadata")

	if err.Code != ErrCodeServiceError {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeServiceError)
	}
	if err.Message != "Failed to refresh metadata" {
		t.Errorf("Message = %q", err.Message)
	}
}
