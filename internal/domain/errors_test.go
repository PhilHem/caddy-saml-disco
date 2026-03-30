//go:build unit

package domain

import (
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

func TestSAMLErrorCategory_String(t *testing.T) {
	tests := []struct {
		category SAMLErrorCategory
		want     string
	}{
		{SAMLErrSignatureVerification, "signature_verification"},
		{SAMLErrDecryptionFailed, "decryption_failed"},
		{SAMLErrTimeConstraint, "time_constraint"},
		{SAMLErrIdPStatus, "idp_status"},
		{SAMLErrUnknown, "unknown"},
	}
	for _, tt := range tests {
		if got := tt.category.String(); got != tt.want {
			t.Errorf("SAMLErrorCategory.String() = %q, want %q", got, tt.want)
		}
	}
}

func TestSAMLErrorCategory_AllValues(t *testing.T) {
	// Verify all 5 categories are defined and distinct
	categories := []SAMLErrorCategory{
		SAMLErrSignatureVerification,
		SAMLErrDecryptionFailed,
		SAMLErrTimeConstraint,
		SAMLErrIdPStatus,
		SAMLErrUnknown,
	}

	if len(categories) != 5 {
		t.Errorf("expected 5 categories, got %d", len(categories))
	}

	// Check all are distinct
	seen := make(map[SAMLErrorCategory]bool)
	for _, c := range categories {
		if seen[c] {
			t.Errorf("duplicate category: %s", c)
		}
		seen[c] = true
	}
}
