//go:build unit

package caddy

import (
	"encoding/json"
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

func TestHTTPStatusForCode(t *testing.T) {
	tests := []struct {
		code   domain.ErrorCode
		status int
	}{
		{domain.ErrCodeConfigMissing, 500},
		{domain.ErrCodeIdPNotFound, 404},
		{domain.ErrCodeAuthFailed, 401},
		{domain.ErrCodeSessionInvalid, 401},
		{domain.ErrCodeServiceError, 500},
		{domain.ErrCodeBadRequest, 400},
		{domain.ErrCodeSignatureInvalid, 400},
	}
	for _, tt := range tests {
		if got := HTTPStatusForCode(tt.code); got != tt.status {
			t.Errorf("HTTPStatusForCode(%s) = %d, want %d", tt.code, got, tt.status)
		}
	}
}

func TestTitleForCode(t *testing.T) {
	tests := []struct {
		code  domain.ErrorCode
		title string
	}{
		{domain.ErrCodeConfigMissing, "Configuration Error"},
		{domain.ErrCodeIdPNotFound, "Not Found"},
		{domain.ErrCodeAuthFailed, "Authentication Failed"},
		{domain.ErrCodeSessionInvalid, "Session Invalid"},
		{domain.ErrCodeServiceError, "Service Error"},
		{domain.ErrCodeBadRequest, "Invalid Request"},
		{domain.ErrCodeSignatureInvalid, "Signature Invalid"},
	}
	for _, tt := range tests {
		if got := TitleForCode(tt.code); got != tt.title {
			t.Errorf("TitleForCode(%s) = %q, want %q", tt.code, got, tt.title)
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
	appErr := &domain.AppError{
		Code:    domain.ErrCodeIdPNotFound,
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
