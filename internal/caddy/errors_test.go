package caddy

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSAMLError_SignatureVerification(t *testing.T) {
	tra.Require(t, "Adapter.SAMLAuthErrors")

	err := &saml.InvalidResponseError{
		PrivateErr: errors.New("signature verification failed"),
		Now:        time.Now(),
	}
	details := ParseSAMLError(err)

	assert.Equal(t, domain.SAMLErrSignatureVerification, details.Category)
	assert.Contains(t, details.PrivateError, "signature")
}

func TestParseSAMLError_DecryptionFailed(t *testing.T) {
	tra.Require(t, "Adapter.SAMLAuthErrors")

	tests := []struct {
		name    string
		privErr string
	}{
		{"decrypt keyword", "failed to decrypt assertion"},
		{"encrypt keyword", "encryption error occurred"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := &saml.InvalidResponseError{
				PrivateErr: errors.New(tc.privErr),
				Now:        time.Now(),
			}
			details := ParseSAMLError(err)

			assert.Equal(t, domain.SAMLErrDecryptionFailed, details.Category)
		})
	}
}

func TestParseSAMLError_TimeConstraint(t *testing.T) {
	tra.Require(t, "Adapter.SAMLAuthErrors")

	tests := []struct {
		name    string
		privErr string
	}{
		{"notbefore", "assertion NotBefore time is in the future"},
		{"notonorafter", "assertion NotOnOrAfter has passed"},
		{"expired", "response has expired"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			err := &saml.InvalidResponseError{
				PrivateErr: errors.New(tc.privErr),
				Now:        now,
			}
			details := ParseSAMLError(err)

			assert.Equal(t, domain.SAMLErrTimeConstraint, details.Category)
			require.NotNil(t, details.TimeContext)
			assert.Equal(t, now, details.TimeContext.ServerTime)
		})
	}
}

func TestParseSAMLError_IdPStatus(t *testing.T) {
	tra.Require(t, "Adapter.SAMLAuthErrors")

	responseXML := `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>
    <samlp:StatusMessage>User denied access</samlp:StatusMessage>
  </samlp:Status>
</samlp:Response>`

	err := &saml.InvalidResponseError{
		PrivateErr: errors.New("bad status code"),
		Response:   responseXML,
		Now:        time.Now(),
	}
	details := ParseSAMLError(err)

	assert.Equal(t, domain.SAMLErrIdPStatus, details.Category)
	require.NotNil(t, details.IdPStatus)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:Responder", details.IdPStatus.StatusCode)
	assert.Equal(t, "User denied access", details.IdPStatus.StatusMessage)
}

func TestParseSAMLError_IdPStatus_StatusCodeOnly(t *testing.T) {
	tra.Require(t, "Adapter.SAMLAuthErrors")

	responseXML := `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/>
  </samlp:Status>
</samlp:Response>`

	err := &saml.InvalidResponseError{
		PrivateErr: errors.New("status"),
		Response:   responseXML,
		Now:        time.Now(),
	}
	details := ParseSAMLError(err)

	assert.Equal(t, domain.SAMLErrIdPStatus, details.Category)
	require.NotNil(t, details.IdPStatus)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", details.IdPStatus.StatusCode)
	assert.Empty(t, details.IdPStatus.StatusMessage)
}

func TestParseSAMLError_Unknown(t *testing.T) {
	tra.Require(t, "Adapter.SAMLAuthErrors")

	err := &saml.InvalidResponseError{
		PrivateErr: errors.New("some unexpected error"),
		Now:        time.Now(),
	}
	details := ParseSAMLError(err)

	assert.Equal(t, domain.SAMLErrUnknown, details.Category)
	assert.Equal(t, "some unexpected error", details.PrivateError)
}

func TestParseSAMLError_NilError(t *testing.T) {
	tra.Require(t, "Adapter.SAMLAuthErrors")

	details := ParseSAMLError(nil)

	assert.Equal(t, domain.SAMLErrUnknown, details.Category)
	assert.Empty(t, details.PrivateError)
}

func TestParseSAMLError_NonSAMLError(t *testing.T) {
	tra.Require(t, "Adapter.SAMLAuthErrors")

	err := errors.New("generic error")
	details := ParseSAMLError(err)

	assert.Equal(t, domain.SAMLErrUnknown, details.Category)
	assert.Equal(t, "generic error", details.PrivateError)
}

func TestParseSAMLError_WrappedSAMLError(t *testing.T) {
	tra.Require(t, "Adapter.SAMLAuthErrors")

	inner := &saml.InvalidResponseError{
		PrivateErr: errors.New("signature verification failed"),
		Now:        time.Now(),
	}
	wrapped := fmt.Errorf("parse saml response: %w", inner)

	details := ParseSAMLError(wrapped)

	assert.Equal(t, domain.SAMLErrSignatureVerification, details.Category)
	assert.Contains(t, details.PrivateError, "signature")
}

func TestParseSAMLError_InvalidXMLResponse(t *testing.T) {
	tra.Require(t, "Adapter.SAMLAuthErrors")

	err := &saml.InvalidResponseError{
		PrivateErr: errors.New("status"),
		Response:   "not valid xml",
		Now:        time.Now(),
	}
	details := ParseSAMLError(err)

	// Should still categorize correctly but IdPStatus may be nil
	assert.Equal(t, domain.SAMLErrIdPStatus, details.Category)
	// Invalid XML means we can't extract status
	assert.Nil(t, details.IdPStatus)
}
