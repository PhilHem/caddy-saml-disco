package caddy

import (
	"errors"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// SAMLErrorDetails holds parsed error information for structured logging.
// @tra: Adapter.SAMLAuthErrors
type SAMLErrorDetails struct {
	Category     domain.SAMLErrorCategory
	Message      string                   // Human-readable description
	PrivateError string                   // Original error from PrivateErr
	IdPStatus    *IdPStatusInfo           // Extracted from Response XML (if available)
	TimeContext  *TimeConstraintContext   // For time constraint errors
}

// IdPStatusInfo contains SAML status information extracted from IdP response.
type IdPStatusInfo struct {
	StatusCode    string // e.g., "urn:oasis:names:tc:SAML:2.0:status:Responder"
	StatusMessage string // Optional message from IdP
}

// TimeConstraintContext provides context for time-based validation failures.
type TimeConstraintContext struct {
	ServerTime       time.Time  // Time used for validation (from Now)
	NotBefore        *time.Time // From assertion (if extractable)
	NotOnOrAfter     *time.Time // From assertion (if extractable)
	ClockSkewSeconds int64      // Estimated skew (if calculable)
}

// ParseSAMLError extracts structured details from crewjam/saml errors.
// It handles both direct InvalidResponseError and wrapped errors.
// @tra: Adapter.SAMLAuthErrors
func ParseSAMLError(err error) *SAMLErrorDetails {
	if err == nil {
		return &SAMLErrorDetails{
			Category: domain.SAMLErrUnknown,
		}
	}

	// Try to unwrap to find InvalidResponseError
	var samlErr *saml.InvalidResponseError
	if errors.As(err, &samlErr) {
		return parseSAMLInvalidResponseError(samlErr)
	}

	// Fall back to string-based categorization for non-SAML errors
	return &SAMLErrorDetails{
		Category:     categorizeByMessage(err.Error()),
		PrivateError: err.Error(),
	}
}

// parseSAMLInvalidResponseError extracts details from a saml.InvalidResponseError.
func parseSAMLInvalidResponseError(err *saml.InvalidResponseError) *SAMLErrorDetails {
	privateErr := ""
	if err.PrivateErr != nil {
		privateErr = err.PrivateErr.Error()
	}

	category := categorizeByMessage(privateErr)
	details := &SAMLErrorDetails{
		Category:     category,
		PrivateError: privateErr,
	}

	// Add time context for time constraint errors
	if category == domain.SAMLErrTimeConstraint {
		details.TimeContext = &TimeConstraintContext{
			ServerTime: err.Now,
		}
	}

	// Try to extract IdP status from response XML
	if category == domain.SAMLErrIdPStatus && err.Response != "" {
		details.IdPStatus = extractIdPStatus(err.Response)
	}

	return details
}

// categorizeByMessage categorizes errors based on message patterns.
func categorizeByMessage(msg string) domain.SAMLErrorCategory {
	if msg == "" {
		return domain.SAMLErrUnknown
	}

	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "signature"):
		return domain.SAMLErrSignatureVerification
	case strings.Contains(lower, "decrypt") || strings.Contains(lower, "encrypt"):
		return domain.SAMLErrDecryptionFailed
	case strings.Contains(lower, "notonorafter") ||
		strings.Contains(lower, "notbefore") ||
		strings.Contains(lower, "expired"):
		return domain.SAMLErrTimeConstraint
	case strings.Contains(lower, "status"):
		return domain.SAMLErrIdPStatus
	default:
		return domain.SAMLErrUnknown
	}
}

// extractIdPStatus parses SAML response XML to extract status code and message.
func extractIdPStatus(responseXML string) *IdPStatusInfo {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(responseXML); err != nil {
		return nil
	}

	root := doc.Root()
	if root == nil {
		return nil
	}

	// Find Status element (with or without namespace prefix)
	var status *etree.Element
	status = root.FindElement("Status")
	if status == nil {
		status = root.FindElement("samlp:Status")
	}
	if status == nil {
		// Try with namespace-aware search
		for _, child := range root.ChildElements() {
			if child.Tag == "Status" {
				status = child
				break
			}
		}
	}
	if status == nil {
		return nil
	}

	info := &IdPStatusInfo{}

	// Find StatusCode
	var statusCode *etree.Element
	statusCode = status.FindElement("StatusCode")
	if statusCode == nil {
		statusCode = status.FindElement("samlp:StatusCode")
	}
	if statusCode == nil {
		for _, child := range status.ChildElements() {
			if child.Tag == "StatusCode" {
				statusCode = child
				break
			}
		}
	}
	if statusCode != nil {
		info.StatusCode = statusCode.SelectAttrValue("Value", "")
	}

	// Find StatusMessage
	var statusMsg *etree.Element
	statusMsg = status.FindElement("StatusMessage")
	if statusMsg == nil {
		statusMsg = status.FindElement("samlp:StatusMessage")
	}
	if statusMsg == nil {
		for _, child := range status.ChildElements() {
			if child.Tag == "StatusMessage" {
				statusMsg = child
				break
			}
		}
	}
	if statusMsg != nil {
		info.StatusMessage = statusMsg.Text()
	}

	// Only return if we found something
	if info.StatusCode == "" && info.StatusMessage == "" {
		return nil
	}

	return info
}
