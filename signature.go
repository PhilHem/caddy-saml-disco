package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/core/ports"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/signature"
)

// Re-export signature interfaces from ports
type SignatureVerifier = ports.SignatureVerifier
type MetadataSigner = ports.MetadataSigner

// Re-export signature adapters
type NoopVerifier = signature.NoopVerifier
type NoopSigner = signature.NoopSigner
type XMLDsigVerifier = signature.XMLDsigVerifier
type XMLDsigSigner = signature.XMLDsigSigner
type VerificationDetails = signature.VerificationDetails

var (
	NewNoopVerifier                      = signature.NewNoopVerifier
	NewNoopSigner                        = signature.NewNoopSigner
	NewXMLDsigVerifier                   = signature.NewXMLDsigVerifier
	NewXMLDsigVerifierWithCerts          = signature.NewXMLDsigVerifierWithCerts
	NewXMLDsigVerifierWithLogger         = signature.NewXMLDsigVerifierWithLogger
	NewXMLDsigVerifierWithCertsAndLogger = signature.NewXMLDsigVerifierWithCertsAndLogger
	NewXMLDsigSigner                     = signature.NewXMLDsigSigner
	LoadSigningCertificates              = signature.LoadSigningCertificates
)
