package signature

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadSigningCertificates loads X.509 certificates from a PEM file.
// Supports multiple certificates in a single file for rotation scenarios.
func LoadSigningCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}

	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		data = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}

	return certs, nil
}






