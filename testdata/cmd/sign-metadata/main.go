//go:build ignore

// sign-metadata generates pre-signed SAML metadata files for unit tests.
// Run with: go run testdata/cmd/sign-metadata/main.go
package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Files to sign (relative to testdata/).
var filesToSign = []string{
	"idp-metadata.xml",
	"aggregate-metadata.xml",
	"nested-metadata.xml",
}

func main() {
	// Find testdata directory (works when run from repo root)
	testdataDir := "testdata"
	if _, err := os.Stat(testdataDir); os.IsNotExist(err) {
		log.Fatalf("testdata directory not found; run from repo root")
	}

	// Load signing key pair
	key, err := loadPrivateKey(filepath.Join(testdataDir, "sp-key.pem"))
	if err != nil {
		log.Fatalf("load private key: %v", err)
	}
	cert, err := loadCertificate(filepath.Join(testdataDir, "sp-cert.pem"))
	if err != nil {
		log.Fatalf("load certificate: %v", err)
	}

	// Create output directory
	signedDir := filepath.Join(testdataDir, "signed")
	if err := os.MkdirAll(signedDir, 0755); err != nil {
		log.Fatalf("create signed directory: %v", err)
	}

	// Sign each file
	for _, filename := range filesToSign {
		inputPath := filepath.Join(testdataDir, filename)
		outputPath := filepath.Join(signedDir, filename)

		if err := signFile(inputPath, outputPath, key, cert); err != nil {
			log.Fatalf("sign %s: %v", filename, err)
		}
		fmt.Printf("signed: %s -> %s\n", inputPath, outputPath)
	}

	fmt.Printf("\nGenerated %d signed metadata files in %s/\n", len(filesToSign), signedDir)
}

func signFile(inputPath, outputPath string, key *rsa.PrivateKey, cert *x509.Certificate) error {
	// Read input
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	// Parse XML
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return fmt.Errorf("parse XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return fmt.Errorf("empty XML document")
	}

	// Create signing context
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}
	keyStore := dsig.TLSCertKeyStore(tlsCert)
	signingContext := dsig.NewDefaultSigningContext(keyStore)
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// Sign
	signedRoot, err := signingContext.SignEnveloped(root)
	if err != nil {
		return fmt.Errorf("sign XML: %w", err)
	}
	doc.SetRoot(signedRoot)

	// Write output
	signedBytes, err := doc.WriteToBytes()
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	if err := os.WriteFile(outputPath, signedBytes, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try PKCS8 first, then PKCS1
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsaKey, nil
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return rsaKey, nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	return x509.ParseCertificate(block.Bytes)
}
