// Command testidp runs a standalone test SAML Identity Provider for manual testing.
// Usage: go run ./cmd/testidp
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml/samlidp"
)

func main() {
	port := flag.Int("port", 8443, "Port to listen on")
	spMetadataURL := flag.String("sp-metadata", "http://localhost:9080/saml/metadata", "SP metadata URL to register")
	flag.Parse()

	// Generate self-signed certificate
	key, cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	store := &samlidp.MemoryStore{}

	baseURL, _ := url.Parse(fmt.Sprintf("http://localhost:%d", *port))

	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *baseURL,
		Key:         key,
		Certificate: cert,
		Store:       store,
	})
	if err != nil {
		log.Fatalf("Failed to create IdP server: %v", err)
	}

	// Add test user via HTTP PUT (so password gets hashed properly)
	go func() {
		time.Sleep(100 * time.Millisecond) // Wait for server to start
		if err := addUserViaHTTP(fmt.Sprintf("http://localhost:%d", *port), "testuser", "password"); err != nil {
			log.Fatalf("Failed to add test user: %v", err)
		}
		log.Println("Added test user: testuser / password")
	}()

	// Try to register the SP
	go func() {
		time.Sleep(2 * time.Second) // Wait for SP to be ready
		if err := registerSP(store, *spMetadataURL, fmt.Sprintf("http://localhost:%d", *port)); err != nil {
			log.Printf("Warning: Failed to register SP from %s: %v", *spMetadataURL, err)
			log.Println("You may need to manually register the SP or ensure the SP is running")
		} else {
			log.Printf("Registered SP from %s", *spMetadataURL)
		}
	}()

	// Print IdP info
	log.Printf("Test IdP starting on http://localhost:%d", *port)
	log.Printf("  Metadata: http://localhost:%d/metadata", *port)
	log.Printf("  SSO:      http://localhost:%d/sso", *port)
	log.Printf("  Login:    http://localhost:%d/login", *port)
	log.Println()
	log.Println("Test credentials: testuser / password")

	if err := http.ListenAndServe(fmt.Sprintf(":%d", *port), idpServer); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func addUserViaHTTP(baseURL, username, password string) error {
	user := samlidp.User{
		Name:              username,
		PlaintextPassword: &password,
		Email:             username + "@example.com",
		CommonName:        username,
		GivenName:         username,
		Surname:           "Test",
	}

	body, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshal user: %w", err)
	}

	req, err := http.NewRequest(http.MethodPut, baseURL+"/users/"+username, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("put user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("put user status: %d", resp.StatusCode)
	}

	return nil
}

func registerSP(store *samlidp.MemoryStore, metadataURL, idpBaseURL string) error {
	resp, err := http.Get(metadataURL)
	if err != nil {
		return fmt.Errorf("fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata response status: %d", resp.StatusCode)
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return fmt.Errorf("read metadata: %w", err)
	}

	// Parse to get entityID
	var entityDescriptor struct {
		EntityID string `xml:"entityID,attr"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &entityDescriptor); err != nil {
		return fmt.Errorf("parse metadata: %w", err)
	}

	// Register via HTTP PUT
	req, err := http.NewRequest(http.MethodPut, idpBaseURL+"/services/"+url.PathEscape(entityDescriptor.EntityID), bytes.NewReader(buf.Bytes()))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/xml")

	client := &http.Client{Timeout: 5 * time.Second}
	putResp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("register SP: %w", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode >= 400 {
		return fmt.Errorf("register SP status: %d", putResp.StatusCode)
	}

	return nil
}

func generateSelfSignedCert() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test IdP",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	return key, cert, nil
}
