// Command multiidp runs multiple test SAML Identity Providers for testing discovery.
// Usage: go run ./cmd/multiidp
//
// This starts 3 IdPs on different ports, each with its own identity:
//   - Port 8081: "TU Berlin" (testuser/password)
//   - Port 8082: "LMU Munich" (testuser/password)
//   - Port 8083: "Uni Heidelberg" (testuser/password)
//
// It also generates a combined metadata file that can be used by the SP.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/crewjam/saml/samlidp"
)

type idpConfig struct {
	Port        int
	Name        string
	DisplayName string
	EntityID    string
}

var idpConfigs = []idpConfig{
	{Port: 8081, Name: "tu-berlin", DisplayName: "TU Berlin", EntityID: "http://localhost:8081/metadata"},
	{Port: 8082, Name: "lmu-munich", DisplayName: "LMU Munich", EntityID: "http://localhost:8082/metadata"},
	{Port: 8083, Name: "uni-heidelberg", DisplayName: "Uni Heidelberg", EntityID: "http://localhost:8083/metadata"},
}

func main() {
	spMetadataURL := flag.String("sp-metadata", "http://localhost:9080/saml/metadata", "SP metadata URL to register")
	outputFile := flag.String("output", "testdata/local-idps-metadata.xml", "Output file for combined metadata")
	flag.Parse()

	var wg sync.WaitGroup
	idpCerts := make(map[int]string) // port -> base64 cert
	var certMu sync.Mutex

	// Start each IdP
	for _, cfg := range idpConfigs {
		wg.Add(1)
		go func(cfg idpConfig) {
			defer wg.Done()
			cert := startIdP(cfg, *spMetadataURL)
			certMu.Lock()
			idpCerts[cfg.Port] = cert
			certMu.Unlock()
		}(cfg)
	}

	// Wait a bit for IdPs to start, then generate combined metadata
	time.Sleep(2 * time.Second)

	certMu.Lock()
	if err := generateCombinedMetadata(*outputFile, idpCerts); err != nil {
		log.Printf("Warning: Failed to generate combined metadata: %v", err)
	} else {
		log.Printf("Generated combined metadata: %s", *outputFile)
	}
	certMu.Unlock()

	log.Println()
	log.Println("All IdPs started. Test credentials: testuser / password")
	log.Println()
	log.Println("To test with discovery UI:")
	log.Printf("  1. Update test-fels.caddyfile to use: metadata_file %s", *outputFile)
	log.Println("  2. Rebuild and restart Caddy")
	log.Println("  3. Browse to http://localhost:9080/saml/disco")

	// Keep running
	select {}
}

func startIdP(cfg idpConfig, spMetadataURL string) string {
	key, cert, err := generateSelfSignedCert(cfg.DisplayName)
	if err != nil {
		log.Fatalf("[%s] Failed to generate certificate: %v", cfg.Name, err)
	}

	// Encode cert for metadata
	certBase64 := base64.StdEncoding.EncodeToString(cert.Raw)

	store := &samlidp.MemoryStore{}
	baseURL, _ := url.Parse(fmt.Sprintf("http://localhost:%d", cfg.Port))

	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *baseURL,
		Key:         key,
		Certificate: cert,
		Store:       store,
	})
	if err != nil {
		log.Fatalf("[%s] Failed to create IdP server: %v", cfg.Name, err)
	}

	// Add test user
	go func() {
		time.Sleep(100 * time.Millisecond)
		if err := addUser(fmt.Sprintf("http://localhost:%d", cfg.Port), "testuser", "password"); err != nil {
			log.Printf("[%s] Warning: Failed to add test user: %v", cfg.Name, err)
		}
	}()

	// Register SP
	go func() {
		time.Sleep(3 * time.Second)
		if err := registerSP(fmt.Sprintf("http://localhost:%d", cfg.Port), spMetadataURL); err != nil {
			log.Printf("[%s] Warning: Failed to register SP: %v", cfg.Name, err)
		} else {
			log.Printf("[%s] Registered SP", cfg.Name)
		}
	}()

	log.Printf("[%s] Starting on http://localhost:%d", cfg.Name, cfg.Port)

	go func() {
		if err := http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), idpServer); err != nil {
			log.Fatalf("[%s] Server failed: %v", cfg.Name, err)
		}
	}()

	return certBase64
}

func generateCombinedMetadata(outputFile string, certs map[int]string) error {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Name="Local Test Federation">
`)

	for _, cfg := range idpConfigs {
		cert := certs[cfg.Port]
		buf.WriteString(fmt.Sprintf(`
    <EntityDescriptor entityID="http://localhost:%d/metadata">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <KeyDescriptor use="signing">
                <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data>
                        <X509Certificate>%s</X509Certificate>
                    </X509Data>
                </KeyInfo>
            </KeyDescriptor>
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                 Location="http://localhost:%d/sso"/>
        </IDPSSODescriptor>
        <Organization>
            <OrganizationName xml:lang="en">%s</OrganizationName>
            <OrganizationDisplayName xml:lang="en">%s</OrganizationDisplayName>
            <OrganizationURL xml:lang="en">http://localhost:%d</OrganizationURL>
        </Organization>
    </EntityDescriptor>
`, cfg.Port, cert, cfg.Port, cfg.DisplayName, cfg.DisplayName, cfg.Port))
	}

	buf.WriteString(`
</EntitiesDescriptor>
`)

	return os.WriteFile(outputFile, buf.Bytes(), 0644)
}

func addUser(baseURL, username, password string) error {
	user := samlidp.User{
		Name:              username,
		PlaintextPassword: &password,
		Email:             username + "@example.com",
		CommonName:        username,
		GivenName:         username,
		Surname:           "Test",
	}

	body, _ := json.Marshal(user)
	req, _ := http.NewRequest(http.MethodPut, baseURL+"/users/"+username, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func registerSP(idpBaseURL, spMetadataURL string) error {
	resp, err := http.Get(spMetadataURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata status %d", resp.StatusCode)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	// Parse entityID from metadata
	// Simple extraction - in production use proper XML parsing
	metadata := buf.String()

	req, _ := http.NewRequest(http.MethodPut, idpBaseURL+"/services/sp", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Type", "application/xml")

	client := &http.Client{Timeout: 5 * time.Second}
	putResp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer putResp.Body.Close()

	if putResp.StatusCode >= 400 {
		return fmt.Errorf("register status %d (metadata len: %d)", putResp.StatusCode, len(metadata))
	}
	return nil
}

func generateSelfSignedCert(cn string) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn + " IdP",
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
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	// Also write PEM files for debugging
	_ = pem.Block{} // suppress unused import warning

	return key, cert, nil
}
