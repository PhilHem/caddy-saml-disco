//go:build unit

package caddy

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/philiph/caddy-saml-disco/internal/domain"
)

// mockMetadataStore is a test double for MetadataStore.
type mockMetadataStore struct {
	idps []domain.IdPInfo
}

func (m *mockMetadataStore) GetIdP(entityID string) (*domain.IdPInfo, error) {
	for i := range m.idps {
		if m.idps[i].EntityID == entityID {
			return &m.idps[i], nil
		}
	}
	return nil, domain.ErrIdPNotFound
}

func (m *mockMetadataStore) ListIdPs(filter string) ([]domain.IdPInfo, error) {
	return m.idps, nil
}

func (m *mockMetadataStore) Refresh(ctx context.Context) error {
	return nil
}

func (m *mockMetadataStore) Health() domain.MetadataHealth {
	return domain.MetadataHealth{IsFresh: true, IdPCount: len(m.idps)}
}

// mockNextHandler is a test double for the next handler in the middleware chain.
type mockNextHandler struct {
	called bool
}

func (m *mockNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	m.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

var _ caddyhttp.Handler = (*mockNextHandler)(nil)

// capturedHeaders captures headers passed to the downstream handler.
type capturedHeaders struct {
	called  bool
	headers http.Header
}

func (c *capturedHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	c.called = true
	c.headers = r.Header.Clone()
	w.WriteHeader(http.StatusOK)
	return nil
}

var _ caddyhttp.Handler = (*capturedHeaders)(nil)

// testTemplateRenderer returns a template renderer for tests.
// This uses the embedded templates.
func testTemplateRenderer(t *testing.T) *TemplateRenderer {
	t.Helper()
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("failed to create template renderer: %v", err)
	}
	return renderer
}

// loadTestKey loads the test private key from testdata (relative to package directory).
func loadTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	// Note: tests run from package directory, so we need to go up to project root
	keyPEM, err := os.ReadFile("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("read test key: %v", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("key is not RSA, got %T", key)
	}

	return rsaKey
}
