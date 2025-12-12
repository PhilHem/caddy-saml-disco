//go:build unit

package idp

import (
	"net/http"
	"testing"
)

func TestNewTestIdP(t *testing.T) {
	idp := New(t)
	defer idp.Close()

	// Verify metadata endpoint is accessible
	resp, err := http.Get(idp.MetadataURL())
	if err != nil {
		t.Fatalf("failed to fetch metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/samlmetadata+xml" && contentType != "application/xml" {
		t.Logf("content-type: %s (acceptable)", contentType)
	}
}

func TestAddUser(t *testing.T) {
	idp := New(t)
	defer idp.Close()

	// Should not panic
	idp.AddUser("testuser", "testpass")
}

func TestBaseURL(t *testing.T) {
	idp := New(t)
	defer idp.Close()

	url := idp.BaseURL()
	if url == "" {
		t.Error("BaseURL returned empty string")
	}

	// Should be a valid HTTP URL
	if url[:7] != "http://" {
		t.Errorf("expected http:// prefix, got %s", url)
	}
}
