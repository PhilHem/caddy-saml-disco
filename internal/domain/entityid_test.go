//go:build unit

package domain

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestValidateEntityID_Empty(t *testing.T) {
	err := ValidateEntityID("")
	if err == nil {
		t.Error("expected error for empty entity_id, got nil")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("expected 'required' in error, got: %v", err)
	}
}

func TestValidateEntityID_ValidHTTPS(t *testing.T) {
	err := ValidateEntityID("https://sp.example.com/saml")
	if err != nil {
		t.Errorf("expected nil error for valid HTTPS URL, got: %v", err)
	}
}

func TestValidateEntityID_ValidHTTP(t *testing.T) {
	err := ValidateEntityID("http://sp.example.com/saml")
	if err != nil {
		t.Errorf("expected nil error for valid HTTP URL, got: %v", err)
	}
}

func TestValidateEntityID_ValidURN(t *testing.T) {
	err := ValidateEntityID("urn:mace:incommon:example.edu")
	if err != nil {
		t.Errorf("expected nil error for valid URN, got: %v", err)
	}
}

func TestValidateEntityID_TooLong(t *testing.T) {
	// Create a URL that's over 1024 characters
	longPath := strings.Repeat("a", 1020)
	longID := "https://example.com/" + longPath

	err := ValidateEntityID(longID)
	if err == nil {
		t.Error("expected error for too-long entity_id, got nil")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("expected 'too long' in error, got: %v", err)
	}
}

func TestValidateEntityID_MissingScheme(t *testing.T) {
	err := ValidateEntityID("sp.example.com/saml")
	if err == nil {
		t.Error("expected error for missing scheme, got nil")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("expected 'scheme' in error, got: %v", err)
	}
}

func TestValidateEntityID_InvalidScheme(t *testing.T) {
	err := ValidateEntityID("ftp://sp.example.com/saml")
	if err == nil {
		t.Error("expected error for invalid scheme, got nil")
	}
	if !strings.Contains(err.Error(), "http, https, or urn") {
		t.Errorf("expected scheme list in error, got: %v", err)
	}
}

func TestValidateEntityID_Property_ValidURIs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate valid HTTPS URLs
		host := rapid.StringMatching(`[a-z]{3,10}\.[a-z]{2,5}`).Draw(t, "host")
		path := rapid.StringMatching(`/[a-z]{0,20}`).Draw(t, "path")
		entityID := "https://" + host + path

		err := ValidateEntityID(entityID)
		if err != nil {
			t.Fatalf("expected valid HTTPS URL to pass: %s, got error: %v", entityID, err)
		}
	})
}

func TestValidateEntityID_Property_ValidURNs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate valid URNs
		nid := rapid.StringMatching(`[a-z]{2,8}`).Draw(t, "nid")
		nss := rapid.StringMatching(`[a-z0-9:.-]{1,30}`).Draw(t, "nss")
		entityID := "urn:" + nid + ":" + nss

		err := ValidateEntityID(entityID)
		if err != nil {
			t.Fatalf("expected valid URN to pass: %s, got error: %v", entityID, err)
		}
	})
}

func TestValidateEntityID_Property_InvalidSchemes(t *testing.T) {
	invalidSchemes := []string{"ftp", "file", "mailto", "ssh", "git", "svn"}

	for _, scheme := range invalidSchemes {
		entityID := scheme + "://example.com/path"
		err := ValidateEntityID(entityID)
		if err == nil {
			t.Errorf("expected error for scheme %q, got nil", scheme)
		}
	}
}
