//go:build unit

package caddysamldisco

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileMetadataStore_Load(t *testing.T) {
	store := NewFileMetadataStore("testdata/idp-metadata.xml")

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idps))
	}

	idp := idps[0]

	if idp.EntityID != "https://idp.example.com/saml" {
		t.Errorf("EntityID = %q, want %q", idp.EntityID, "https://idp.example.com/saml")
	}

	if idp.DisplayName != "Example IdP" {
		t.Errorf("DisplayName = %q, want %q", idp.DisplayName, "Example IdP")
	}

	if idp.SSOURL != "https://idp.example.com/saml/sso" {
		t.Errorf("SSOURL = %q, want %q", idp.SSOURL, "https://idp.example.com/saml/sso")
	}

	if idp.SSOBinding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
		t.Errorf("SSOBinding = %q, want HTTP-Redirect binding", idp.SSOBinding)
	}

	if len(idp.Certificates) == 0 {
		t.Error("expected at least one certificate")
	}
}

func TestFileMetadataStore_GetIdP(t *testing.T) {
	store := NewFileMetadataStore("testdata/idp-metadata.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Found
	idp, err := store.GetIdP("https://idp.example.com/saml")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}
	if idp.EntityID != "https://idp.example.com/saml" {
		t.Errorf("wrong EntityID returned")
	}

	// Not found
	_, err = store.GetIdP("https://unknown.example.com")
	if err != ErrIdPNotFound {
		t.Errorf("expected ErrIdPNotFound, got %v", err)
	}
}

func TestFileMetadataStore_ListIdPs_Filter(t *testing.T) {
	store := NewFileMetadataStore("testdata/idp-metadata.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	tests := []struct {
		filter   string
		expected int
	}{
		{"", 1},           // no filter
		{"example", 1},    // matches display name and entity ID
		{"IdP", 1},        // matches display name (case insensitive)
		{"unknown", 0},    // no match
		{"EXAMPLE", 1},    // case insensitive
	}

	for _, tc := range tests {
		idps, err := store.ListIdPs(tc.filter)
		if err != nil {
			t.Errorf("ListIdPs(%q) failed: %v", tc.filter, err)
			continue
		}
		if len(idps) != tc.expected {
			t.Errorf("ListIdPs(%q) returned %d IdPs, want %d", tc.filter, len(idps), tc.expected)
		}
	}
}

func TestFileMetadataStore_Refresh(t *testing.T) {
	// Create a temp file for this test
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.xml")

	// Write initial metadata
	initialXML := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://first.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://first.example.com/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>`
	if err := os.WriteFile(path, []byte(initialXML), 0644); err != nil {
		t.Fatalf("write initial metadata: %v", err)
	}

	store := NewFileMetadataStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify initial state
	idp, err := store.GetIdP("https://first.example.com")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}
	if idp.EntityID != "https://first.example.com" {
		t.Errorf("initial EntityID wrong")
	}

	// Update the file
	updatedXML := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://second.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://second.example.com/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>`
	if err := os.WriteFile(path, []byte(updatedXML), 0644); err != nil {
		t.Fatalf("write updated metadata: %v", err)
	}

	// Refresh
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Verify updated state
	_, err = store.GetIdP("https://first.example.com")
	if err != ErrIdPNotFound {
		t.Error("old IdP should not be found after refresh")
	}

	idp, err = store.GetIdP("https://second.example.com")
	if err != nil {
		t.Fatalf("GetIdP() after refresh failed: %v", err)
	}
	if idp.EntityID != "https://second.example.com" {
		t.Errorf("refreshed EntityID wrong")
	}
}

func TestFileMetadataStore_FileNotFound(t *testing.T) {
	store := NewFileMetadataStore("/nonexistent/path/metadata.xml")
	err := store.Load()
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestFileMetadataStore_InvalidXML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.xml")
	if err := os.WriteFile(path, []byte("not valid xml"), 0644); err != nil {
		t.Fatalf("write bad xml: %v", err)
	}

	store := NewFileMetadataStore(path)
	err := store.Load()
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestFileMetadataStore_NoIdPDescriptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sp-only.xml")
	// This is an SP metadata, not IdP
	xml := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
    </SPSSODescriptor>
</EntityDescriptor>`
	if err := os.WriteFile(path, []byte(xml), 0644); err != nil {
		t.Fatalf("write sp metadata: %v", err)
	}

	store := NewFileMetadataStore(path)
	err := store.Load()
	if err == nil {
		t.Error("expected error for SP-only metadata")
	}
}
