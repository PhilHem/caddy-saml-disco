//go:build unit

package metadata

import (
	"testing"
)

// Cycle 9: Metadata parser scope extraction tests
func TestParseMetadata_WithScope(t *testing.T) {
	xml := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <Extensions>
      <Scope xmlns="urn:mace:shibboleth:metadata:1.0" regexp="false">example.edu</Scope>
    </Extensions>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

	idps, _, err := ParseMetadata([]byte(xml))
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}

	if len(idps) != 1 {
		t.Fatalf("ParseMetadata() returned %d IdPs, want 1", len(idps))
	}

	idp := idps[0]
	if len(idp.AllowedScopes) != 1 {
		t.Fatalf("IdP.AllowedScopes length = %d, want 1", len(idp.AllowedScopes))
	}

	if idp.AllowedScopes[0].Value != "example.edu" {
		t.Errorf("IdP.AllowedScopes[0].Value = %q, want %q", idp.AllowedScopes[0].Value, "example.edu")
	}

	if idp.AllowedScopes[0].Regexp != false {
		t.Errorf("IdP.AllowedScopes[0].Regexp = %v, want false", idp.AllowedScopes[0].Regexp)
	}
}

func TestParseMetadata_WithRegexScope(t *testing.T) {
	xml := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <Extensions>
      <Scope xmlns="urn:mace:shibboleth:metadata:1.0" regexp="true">.*\.partner\.edu</Scope>
    </Extensions>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

	idps, _, err := ParseMetadata([]byte(xml))
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}

	if len(idps) != 1 {
		t.Fatalf("ParseMetadata() returned %d IdPs, want 1", len(idps))
	}

	idp := idps[0]
	if len(idp.AllowedScopes) != 1 {
		t.Fatalf("IdP.AllowedScopes length = %d, want 1", len(idp.AllowedScopes))
	}

	if idp.AllowedScopes[0].Value != `.*\.partner\.edu` {
		t.Errorf("IdP.AllowedScopes[0].Value = %q, want %q", idp.AllowedScopes[0].Value, `.*\.partner\.edu`)
	}

	if idp.AllowedScopes[0].Regexp != true {
		t.Errorf("IdP.AllowedScopes[0].Regexp = %v, want true", idp.AllowedScopes[0].Regexp)
	}
}

func TestParseMetadata_MultipleScopes(t *testing.T) {
	xml := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <Extensions>
      <Scope xmlns="urn:mace:shibboleth:metadata:1.0" regexp="false">example.edu</Scope>
      <Scope xmlns="urn:mace:shibboleth:metadata:1.0" regexp="true">.*\.partner\.edu</Scope>
    </Extensions>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

	idps, _, err := ParseMetadata([]byte(xml))
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}

	if len(idps) != 1 {
		t.Fatalf("ParseMetadata() returned %d IdPs, want 1", len(idps))
	}

	idp := idps[0]
	if len(idp.AllowedScopes) != 2 {
		t.Fatalf("IdP.AllowedScopes length = %d, want 2", len(idp.AllowedScopes))
	}

	if idp.AllowedScopes[0].Value != "example.edu" {
		t.Errorf("IdP.AllowedScopes[0].Value = %q, want %q", idp.AllowedScopes[0].Value, "example.edu")
	}

	if idp.AllowedScopes[1].Value != `.*\.partner\.edu` {
		t.Errorf("IdP.AllowedScopes[1].Value = %q, want %q", idp.AllowedScopes[1].Value, `.*\.partner\.edu`)
	}
}

func TestParseMetadata_NoScope(t *testing.T) {
	xml := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

	idps, _, err := ParseMetadata([]byte(xml))
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}

	if len(idps) != 1 {
		t.Fatalf("ParseMetadata() returned %d IdPs, want 1", len(idps))
	}

	idp := idps[0]
	if idp.AllowedScopes != nil && len(idp.AllowedScopes) != 0 {
		t.Errorf("IdP.AllowedScopes = %v, want nil or empty", idp.AllowedScopes)
	}
}
