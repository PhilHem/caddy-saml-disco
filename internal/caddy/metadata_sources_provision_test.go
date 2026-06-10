//go:build unit

package caddy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	caddy2 "github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// TestProvisionSPConfig_MetadataSources_File verifies the regression fix: a
// config whose MetadataSources holds a file entry provisions a working store
// that serves the source's IdPs. Before the fix, sources-based config produced
// a nil store because provisionSPConfig only consulted the legacy
// MetadataURL/MetadataFile fields.
func TestProvisionSPConfig_MetadataSources_File(t *testing.T) {
	s := &SAMLDisco{logger: zap.NewNop()}
	s.initMetricsRecorder()

	spCfg := &SPConfig{}
	spCfg.MetadataSources = []MetadataSource{
		{File: "../../testdata/idp-metadata.xml"},
	}
	spCfg.Config.SetDefaults()

	if err := s.provisionSPConfig(caddy2.Context{}, spCfg); err != nil {
		t.Fatalf("provisionSPConfig() error = %v", err)
	}

	if spCfg.metadataStore == nil {
		t.Fatal("expected a non-nil metadata store for sources-based config")
	}

	idps, err := spCfg.metadataStore.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() error = %v", err)
	}
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP from file source, got %d", len(idps))
	}
	if idps[0].EntityID != "https://idp.example.com/saml" {
		t.Errorf("EntityID = %q, want %q", idps[0].EntityID, "https://idp.example.com/saml")
	}
}

// TestProvisionSPConfig_MetadataSources_URL verifies a URL-backed source entry
// is provisioned and serves IdPs.
func TestProvisionSPConfig_MetadataSources_URL(t *testing.T) {
	metadataXML, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(metadataXML)
	}))
	defer server.Close()

	s := &SAMLDisco{logger: zap.NewNop()}
	s.initMetricsRecorder()

	spCfg := &SPConfig{}
	spCfg.MetadataSources = []MetadataSource{
		{URL: server.URL},
	}
	spCfg.Config.SetDefaults()

	if err := s.provisionSPConfig(caddy2.Context{}, spCfg); err != nil {
		t.Fatalf("provisionSPConfig() error = %v", err)
	}
	if spCfg.metadataStore == nil {
		t.Fatal("expected a non-nil metadata store for URL sources-based config")
	}
	idps, err := spCfg.metadataStore.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() error = %v", err)
	}
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP from URL source, got %d", len(idps))
	}
}

// TestProvisionSPConfig_ExpiredURLSource_SurvivesAndSelfHeals verifies Fix 2 and
// Fix 3 at the provisioner level: an expired/unreachable URL source must not
// abort provisioning; the store is installed with an empty IdP list and is
// promoted to background refresh so it recovers when the upstream serves fresh
// metadata.
func TestProvisionSPConfig_ExpiredURLSource_SurvivesAndSelfHeals(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		// Always serve an expired aggregate; the parser rejects it.
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2020-01-01T00:00:00Z">
  <EntityDescriptor entityID="https://stale-idp.example.com/saml">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://stale-idp.example.com/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`))
	}))
	defer server.Close()

	core, logs := observer.New(zap.ErrorLevel)
	s := &SAMLDisco{logger: zap.New(core)}
	s.initMetricsRecorder()

	spCfg := &SPConfig{}
	spCfg.MetadataSources = []MetadataSource{
		{URL: server.URL},
	}
	spCfg.Config.SetDefaults()

	// Provisioning must succeed despite the expired upstream.
	if err := s.provisionSPConfig(caddy2.Context{}, spCfg); err != nil {
		t.Fatalf("provisionSPConfig() must not fail on expired metadata, got: %v", err)
	}

	// A structured ERROR-level log must record the degraded load.
	errorLogs := logs.FilterLevelExact(zap.ErrorLevel)
	if errorLogs.Len() == 0 {
		t.Fatal("expected an ERROR-level log for the failed initial load")
	}
	fields := errorLogs.All()[0].ContextMap()
	if _, ok := fields["source"]; !ok {
		t.Error("expected 'source' field in the degraded-load error log")
	}
	if _, ok := fields["error"]; !ok {
		t.Error("expected 'error' field in the degraded-load error log")
	}
	if spCfg.metadataStore == nil {
		t.Fatal("expected a non-nil (empty) metadata store after degraded load")
	}
	// Empty IdP list: expired entity descriptors are never served.
	idps, err := spCfg.metadataStore.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() error = %v", err)
	}
	if len(idps) != 0 {
		t.Errorf("expected empty IdP list after expired load, got %d", len(idps))
	}

	// The store must have been promoted to background refresh so it can heal.
	if closer, ok := spCfg.metadataStore.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}
