package caddy

import (
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
	"go.uber.org/zap"
)

// TestBuildMetadataStoreOptions tests the extraction of metadata store options building logic.
func TestBuildMetadataStoreOptions(t *testing.T) {
	tests := []struct {
		name                         string
		idpFilter                    string
		registrationAuthorityFilter  string
		entityCategoryFilter         string
		assuranceCertificationFilter string
		verifyMetadataSignature      bool
		metadataSigningCert          string
		expectedOptionsCount         int
		expectError                  bool
	}{
		{
			name:                 "no filters or verification",
			expectedOptionsCount: 3, // logger, metrics, version
		},
		{
			name:                         "all filters enabled",
			idpFilter:                    "university",
			registrationAuthorityFilter:  "urn:example",
			entityCategoryFilter:         "research",
			assuranceCertificationFilter: "assurance",
			expectedOptionsCount:         7, // 4 filters + logger + metrics + version
		},
		{
			name:                    "signature verification enabled",
			verifyMetadataSignature: true,
			metadataSigningCert:     "../../../../testdata/sp-cert.pem",
			expectedOptionsCount:    4, // verifier + logger + metrics + version
		},
		{
			name:                    "signature verification with missing cert",
			verifyMetadataSignature: true,
			metadataSigningCert:     "../../../../testdata/nonexistent.pem",
			expectError:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SAMLDisco{
				Config: Config{
					IdPFilter:                    tt.idpFilter,
					RegistrationAuthorityFilter:  tt.registrationAuthorityFilter,
					EntityCategoryFilter:         tt.entityCategoryFilter,
					AssuranceCertificationFilter: tt.assuranceCertificationFilter,
					VerifyMetadataSignature:      tt.verifyMetadataSignature,
					MetadataSigningCert:          tt.metadataSigningCert,
				},
				logger: zap.NewNop(),
			}
			s.initMetricsRecorder()

			opts, err := s.buildMetadataStoreOptions()

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(opts) != tt.expectedOptionsCount {
				t.Errorf("expected %d options, got %d", tt.expectedOptionsCount, len(opts))
			}
		})
	}
}

// TestInitializeMetadataStore tests the extraction of metadata store initialization logic.
func TestInitializeMetadataStore(t *testing.T) {
	tests := []struct {
		name              string
		metadataFile      string
		metadataURL       string
		backgroundRefresh bool
		expectStore       bool
		expectType        string
	}{
		{
			name:         "file-based metadata store",
			metadataFile: "../../../../testdata/idp-metadata.xml",
			expectStore:  true,
			expectType:   "file",
		},
		{
			name:        "URL-based metadata store without background refresh",
			metadataURL: "http://example.com/metadata.xml",
			expectStore: true,
			expectType:  "url",
		},
		{
			name:              "URL-based metadata store with background refresh",
			metadataURL:       "http://example.com/metadata.xml",
			backgroundRefresh: true,
			expectStore:       true,
			expectType:        "url_refresh",
		},
		{
			name:        "no metadata source configured",
			expectStore: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SAMLDisco{
				Config: Config{
					MetadataFile:      tt.metadataFile,
					MetadataURL:       tt.metadataURL,
					BackgroundRefresh: tt.backgroundRefresh,
				},
				logger: zap.NewNop(),
			}
			s.initMetricsRecorder()

			refreshInterval := 1 * time.Hour
			opts := []metadata.MetadataOption{
				metadata.WithLogger(s.logger),
			}

			// Note: We don't call Load() here because that would trigger network I/O or file I/O.
			// This test only verifies that the correct store type is created.
			store, err := s.initializeMetadataStore(refreshInterval, opts)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.expectStore && store == nil {
				t.Error("expected metadata store but got nil")
			}

			if !tt.expectStore && store != nil {
				t.Error("expected no metadata store but got one")
			}

			// Verify the correct store type was created based on configuration
			if tt.expectStore {
				switch tt.expectType {
				case "file":
					if _, ok := store.(*metadata.FileMetadataStore); !ok {
						t.Errorf("expected FileMetadataStore, got %T", store)
					}
				case "url", "url_refresh":
					if _, ok := store.(*metadata.URLMetadataStore); !ok {
						t.Errorf("expected URLMetadataStore, got %T", store)
					}
				}
			}
		})
	}
}

// TestInitializeSessionAndSAML tests the extraction of session store and SAML service initialization logic.
func TestInitializeSessionAndSAML(t *testing.T) {
	tests := []struct {
		name               string
		keyFile            string
		certFile           string
		signMetadata       bool
		sessionDuration    string
		expectError        bool
		expectSessionStore bool
		expectSAMLService  bool
	}{
		{
			name:               "full SAML setup with key and cert",
			keyFile:            "../../../../testdata/sp-key.pem",
			certFile:           "../../../../testdata/sp-cert.pem",
			sessionDuration:    "24h",
			expectSessionStore: true,
			expectSAMLService:  true,
		},
		{
			name:               "session store only (no cert)",
			keyFile:            "../../../../testdata/sp-key.pem",
			sessionDuration:    "12h",
			expectSessionStore: true,
			expectSAMLService:  false,
		},
		{
			name:               "metadata signing enabled",
			keyFile:            "../../../../testdata/sp-key.pem",
			certFile:           "../../../../testdata/sp-cert.pem",
			signMetadata:       true,
			sessionDuration:    "24h",
			expectSessionStore: true,
			expectSAMLService:  true,
		},
		{
			name:            "missing key file",
			keyFile:         "../../../../testdata/nonexistent_key.pem",
			sessionDuration: "24h",
			expectError:     true,
		},
		{
			name:            "invalid session duration",
			keyFile:         "../../../../testdata/sp-key.pem",
			sessionDuration: "invalid",
			expectError:     true,
		},
		{
			name:               "no key file configured",
			sessionDuration:    "24h",
			expectSessionStore: false,
			expectSAMLService:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SAMLDisco{
				Config: Config{
					EntityID:        "https://sp.example.com",
					KeyFile:         tt.keyFile,
					CertFile:        tt.certFile,
					SignMetadata:    tt.signMetadata,
					SessionDuration: tt.sessionDuration,
				},
				logger: zap.NewNop(),
			}

			sessionStore, samlService, sessionDur, err := s.initializeSessionAndSAML()

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.expectSessionStore && sessionStore == nil {
				t.Error("expected session store but got nil")
			}

			if !tt.expectSessionStore && sessionStore != nil {
				t.Error("expected no session store but got one")
			}

			if tt.expectSAMLService && samlService == nil {
				t.Error("expected SAML service but got nil")
			}

			if !tt.expectSAMLService && samlService != nil {
				t.Error("expected no SAML service but got one")
			}

			if tt.expectSessionStore && sessionDur == 0 {
				t.Error("expected session duration to be set")
			}
		})
	}
}
