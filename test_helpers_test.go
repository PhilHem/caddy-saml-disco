//go:build unit

package caddysamldisco

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// Type alias for MetricsRecorder port.
type MetricsRecorder = ports.MetricsRecorder

// MockMetricsRecorder is a thread-safe test double for MetricsRecorder.
// Use in any test file that needs to verify metrics recording behavior.
type MockMetricsRecorder struct {
	mu                 sync.Mutex
	authAttempts       []AuthAttemptCall
	sessionsCreated    int
	sessionValidations []bool
	metadataRefreshes  []MetadataRefreshCall
}

// AuthAttemptCall records a call to RecordAuthAttempt.
type AuthAttemptCall struct {
	IdpEntityID string
	Success     bool
}

// MetadataRefreshCall records a call to RecordMetadataRefresh.
type MetadataRefreshCall struct {
	Source   string
	Success  bool
	IdpCount int
}

// RecordAuthAttempt implements MetricsRecorder.
func (m *MockMetricsRecorder) RecordAuthAttempt(idpEntityID string, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authAttempts = append(m.authAttempts, AuthAttemptCall{idpEntityID, success})
}

// RecordSessionCreated implements MetricsRecorder.
func (m *MockMetricsRecorder) RecordSessionCreated() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessionsCreated++
}

// RecordSessionValidation implements MetricsRecorder.
func (m *MockMetricsRecorder) RecordSessionValidation(valid bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessionValidations = append(m.sessionValidations, valid)
}

// RecordMetadataRefresh implements MetricsRecorder.
func (m *MockMetricsRecorder) RecordMetadataRefresh(source string, success bool, idpCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metadataRefreshes = append(m.metadataRefreshes, MetadataRefreshCall{source, success, idpCount})
}

// RecordAuthFailure implements MetricsRecorder (no-op for mock).
func (m *MockMetricsRecorder) RecordAuthFailure(category string, idpEntityID string) {
	// No-op - not tracked in mock
}

// RecordAuthSuccess implements MetricsRecorder (no-op for mock).
func (m *MockMetricsRecorder) RecordAuthSuccess(idpEntityID string) {
	// No-op - not tracked in mock
}

// RecordAuthDuration implements MetricsRecorder (no-op for mock).
func (m *MockMetricsRecorder) RecordAuthDuration(idpEntityID string, outcome string, duration time.Duration) {
	// No-op - not tracked in mock
}

// GetAuthAttempts returns a copy of recorded auth attempts (thread-safe).
func (m *MockMetricsRecorder) GetAuthAttempts() []AuthAttemptCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]AuthAttemptCall, len(m.authAttempts))
	copy(result, m.authAttempts)
	return result
}

// GetSessionsCreated returns the number of sessions created (thread-safe).
func (m *MockMetricsRecorder) GetSessionsCreated() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessionsCreated
}

// GetSessionValidations returns a copy of recorded session validations (thread-safe).
func (m *MockMetricsRecorder) GetSessionValidations() []bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]bool, len(m.sessionValidations))
	copy(result, m.sessionValidations)
	return result
}

// GetMetadataRefreshes returns a copy of recorded metadata refreshes (thread-safe).
func (m *MockMetricsRecorder) GetMetadataRefreshes() []MetadataRefreshCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]MetadataRefreshCall, len(m.metadataRefreshes))
	copy(result, m.metadataRefreshes)
	return result
}

// TestMockMetricsRecorder_ImplementsInterface verifies MockMetricsRecorder implements MetricsRecorder.
func TestMockMetricsRecorder_ImplementsInterface(t *testing.T) {
	var _ MetricsRecorder = (*MockMetricsRecorder)(nil)
}

// TestMockMetricsRecorder_ThreadSafety verifies MockMetricsRecorder is safe for concurrent use.
func TestMockMetricsRecorder_ThreadSafety(t *testing.T) {
	mock := &MockMetricsRecorder{}
	var wg sync.WaitGroup

	// Spawn goroutines that concurrently call all methods
	for i := 0; i < 100; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			mock.RecordAuthAttempt("https://idp.example.com", true)
		}()
		go func() {
			defer wg.Done()
			mock.RecordSessionCreated()
		}()
		go func() {
			defer wg.Done()
			mock.RecordSessionValidation(true)
		}()
		go func() {
			defer wg.Done()
			mock.RecordMetadataRefresh("file", true, 5)
		}()
	}
	wg.Wait()

	// Verify all calls were recorded
	if len(mock.GetAuthAttempts()) != 100 {
		t.Errorf("expected 100 auth attempts, got %d", len(mock.GetAuthAttempts()))
	}
	if mock.GetSessionsCreated() != 100 {
		t.Errorf("expected 100 sessions created, got %d", mock.GetSessionsCreated())
	}
	if len(mock.GetSessionValidations()) != 100 {
		t.Errorf("expected 100 session validations, got %d", len(mock.GetSessionValidations()))
	}
	if len(mock.GetMetadataRefreshes()) != 100 {
		t.Errorf("expected 100 metadata refreshes, got %d", len(mock.GetMetadataRefreshes()))
	}
}

// TestMockMetricsRecorder_RecordsAllCalls verifies MockMetricsRecorder records call details.
func TestMockMetricsRecorder_RecordsAllCalls(t *testing.T) {
	mock := &MockMetricsRecorder{}

	mock.RecordAuthAttempt("https://idp1.example.com", true)
	mock.RecordAuthAttempt("https://idp2.example.com", false)
	mock.RecordSessionCreated()
	mock.RecordSessionCreated()
	mock.RecordSessionValidation(true)
	mock.RecordSessionValidation(false)
	mock.RecordMetadataRefresh("file", true, 5)
	mock.RecordMetadataRefresh("url", false, 0)

	authAttempts := mock.GetAuthAttempts()
	if len(authAttempts) != 2 {
		t.Fatalf("expected 2 auth attempts, got %d", len(authAttempts))
	}
	if authAttempts[0].IdpEntityID != "https://idp1.example.com" || !authAttempts[0].Success {
		t.Errorf("unexpected first auth attempt: %+v", authAttempts[0])
	}
	if authAttempts[1].IdpEntityID != "https://idp2.example.com" || authAttempts[1].Success {
		t.Errorf("unexpected second auth attempt: %+v", authAttempts[1])
	}

	if mock.GetSessionsCreated() != 2 {
		t.Errorf("expected 2 sessions created, got %d", mock.GetSessionsCreated())
	}

	validations := mock.GetSessionValidations()
	if len(validations) != 2 || validations[0] != true || validations[1] != false {
		t.Errorf("unexpected session validations: %+v", validations)
	}

	refreshes := mock.GetMetadataRefreshes()
	if len(refreshes) != 2 {
		t.Fatalf("expected 2 metadata refreshes, got %d", len(refreshes))
	}
	if refreshes[0].Source != "file" || !refreshes[0].Success || refreshes[0].IdpCount != 5 {
		t.Errorf("unexpected first refresh: %+v", refreshes[0])
	}
	if refreshes[1].Source != "url" || refreshes[1].Success || refreshes[1].IdpCount != 0 {
		t.Errorf("unexpected second refresh: %+v", refreshes[1])
	}
}

// loadTestKey loads the test private key from testdata.
func loadTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	keyPEM, err := os.ReadFile("testdata/sp-key.pem")
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
		t.Fatalf("expected RSA key, got %T", key)
	}

	return rsaKey
}
