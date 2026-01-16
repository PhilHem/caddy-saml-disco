//go:build unit

package metadata

import (
	"sync"
	"time"
)

// FakeClock is a controllable clock for testing cache TTL expiration.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock creates a FakeClock initialized to the current time.
func NewFakeClock() *FakeClock {
	return &FakeClock{now: time.Now()}
}

// Now returns the fake clock's current time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by the specified duration.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// MockMetricsRecorder is a thread-safe test double for MetricsRecorder.
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
