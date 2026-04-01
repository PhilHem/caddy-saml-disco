//go:build unit

package domain

import (
	"errors"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

func TestTimeBound_Value_ReturnsDataWhenValid(t *testing.T) {
	tra.RequireLegacy(t)

	tb := NewTimeBound("hello", time.Now().Add(1*time.Hour))
	v, err := tb.Value(time.Now())
	if err != nil {
		t.Fatalf("Value() returned unexpected error: %v", err)
	}
	if v != "hello" {
		t.Errorf("Value() = %q, want %q", v, "hello")
	}
}

func TestTimeBound_Value_ReturnsErrMetadataExpiredWhenExpired(t *testing.T) {
	tra.RequireLegacy(t)

	past := time.Now().Add(-1 * time.Hour)
	tb := NewTimeBound("stale", past)
	_, err := tb.Value(time.Now())
	if !errors.Is(err, ErrMetadataExpired) {
		t.Errorf("Value() error = %v, want ErrMetadataExpired", err)
	}
}

func TestTimeBound_Value_ZeroValidUntilNeverExpires(t *testing.T) {
	tra.RequireLegacy(t)

	tb := NewTimeBound([]string{"a", "b"}, time.Time{})
	// Far future "now" — should still succeed
	farFuture := time.Now().Add(100 * 365 * 24 * time.Hour)
	v, err := tb.Value(farFuture)
	if err != nil {
		t.Fatalf("Value() with zero validUntil returned unexpected error: %v", err)
	}
	if len(v) != 2 {
		t.Errorf("Value() len = %d, want 2", len(v))
	}
}

func TestTimeBound_ValueWithGrace_ReturnsFalseWhenExpired(t *testing.T) {
	tra.RequireLegacy(t)

	past := time.Now().Add(-1 * time.Hour)
	tb := NewTimeBound("old", past)
	v, fresh := tb.ValueWithGrace(time.Now())
	if v != "old" {
		t.Errorf("ValueWithGrace() value = %q, want %q", v, "old")
	}
	if fresh {
		t.Error("ValueWithGrace() fresh = true, want false for expired value")
	}
}

func TestTimeBound_ValueWithGrace_ReturnsTrueWhenValid(t *testing.T) {
	tra.RequireLegacy(t)

	future := time.Now().Add(1 * time.Hour)
	tb := NewTimeBound(42, future)
	v, fresh := tb.ValueWithGrace(time.Now())
	if v != 42 {
		t.Errorf("ValueWithGrace() value = %d, want 42", v)
	}
	if !fresh {
		t.Error("ValueWithGrace() fresh = false, want true for valid value")
	}
}
