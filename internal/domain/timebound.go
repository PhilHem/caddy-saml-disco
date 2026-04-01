package domain

import "time"

// TimeBound wraps a value with a validUntil timestamp.
// A zero validUntil means the value never expires.
type TimeBound[T any] struct {
	value      T
	validUntil time.Time
}

// NewTimeBound creates a TimeBound wrapping value with the given expiry time.
// A zero validUntil means the value never expires.
func NewTimeBound[T any](value T, validUntil time.Time) TimeBound[T] {
	return TimeBound[T]{value: value, validUntil: validUntil}
}

// Value returns the inner value if still valid, or ErrMetadataExpired if validUntil has passed.
func (tb TimeBound[T]) Value(now time.Time) (T, error) {
	if !tb.validUntil.IsZero() && now.After(tb.validUntil) {
		var zero T
		return zero, ErrMetadataExpired
	}
	return tb.value, nil
}

// ValueWithGrace returns the value even if expired, plus a boolean indicating freshness.
// fresh is true when the value has not yet expired (or has no expiry set).
// This supports stale-serve with logging: callers can serve the value while recording
// that it is no longer fresh.
func (tb TimeBound[T]) ValueWithGrace(now time.Time) (T, bool) {
	fresh := tb.validUntil.IsZero() || !now.After(tb.validUntil)
	return tb.value, fresh
}

// ValidUntil returns the expiry time. A zero value means no expiry.
func (tb TimeBound[T]) ValidUntil() time.Time {
	return tb.validUntil
}
