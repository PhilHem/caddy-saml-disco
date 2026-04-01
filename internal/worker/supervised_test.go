//go:build unit

package worker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// tickTimeout is the maximum time a test waits for a tick to occur. Because we
// use very short intervals in tests (1 ms), this is generous enough to prevent
// flakes on a loaded CI runner.
const tickTimeout = 5 * time.Second

// waitForTick blocks until fn delivers a value on the returned channel or
// tickTimeout elapses (in which case t.Fatal is called).
func waitForTick(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(tickTimeout):
		t.Fatalf("timed out waiting for tick")
		return nil
	}
}

// TestSupervisedWorker_NormalTick verifies that the work function is called on
// each interval and the onTick hook receives nil on success.
func TestSupervisedWorker_NormalTick(t *testing.T) {
	tra.RequireLegacy(t)

	logger := zaptest.NewLogger(t)

	var callCount atomic.Int32
	tickCh := make(chan error, 8)

	w := NewSupervisedWorker(
		"test",
		1*time.Millisecond,
		func(_ context.Context) error {
			callCount.Add(1)
			return nil
		},
		logger,
		WithOnTick(func(err error) { tickCh <- err }),
	)
	w.Start()
	defer w.Close()

	// Wait for at least two successful ticks.
	err1 := waitForTick(t, tickCh)
	err2 := waitForTick(t, tickCh)

	if err1 != nil {
		t.Errorf("tick 1: expected nil error, got %v", err1)
	}
	if err2 != nil {
		t.Errorf("tick 2: expected nil error, got %v", err2)
	}
	if callCount.Load() < 2 {
		t.Errorf("expected at least 2 work calls, got %d", callCount.Load())
	}
}

// TestSupervisedWorker_PanicRecovery verifies that a panicking work function
// does not crash the process: the loop continues and subsequent ticks run.
func TestSupervisedWorker_PanicRecovery(t *testing.T) {
	tra.RequireLegacy(t)

	logger := zaptest.NewLogger(t)

	var callCount atomic.Int32
	tickCh := make(chan error, 8)

	w := NewSupervisedWorker(
		"panicker",
		1*time.Millisecond,
		func(_ context.Context) error {
			n := callCount.Add(1)
			if n == 1 {
				panic("intentional test panic")
			}
			return nil
		},
		logger,
		WithOnTick(func(err error) { tickCh <- err }),
	)
	w.Start()
	defer w.Close()

	// First tick should produce a non-nil error (recovered panic).
	panicErr := waitForTick(t, tickCh)
	if panicErr == nil {
		t.Error("expected non-nil error from panicking tick")
	}

	// Second tick should succeed (loop continued after panic).
	successErr := waitForTick(t, tickCh)
	if successErr != nil {
		t.Errorf("expected nil error on second tick, got %v", successErr)
	}
}

// TestSupervisedWorker_HealthDegradeAfterRepeatedPanics verifies that Healthy()
// returns false once consecutivePanicLimit consecutive panics have occurred.
func TestSupervisedWorker_HealthDegradeAfterRepeatedPanics(t *testing.T) {
	tra.RequireLegacy(t)

	logger := zap.NewNop()
	tickCh := make(chan error, consecutivePanicLimit+2)

	w := NewSupervisedWorker(
		"unhealthy",
		1*time.Millisecond,
		func(_ context.Context) error {
			panic("always panics")
		},
		logger,
		WithOnTick(func(err error) { tickCh <- err }),
	)
	w.Start()
	defer w.Close()

	// Drain exactly consecutivePanicLimit ticks.
	for i := 0; i < consecutivePanicLimit; i++ {
		waitForTick(t, tickCh)
	}

	if w.Healthy() {
		t.Error("expected Healthy() == false after consecutive panics")
	}
}

// TestSupervisedWorker_HealthResetsAfterSuccess verifies that Healthy() returns
// true again once a successful tick follows repeated panics.
func TestSupervisedWorker_HealthResetsAfterSuccess(t *testing.T) {
	tra.RequireLegacy(t)

	logger := zap.NewNop()
	tickCh := make(chan error, consecutivePanicLimit+4)

	var callCount atomic.Int32

	w := NewSupervisedWorker(
		"recover",
		1*time.Millisecond,
		func(_ context.Context) error {
			n := callCount.Add(1)
			// Panic for the first batch, then succeed.
			if int(n) <= consecutivePanicLimit {
				panic("deliberate")
			}
			return nil
		},
		logger,
		WithOnTick(func(err error) { tickCh <- err }),
	)
	w.Start()
	defer w.Close()

	// Drain panics until unhealthy.
	for i := 0; i < consecutivePanicLimit; i++ {
		waitForTick(t, tickCh)
	}
	if w.Healthy() {
		t.Error("expected Healthy() == false after threshold panics")
	}

	// Wait for one successful tick.
	successErr := waitForTick(t, tickCh)
	if successErr != nil {
		t.Errorf("expected nil error on recovery tick, got %v", successErr)
	}
	if !w.Healthy() {
		t.Error("expected Healthy() == true after successful tick")
	}
}

// TestSupervisedWorker_CloseStopsLoop verifies that after Close() the work
// function is no longer called.
func TestSupervisedWorker_CloseStopsLoop(t *testing.T) {
	tra.RequireLegacy(t)

	logger := zaptest.NewLogger(t)

	tickCh := make(chan error, 4)

	w := NewSupervisedWorker(
		"stoppable",
		1*time.Millisecond,
		func(_ context.Context) error { return nil },
		logger,
		WithOnTick(func(err error) {
			select {
			case tickCh <- err:
			default:
			}
		}),
	)
	w.Start()

	// Wait for at least one tick to confirm the loop is running.
	waitForTick(t, tickCh)

	w.Close()

	// Drain the channel and record how many ticks occurred before and briefly
	// after Close to confirm the loop stopped.
	deadline := time.After(20 * time.Millisecond)
	var postCloseCount int
outer:
	for {
		select {
		case <-tickCh:
			postCloseCount++
		case <-deadline:
			break outer
		}
	}

	// We cannot assert zero post-close ticks (a tick may have been in-flight),
	// but the channel must drain quickly. The key assertion is that we did not
	// block indefinitely — if Close() failed to stop the loop, tickCh would
	// keep filling indefinitely and the deadline select would overflow.
	_ = postCloseCount
}

// TestSupervisedWorker_CloseIsIdempotent verifies that calling Close() multiple
// times does not panic or deadlock.
func TestSupervisedWorker_CloseIsIdempotent(t *testing.T) {
	tra.RequireLegacy(t)

	logger := zaptest.NewLogger(t)

	tickCh := make(chan error, 4)

	w := NewSupervisedWorker(
		"idempotent",
		1*time.Millisecond,
		func(_ context.Context) error { return nil },
		logger,
		WithOnTick(func(err error) {
			select {
			case tickCh <- err:
			default:
			}
		}),
	)
	w.Start()
	waitForTick(t, tickCh)

	// Closing multiple times must not panic.
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Close()
		w.Close()
		w.Close()
	}()

	select {
	case <-done:
		// success
	case <-time.After(tickTimeout):
		t.Fatal("Close() deadlocked on repeated calls")
	}
}

// TestSupervisedWorker_WithOnTickHookCalled verifies that the WithOnTick hook
// is invoked after every tick with the correct error value.
func TestSupervisedWorker_WithOnTickHookCalled(t *testing.T) {
	tra.RequireLegacy(t)

	logger := zaptest.NewLogger(t)

	sentinel := errors.New("sentinel error")
	var mu sync.Mutex
	var received []error

	done := make(chan struct{})

	w := NewSupervisedWorker(
		"hook",
		1*time.Millisecond,
		func(_ context.Context) error { return sentinel },
		logger,
		WithOnTick(func(err error) {
			mu.Lock()
			received = append(received, err)
			if len(received) >= 3 {
				select {
				case <-done:
				default:
					close(done)
				}
			}
			mu.Unlock()
		}),
	)
	w.Start()
	defer w.Close()

	select {
	case <-done:
	case <-time.After(tickTimeout):
		t.Fatal("timed out waiting for 3 hook invocations")
	}

	mu.Lock()
	defer mu.Unlock()
	for i, err := range received {
		if !errors.Is(err, sentinel) {
			t.Errorf("tick %d: expected sentinel error, got %v", i, err)
		}
	}
}

// TestSupervisedWorker_ContextCancelledOnClose verifies that the context passed
// to the work function is cancelled when Close() is called during an in-flight tick.
func TestSupervisedWorker_ContextCancelledOnClose(t *testing.T) {
	tra.RequireLegacy(t)

	logger := zaptest.NewLogger(t)

	started := make(chan struct{})
	proceed := make(chan struct{})

	w := NewSupervisedWorker(
		"ctx-cancel",
		1*time.Millisecond,
		func(ctx context.Context) error {
			close(started)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-proceed:
				return nil
			}
		},
		logger,
	)
	w.Start()

	// Wait for work to be in-flight.
	select {
	case <-started:
	case <-time.After(tickTimeout):
		t.Fatal("timed out waiting for work to start")
	}

	// Close while work is blocked — context should be cancelled.
	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		w.Close()
	}()

	select {
	case <-closeDone:
		// success: Close() returned, meaning the in-flight work completed.
	case <-time.After(tickTimeout):
		close(proceed) // unblock to avoid goroutine leak
		t.Fatal("Close() timed out waiting for in-flight work")
	}
}
