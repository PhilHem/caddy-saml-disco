// Package worker provides a supervised background goroutine with panic recovery
// and automatic restart after transient failures.
package worker

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// consecutivePanicLimit is the number of consecutive panics after which the
// worker marks itself unhealthy. Successful ticks reset the counter.
const consecutivePanicLimit = 5

// Option is a functional option for configuring a SupervisedWorker.
type Option func(*SupervisedWorker)

// WithOnTick sets a callback invoked after each tick completes.
// The callback receives the error returned by the work function, or nil on
// success. Panics recovered by the worker are reported as errors. Used for
// test synchronization hooks.
func WithOnTick(fn func(error)) Option {
	return func(w *SupervisedWorker) {
		w.onTick = fn
	}
}

// SupervisedWorker runs a function on a fixed interval in a background
// goroutine. Each invocation is wrapped in a deferred recover; panics are
// logged with a stack trace and counted toward a circuit-breaker threshold.
// After consecutivePanicLimit consecutive panics, Healthy() returns false.
// A successful tick resets the count.
type SupervisedWorker struct {
	name     string
	work     func(ctx context.Context) error
	interval time.Duration
	logger   *zap.Logger
	onTick   func(error) // optional test hook

	// health is false when consecutive panics exceed the threshold.
	health atomic.Bool

	// closed is true once Close() has been called.
	closed atomic.Bool

	// stopCh is closed by Close() to signal the loop goroutine to exit.
	stopCh chan struct{}

	// ctx / cancel are created in Start() and cancelled by Close().
	ctx    context.Context
	cancel context.CancelFunc

	// done is closed when the loop goroutine exits, so Close() can wait.
	done chan struct{}

	// startOnce ensures Start() only launches one goroutine regardless of
	// how many times it is called.
	startOnce sync.Once
}

// NewSupervisedWorker constructs a SupervisedWorker. Call Start() to begin
// execution and Close() to stop it.
func NewSupervisedWorker(
	name string,
	interval time.Duration,
	work func(ctx context.Context) error,
	logger *zap.Logger,
	opts ...Option,
) *SupervisedWorker {
	w := &SupervisedWorker{
		name:     name,
		work:     work,
		interval: interval,
		logger:   logger,
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}
	w.health.Store(true)
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Start launches the background goroutine. It is safe to call multiple times;
// only the first call has any effect.
func (w *SupervisedWorker) Start() {
	w.startOnce.Do(func() {
		w.ctx, w.cancel = context.WithCancel(context.Background())
		go w.loop()
	})
}

// Close signals the worker to stop and waits for the in-flight tick (if any)
// to complete. Idempotent — safe to call multiple times or without a prior
// Start().
func (w *SupervisedWorker) Close() {
	if !w.closed.CompareAndSwap(false, true) {
		// Already closed.
		return
	}

	// Signal the loop goroutine and cancel any in-flight context.
	close(w.stopCh)
	if w.cancel != nil {
		w.cancel()
	}

	// Wait for the goroutine to exit. If Start() was never called, done is
	// never closed, but neither is there a goroutine to wait for — so we
	// only wait if Start() ran at least once.
	select {
	case <-w.done:
	default:
		// done is only closed when the goroutine exits. If the goroutine was
		// never started, we don't block. We detect this by checking whether
		// ctx was set (Start() sets it inside startOnce).
		if w.ctx != nil {
			<-w.done
		}
	}
}

// Healthy returns true while the worker has not exceeded the consecutive-panic
// threshold. It returns false once the threshold is reached and resets to true
// only after a subsequent successful tick.
func (w *SupervisedWorker) Healthy() bool {
	return w.health.Load()
}

// loop is the background goroutine body.
func (w *SupervisedWorker) loop() {
	defer close(w.done)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	var consecutivePanics int

	for {
		select {
		case <-ticker.C:
			err := w.runOnce(w.ctx)
			if err != nil {
				consecutivePanics++
			} else {
				consecutivePanics = 0
				w.health.Store(true)
			}
			if consecutivePanics >= consecutivePanicLimit {
				w.health.Store(false)
			}
			if w.onTick != nil {
				w.onTick(err)
			}
		case <-w.stopCh:
			return
		case <-w.ctx.Done():
			return
		}
	}
}

// runOnce calls the work function, recovering any panic into an error.
func (w *SupervisedWorker) runOnce(ctx context.Context) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			retErr = fmt.Errorf("panic: %v", r)
			if w.logger != nil {
				w.logger.Error("supervised worker recovered from panic",
					zap.String("worker", w.name),
					zap.Any("panic", r),
					zap.ByteString("stack", stack),
				)
			}
		}
	}()

	err := w.work(ctx)
	if err != nil && w.logger != nil {
		w.logger.Warn("supervised worker tick error",
			zap.String("worker", w.name),
			zap.Error(err),
		)
	}
	return err
}
