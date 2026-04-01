package entitlements

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/ports"
	"github.com/philiph/caddy-saml-disco/internal/worker"
)

// StartRefresh starts a supervised background worker that periodically calls
// store.Refresh(). Returns the worker; call Close() on it to stop.
func StartRefresh(store ports.EntitlementStore, interval time.Duration, logger *zap.Logger) *worker.SupervisedWorker {
	w := worker.NewSupervisedWorker(
		"entitlement-refresh",
		interval,
		func(ctx context.Context) error {
			return store.Refresh(ctx)
		},
		logger,
	)
	w.Start()
	return w
}
