package entitlements

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// StartRefresh starts a background goroutine that periodically calls
// store.Refresh(). Returns a cancel function that stops the goroutine.
func StartRefresh(store ports.EntitlementStore, interval time.Duration, logger *zap.Logger) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := store.Refresh(ctx); err != nil {
					logger.Warn("entitlement refresh failed", zap.Error(err))
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return cancel
}
