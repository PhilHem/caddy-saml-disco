.PHONY: build test test-unit test-unit-timeout test-pattern test-integration test-bdd test-domain test-metrics lint fmt pre-commit

# Build all packages
build:
	go build ./...

# Run all tests
test:
	go test -timeout 30s -failfast ./...

# Run unit tests only
test-unit:
	go test -tags=unit -timeout 30s -failfast ./...

# Run unit tests with 5s timeout per test (identifies slow/deadlocking tests)
test-unit-timeout:
	go test -tags=unit -timeout 5s ./...

# Run specific test pattern with timeout
test-pattern:
	go test -tags=unit -timeout 5s -failfast -run "$(PATTERN)" -v ./...

# Run integration tests only
test-integration:
	go test -tags=integration ./...

# Run BDD tests only
test-bdd:
	go test -tags=bdd -v ./tests/features/...

# Run domain tests only
test-domain:
	go test -tags=unit -timeout 30s -failfast -v ./internal/core/domain/...

# Run metrics tests only
test-metrics:
	go test -tags=unit -v ./internal/adapters/driven/metrics/...

# Run linter
lint:
	golangci-lint run

# Format code
fmt:
	gofmt -w .

# Run pre-commit checks
pre-commit:
	pre-commit run --all-files

# Run metadata tests with verbose output
test-metadata-verbose:
	go test -v ./internal/adapters/driven/metadata

# Run caddy adapter tests only
test-caddy:
	go test -tags=unit -timeout 30s -v ./internal/adapters/driving/caddy/...
