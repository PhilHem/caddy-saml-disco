.PHONY: build test test-unit test-integration test-domain test-metrics lint fmt

# Build all packages
build:
	go build ./...

# Run all tests
test:
	go test ./...

# Run unit tests only
test-unit:
	go test -tags=unit ./...

# Run integration tests only
test-integration:
	go test -tags=integration ./...

# Run domain tests only
test-domain:
	go test -tags=unit -v ./internal/core/domain/...

# Run metrics tests only
test-metrics:
	go test -tags=unit -v ./internal/adapters/driven/metrics/...

# Run linter
lint:
	golangci-lint run

# Format code
fmt:
	gofmt -w .
