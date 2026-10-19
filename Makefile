# DNS over SMTP Makefile

.PHONY: build test clean run-client run-server install deps

# Binary name
BINARY_NAME=dns-over-smtp

# Build without cgo so Linux binaries do not depend on the builder's glibc.
build:
	CGO_ENABLED=0 go build -o $(BINARY_NAME) ./main.go

# Install dependencies
deps:
	go mod tidy
	go mod download

# Run tests
test:
	go test ./...

# Run tests with coverage
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

# Clean build artifacts
clean:
	go clean
	rm -f $(BINARY_NAME)
	rm -f coverage.out

# Install the binary
install: build
	CGO_ENABLED=0 go install

# Run client example (requires configuration)
run-client:
	./$(BINARY_NAME) \
		-mode=client \
		-smtp-host=localhost \
		-smtp-port=2525 \
		-email-from=client@local.test \
		-email-to=dns@localhost \
		-listen=:5353

# Run server example (requires configuration)
run-server:
	./$(BINARY_NAME) \
		-mode=server \
		-smtp-listen=127.0.0.1:2525 \
		-email-to=dns@localhost \
		-dns-server=8.8.8.8:53

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	golangci-lint run

# Check for security issues
sec:
	gosec ./...

# Run all checks
check: fmt test lint sec

# Build for multiple platforms
build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)-linux-amd64 ./main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME)-darwin-amd64 ./main.go
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME)-windows-amd64.exe ./main.go

# Development server with auto-reload (requires air)
dev:
	air

# Help
help:
	@echo "Available targets:"
	@echo "  build       - Build the application"
	@echo "  deps        - Install dependencies"
	@echo "  test        - Run tests"
	@echo "  clean       - Clean build artifacts"
	@echo "  install     - Install the binary"
	@echo "  run-client  - Run client example"
	@echo "  run-server  - Run server example"
	@echo "  fmt         - Format code"
	@echo "  lint        - Lint code"
	@echo "  sec         - Security check"
	@echo "  check       - Run all checks"
	@echo "  build-all   - Build for multiple platforms"
	@echo "  help        - Show this help"
