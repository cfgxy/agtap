.PHONY: build test test-integration test-live test-all coverage clean setup-hooks

# Build agtap release binary
build:
	cargo build -p agtap --release

# Unit + scenario pipeline tests (no sudo, no API key)
test:
	cargo test -p agtap -p agtap-common

# Full eBPF integration via mock server (needs sudo, no API key)
test-integration: build
	cargo run -p agtap-test

# Real API smoke test (needs sudo + API keys)
test-live: build
	cargo run -p agtap-test -- --live

# All non-live tests
test-all: test test-integration

# Code coverage (unit + scenario pipeline tests)
coverage:
	cargo llvm-cov --package agtap --package agtap-common

# Remove build artifacts
clean:
	cargo clean

# Install pre-commit hook for format checking
setup-hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks path set to .githooks/"
