# Contributing to agtap

## Building from source

Prerequisites:

- **Rust nightly** — `rust-toolchain.toml` handles the channel and components automatically via rustup (`rust-src` for eBPF cross-compilation, `rustfmt` and `clippy` for code style)
- **bpf-linker** — `cargo install bpf-linker` (required for eBPF compilation)

```
cargo build -p agtap --release
```

The binary is at `./target/release/agtap`.

## Code style

Format and lint before committing:

```
cargo fmt --all            # auto-format
cargo clippy -p agtap -- -D warnings   # lint (must pass cleanly)
```

CI enforces both — PRs will fail if either check doesn't pass.

Run `make setup-hooks` to install a pre-commit hook that enforces formatting automatically.

## How it works

eBPF probes attached at three levels:

| Layer | Probes | Captures |
|-------|--------|----------|
| **TLS** | `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex`, `SSL_set_fd` (uprobes) | HTTPS API calls (OpenSSL/LibreSSL) |
| **Plain HTTP** | `send`, `recv` via glibc (uprobes) | Unencrypted HTTP (Python, curl, Ruby, Java) |
| **Stdio MCP** | `vfs_write`, `vfs_read`, `vfs_writev`, `vfs_readv` (kprobes) | Pipe-based MCP (stdio pipes) |

## Project structure

| Crate | Purpose |
|-------|---------|
| `agtap` | Main binary — daemon, TUI, providers, HTTP reassembly, telemetry |
| `agtap-ebpf` | eBPF kernel probes (SSL, TCP, pipes) |
| `agtap-common` | Shared types between userspace and eBPF |
| `agtap-mock` | Mock HTTPS server for testing |
| `agtap-test` | Integration test runner |

## Testing

| Target | Packages | Requirements |
|--------|----------|--------------|
| `make test` | `agtap` + `agtap-common` | none |
| `make test-integration` | `agtap-test` (eBPF integration via mock server) | sudo |
| `make test-live` | `agtap-test --live` (real API smoke) | sudo + API keys |
| `make test-all` | `agtap` + `agtap-common` + `agtap-test` | sudo |
| `make coverage` | `agtap` + `agtap-common` (llvm-cov) | none |

> **Note:** CI additionally runs `cargo test -p agtap-mock`, which `make test` does not cover. To run it locally: `cargo test -p agtap-mock`.

Scenario-driven tests live in `scenarios/` — each TOML file defines an HTTP exchange that gets fed through the reassembler, parser, and output pipeline.

### Testing with real runtimes

To verify agtap captures traffic from each supported runtime, run `sudo ./target/release/agtap` in one terminal and exercise the runtime in another. Use `--verbose` to confirm probe attachment.

**Python** — `pip install anthropic openai`. One-liner SDK calls test OpenSSL capture via Python's `ssl` module. Works with `requests`, `httpx`, `aiohttp`.

**Node.js** — `npm install @anthropic-ai/sdk openai`. Use `--verbose` to confirm agtap finds SSL symbols in the Node binary. Test across nvm versions for per-version OpenSSL detection.

**curl** — direct API calls to Anthropic/OpenAI. This is what `agtap-test` uses internally.

**Ruby** — `ruby -e` with `net/http` (uses OpenSSL via C extension).

**MCP (stdio)** — `npx @modelcontextprotocol/inspector` or any stdio MCP server. Captured via pipe kprobes (`vfs_write`/`vfs_read`).

**Frameworks** — LangChain (`pip install langchain-anthropic`), CrewAI, AutoGen use the same Python SSL path. If basic Python capture works, frameworks work too.

**musl/Alpine** — `docker run alpine` with curl. agtap runs on the host and captures via musl uprobes + vfs kprobes.

**Observability** — OTel: run Jaeger (`docker run -p 4318:4318 -p 16686:16686 jaegertracing/all-in-one`) and start agtap with `--otel http://localhost:4318`. Prometheus: start with `--metrics-addr 127.0.0.1:9464` and scrape `curl localhost:9464/metrics`.

**Offline (no API keys)** — `cargo run -p agtap-mock` starts a mock HTTPS server. Point curl at it for full eBPF testing without real API calls.

## Releasing

1. Update `version` in all 5 `Cargo.toml` files (`agtap`, `agtap-common`, `agtap-ebpf`, `agtap-mock`, `agtap-test`)
2. `cargo check` to update `Cargo.lock`
3. Commit, tag `vX.Y.Z`, push

CI takes it from there: the release workflow builds linux/x86_64 and linux/aarch64 binaries, validates the tag matches `Cargo.toml`, and creates a GitHub Release with the archives and checksums.
