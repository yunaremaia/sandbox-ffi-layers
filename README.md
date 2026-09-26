# sandbox-ffi-layers

> Runtime security gateway for AI coding agents building with native dependencies.

`sandbox-ffi-layers` intercepts build commands executed by AI coding agents
(Claude Code, Codex, OpenCode) and verifies native dependency supply chain
before allowing `build.rs`, `proc-macro`, or CFFI execution.

## Problem

In August 2026, the Rust crate `arrayref@0.3.10` was compromised via a typosquat
of `proc-macro2` called `proc-macro1`. The malicious `build.rs` downloaded and
executed a remote payload during `cargo build`. Over 2,285 downloads before removal.

**Existing tools fail because:**
- `cargo audit` only checks known CVEs (new attacks have none)
- Supply-chain scanners (Socket, Phylum) run post-installation
- Agent sandboxes (Eclipse Enclave) don't inspect native build execution

## Solution

`sandbox-ffi-layers` is the first tool to unify:
1. **Agent sandboxing** — intercepts build commands from AI agents
2. **Supply-chain scanning** — checks deps against PhantomDB, OSV, RustSec
3. **Native build detection** — identifies proc-macros, build.rs, CFFI
4. **Runtime enforcement** — blocks BEFORE native code executes

## Installation

```bash
cargo install --locked sandbox-ffi-layers
```

## Usage

```bash
# One-shot check of Cargo.lock
sandbox-ffi --check --lockfile ./Cargo.lock

# With SARIF output for GitHub Code Scanning
sandbox-ffi --check --format sarif --output results.sarif

# Fail on critical findings (CI/CD gate)
sandbox-ffi --check --fail-critical

# Watch mode (requires root, eBPF)
sudo sandbox-ffi --watch
```

## Status

**v0.1.0-alpha** — Cargo.lock parser + proc-macro detection + known-malicious blocklist.

See [PROPOSAL.md](PROPOSAL.md) for full roadmap.

## License

AGPL-3.0 — see [LICENSE](LICENSE).

# sandbox-ffi-layers

![CI](https://github.com/yunaremaia/sandbox-ffi-layers/actions/workflows/ci.yml/badge.svg)
