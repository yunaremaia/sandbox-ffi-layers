# sandbox-ffi-layers

![ci](https://github.com/yunaremaia/sandbox-ffi-layers/actions/workflows/ci.yml/badge.svg) ![license](https://img.shields.io/github/license/yunaremaia/sandbox-ffi-layers) ![stars](https://img.shields.io/github/stars/yunaremaia/sandbox-ffi-layers)

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

Not published to crates.io. Build from source:

```bash
cargo install --locked --git https://github.com/yunaremaia/sandbox-ffi-layers.git
```

## Usage

```bash
# One-shot check of Cargo.lock
sandbox-ffi --check --lockfile ./Cargo.lock

# Machine-readable output for CI
sandbox-ffi --check --format json

# Fail on critical findings (CI/CD gate)
sandbox-ffi --check --fail-critical

# Watch mode (requires root, eBPF) — not implemented yet, exits 2
sandbox-ffi --watch
```

Output formats: `text` (default) and `json`. SARIF is not implemented.

## Status

**v0.1.0-alpha** — Cargo.lock parser + proc-macro detection + known-malicious blocklist.

Parses `Cargo.lock` as TOML, so non-`[[package]]` sections (`[[patch.unused]]`,
`[[metadata]]`) are not mistaken for packages. A lockfile that cannot be parsed
is reported as an error rather than as "no findings" — for a scanner, an empty
result reads as an all-clear.

Advisory-database lookups (OSV, RustSec) and runtime interception are not
implemented. `--watch` is a stub and `--format sarif` does not exist.

If this tool is useful to you, a star helps other people find it.

## Related tools

- **[vibeguard](https://github.com/yunaremaia/vibeguard)** — guardrails for AI-generated code changes
- **[ci-sandbox](https://github.com/yunaremaia/ci-sandbox)** — sandbox untrusted CI steps
- **[agent-workspace](https://github.com/yunaremaia/agent-workspace)** — isolated workspaces per AI agent session
- **[agent-guard](https://github.com/yunaremaia/agent-guard)** — enforce guardrails on AI agent tool calls

Part of a family of focused, single-purpose developer tools — each one does one thing
and does it well.

## License

AGPL-3.0 — see [LICENSE](LICENSE).
