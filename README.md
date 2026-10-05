# sandbox-ffi-layers

![ci](https://github.com/yunaremaia/sandbox-ffi-layers/actions/workflows/ci.yml/badge.svg) ![license](https://img.shields.io/github/license/yunaremaia/sandbox-ffi-layers) ![stars](https://img.shields.io/github/stars/yunaremaia/sandbox-ffi-layers)

> A `Cargo.lock` scanner that finds crates which execute code at build time, and blocks the known-malicious typosquat family from the August 2026 Rust supply-chain attack.

`sandbox-ffi-layers` analyzes a resolved Rust `Cargo.lock` and reports the
packages that can run code during `cargo build` — proc-macro crates and build
script dependencies — so a typosquatted dependency is caught before you build.

## Why

On 2026-08-20 three Rust crates — `arrayref 0.3.10`, `internment 0.8.7` and
`append-only-vec 0.1.9` — were published with a new build-time dependency,
`proc-macro1`, a typosquat of `proc-macro2`. Its `build.rs` runs automatically
when Cargo compiles it, so a plain `cargo build` was enough to fetch and run a
remote payload. The Rust Security Response Team pulled the versions and six
attacker-owned crates within 86–107 minutes; a deleted registry version produces
no `cargo audit` finding at all, so the lockfile is where you catch it.

**Existing tools miss this class of attack:**

- `cargo audit` matches known advisories — this attack had no CVE, only a
  compromised version
- SCA scanners (Socket, Phylum) generally run post-installation, after the
  build script has already executed
- agent sandboxes isolate the agent, but don't inspect what the build runs

## Install

Not published to crates.io. Build from source:

```bash
cargo install --locked --git https://github.com/yunaremaia/sandbox-ffi-layers.git
```

## Quickstart

The output below is real, from a directory containing this `Cargo.lock`:

```toml
version = 3

[[package]]
name = "arrayref"
version = "0.3.10"
dependencies = [
 "proc-macro1",
]

[[package]]
name = "proc-macro1"
version = "1.0.107"

[[package]]
name = "serde"
version = "1.0.229"
```

```console
$ sandbox-ffi --check
  [BUILD] arrayref@0.3.10 — build script dep
  [PROC-MACRO] proc-macro1@1.0.107 — proc-macro crate
⚠️  KNOWN-MALICIOUS PACKAGES DETECTED:
  BLOCKED: proc-macro1@1.0.107
$ echo $?
0
```

## Commands

`--help` is the source of truth. As of v0.1.0:

```console
$ sandbox-ffi --help
Runtime security gateway for AI coding agents building with native dependencies

Usage: sandbox-ffi [OPTIONS]

Options:
  -c, --check                Check Cargo.lock for supply-chain risks (one-shot mode)
  -w, --watch                Watch mode: intercept build commands via eBPF (requires root)
  -l, --lockfile <LOCKFILE>  Path to Cargo.lock (default: ./Cargo.lock) [default: ./Cargo.lock]
  -f, --format <FORMAT>      Output format: text, json [default: text] [possible values: text, json]
      --json                 Output JSON format (shorthand for --format json)
      --fail-critical        Exit with code 1 on critical findings
  -h, --help                 Print help
  -V, --version              Print version
```

### Exit codes

The two output formats do **not** agree on exit codes. This is a real
inconsistency, documented here so you can gate CI correctly:

| Mode | Findings | Exit |
|---|---|---|
| `--check` (text) | any | `0` |
| `--check` (text) `--fail-critical` | known-malicious package | `1` |
| `--check` (format json) | known-malicious package | `1` |
| `--check` (format json) `--fail-critical` | also any warning | `1` |
| `--watch` | always (stub) | `2` |
| any | lockfile missing / unreadable / unparsable | `1` |

To gate CI on malicious packages alone, `--format json` is the stricter and more
predictable choice. Text mode needs `--fail-critical` to fail at all.

### JSON output

```console
$ sandbox-ffi --check --format json
{
  "version": "1.0.0",
  "timestamp": "2026-10-05T07:13:41Z",
  "summary": {
    "total": 3,
    "errors": 1,
    "warnings": 1,
    "passed": 1
  },
  "results": [
    {
      "id": "known-malicious-package",
      "severity": "error",
      "message": "Blocked known malicious/typosquat package: proc-macro1@1.0.107",
      "file": "./Cargo.lock",
      "line": 0,
      "suggestion": "Remove or replace this dependency immediately."
    },
    {
      "id": "native-build-surface",
      "severity": "warning",
      "message": "build script dependency: arrayref@0.3.10",
      "file": "./Cargo.lock",
      "line": 0,
      "suggestion": "Review build scripts and proc-macros for untrusted execution."
    }
  ]
}
```

`errors + warnings + passed` is a partition of `total`: a package that is both
known-malicious and a build surface is counted once, as the error.

## What it detects

- **Known-malicious packages** (`error`) — the `proc-macro1` / `proc-macro-en`
  typosquat family, hardcoded.
- **Proc-macro crates** (`warning`) — a curated name list (`proc-macro2`, `syn`,
  `quote`, `serde_derive`, `tokio-macros`, …) plus a name heuristic catching
  typosquats and `*-derive` / `*-macros` / `*-impl` crates.
- **Build script dependencies** (`warning`) — names containing `build`, plus
  `cc` and `cmake`.

This is a **name heuristic over `Cargo.lock`, not static analysis**. It does not
read `build.rs`, does not inspect crate source, and cannot detect a malicious
crate with an innocuous name. Treat output as a review queue, not a verdict.

`Cargo.lock` is parsed as TOML. Non-`[[package]]` sections (`[[patch.unused]]`,
`[[metadata]]`) are not read as packages, a `[[package]]` missing its `version`
is still reported, and a file that cannot be parsed is an **error**, never an
empty result — an empty result reads as an all-clear, which is the one failure
mode a scanner must not have.

`--lockfile` is restricted to paths inside the current directory. A path that
resolves outside it — via `..`, an absolute path, or a symlink — is rejected
before the file is opened.

## Not implemented

Stated plainly so nothing here is mistaken for working functionality:

- **No advisory-database lookups.** There is no OSV, RustSec, or PhantomDB
  integration. The only threat data is the hardcoded typosquat blocklist.
- **`--watch` is a stub.** It prints that eBPF support is coming and exits `2`.
  There is no runtime interception in this release; `--check` is the only mode
  that does real work. This means the tool does not yet do what its crate
  description ("runtime security gateway") suggests.
- **No SARIF output.** `--format` accepts only `text` and `json`; anything else
  is rejected with a non-zero exit naming the valid values.
- **No CFFI or Python analysis.** It reads Rust `Cargo.lock` files only.

## Development

```bash
cargo test              # 29 tests
cargo test --release
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
```

Tests live in `src/*.rs` unit-test modules and `tests/json_integration.rs`. The
integration tests invoke the compiled binary, because the defect classes that
reached CI here (a hardcoded timestamp, a summary that double-counted a package)
were invisible to tests that build the report struct in-process.

See [CHANGELOG.md](CHANGELOG.md) for the full history, including the parser
false-negatives fixed in this release.

## Related tools

- **[vibeguard](https://github.com/yunaremaia/vibeguard)** — static scanner for AI-generated code: hardcoded secrets, SQL injection, dangerous `eval`/`exec`, CORS wildcards
- **[ci-sandbox](https://github.com/yunaremaia/ci-sandbox)** — local CI pipeline simulator; see what runs and what skips without executing anything
- **[agent-workspace](https://github.com/yunaremaia/agent-workspace)** — git worktree manager for parallel AI coding agents, with state persistence
- **[agent-guard](https://github.com/yunaremaia/agent-guard)** — policy-as-code for AI agent permissions, defined in YAML and enforced at runtime

## License

AGPL-3.0 — see [LICENSE](LICENSE).