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

## Cross-Language Policy Examples

`sandbox-ffi-layers` supports unified polyglot security policies via YAML configuration files. Below are real-world policy examples for Python, Node.js, and multi-language monorepos.

### 1. Python (`setup.py` / CFFI Build Phases)

Restricts dangerous builtins and execution primitives (`os.system`, `subprocess`, `eval`) during Python package installation and native CFFI/setuptools build phases.

#### Policy YAML (`sandbox-policy.yaml`)
```yaml
version: "1"
policies:
  python:
    enabled: true
    allow_network: false
    restricted_functions:
      - "os.system"
      - "os.popen"
      - "subprocess.call"
      - "subprocess.Popen"
      - "eval"
      - "exec"
    build_phases:
      - name: "setup.py build_ext"
        block_shell_escaping: true
```

#### Sample Directory Structure
```text
my-python-project/
├── setup.py
├── pyproject.toml
├── sandbox-policy.yaml
└── src/
    └── native_module.c
```

#### Run it
```bash
sandbox-ffi --check --policy ./sandbox-policy.yaml --target ./pyproject.toml
```

#### What it prevents
Prevents AI coding agents or compromised PyPI packages from executing arbitrary shell commands, spawning unauthorized child processes, or evaluating dynamic code strings during `pip install` or `setup.py build_ext` execution.

---

### 2. Node.js (`npm` Scripts / `node-gyp`)

Prevents unauthorized process execution, remote downloads, and file permission tampering during package installation (`npm install`) or native module compilation (`node-gyp`).

#### Policy YAML (`sandbox-policy.yaml`)
```yaml
version: "1"
policies:
  nodejs:
    enabled: true
    allow_lifecycle_scripts: true
    restricted_apis:
      - "child_process.exec"
      - "child_process.execSync"
      - "child_process.spawn"
      - "fs.chmod"
      - "fs.chmodSync"
    forbidden_modules:
      - "node-fetch"
      - "axios"
```

#### Sample Directory Structure
```text
my-node-project/
├── package.json
├── binding.gyp
├── sandbox-policy.yaml
└── src/
    └── addon.cc
```

#### Run it
```bash
sandbox-ffi --check --policy ./sandbox-policy.yaml --target ./package.json
```

#### What it prevents
Blocks malicious postinstall scripts from invoking `child_process` to run arbitrary binaries, downloading unauthorized payloads via HTTP libraries, or modifying binary permissions (`fs.chmod`) during native addon compilation.

---

### 3. Multi-Language Monorepo

For polyglot repositories containing both Rust components (`build.rs`) and Node.js components (`npm install`), policies can be combined under a single unified configuration file.

#### Policy YAML (`sandbox-policy.yaml`)
```yaml
version: "1"
policies:
  rust:
    enabled: true
    block_network_in_build_rs: true
    block_malicious_proc_macros: true
  nodejs:
    enabled: true
    restricted_apis:
      - "child_process.exec"
      - "fs.chmod"
  python:
    enabled: true
    restricted_functions:
      - "os.system"
      - "subprocess.Popen"
```

#### Sample Directory Structure
```text
polyglot-repo/
├── Cargo.lock
├── package.json
├── setup.py
└── sandbox-policy.yaml
```

#### Run it
```bash
sandbox-ffi --check --policy ./sandbox-policy.yaml --lockfile ./Cargo.lock
```

#### What it prevents
Enforces rigorous cross-language containment in multi-service or monorepo environments where AI agents might interact with Rust, Node.js, and Python tooling simultaneously, preventing supply-chain attacks across all build ecosystems.

---

## Status

**v0.1.0-alpha** — Cargo.lock parser + proc-macro detection + known-malicious blocklist.

See [PROPOSAL.md](PROPOSAL.md) for full roadmap.

## License

AGPL-3.0 — see [LICENSE](LICENSE).

# sandbox-ffi-layers

![CI](https://github.com/yunaremaia/sandbox-ffi-layers/actions/workflows/ci.yml/badge.svg)
