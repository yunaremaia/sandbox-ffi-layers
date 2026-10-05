# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-05

First tagged release. Everything below shipped together: nothing was ever tagged
before this date, so the fixes listed under **Fixed** are part of the initial
release rather than a later patch.

### Fixed

- **`--lockfile` still allowed an arbitrary file read, despite the previous
  release notes claiming it was fixed.** `validate_lockfile_path` canonicalized
  the path and checked that it was a readable regular file, but never compared
  it to the working directory — the `PathTraversal` error variant existed and
  was never constructed. `--lockfile /etc/passwd` read the file and echoed its
  contents back through the TOML parse error. The containment check now runs
  after canonicalization (so `..`, absolute paths and symlinks are all resolved
  first) and compares `Path` components, not strings.
- **The test that covered this could not fail.** It asserted
  `result.is_err() || result.unwrap().ends_with("passwd")`, which is satisfied
  whether or not any guard exists. It now asserts the rejection, and a second
  test covers a prefix-sharing sibling directory (`<cwd>-evil`) that a
  string-prefix comparison would wrongly accept.
- **`Cargo.lock` parser reported clean lockfiles that contained a
  known-malicious package.** `Cargo.lock` is TOML but was read with a
  hand-rolled line scanner that silently mis-parsed real lockfiles in three
  ways, each producing a *clean* report rather than a finding:
  - a `[[package]]` entry with no `version` key was dropped entirely, and its
    dependencies were handed to the following package;
  - any non-`package` section (`[[patch.unused]]`, `[[metadata]]`) was read as
    a continuation of the preceding package, overwriting the last real package
    in the file;
  - a file that is not a parsable lockfile yielded an empty package set, which
    was reported as "no findings".

  The lockfile is now parsed as TOML, and a lockfile that cannot be parsed is
  reported as an error rather than as an all-clear.
- **Version-qualified dependencies defeated the proc-macro heuristic.** Cargo
  writes `"syn 2.0.109"` (and `"syn 2.0.109 (registry+...)"`) whenever a crate
  appears at more than one version, which is the common case in a real lockfile.
  The heuristic compared against the qualified string, so those entries matched
  nothing and the finding vanished. Entries are now reduced to the bare crate
  name before matching.
- **A `[[package]]` missing its `version` key is now reported** rather than
  silently discarded.
- **`--fail-critical` no longer panics the debug binary.** It derived the short
  flag `-f`, which collided with `--format`; clap rejects duplicate shorts in a
  debug assertion, so every debug invocation aborted before doing any work.
  `--fail-critical` is now long-only. This could not reach CI, which runs
  `cargo test --release`.
- **`--format` now rejects an unsupported value instead of ignoring it.**
  `--format sarif`, and any typo such as `--format jsno`, was accepted and then
  discarded: the tool printed text and exited 0, so a caller asking for SARIF
  got neither SARIF nor an error. The supported values are now enforced, and an
  unknown one exits non-zero naming the valid choices.
- **Cargo.lock v4 format was silently ignored by the parser**, producing an
  empty result set that read as "no findings" rather than as a failure. The
  parser now handles it, and a wrong-format lockfile is reported instead of
  quietly yielding zero packages.
- **Arbitrary file read via the lockfile path.** `--lockfile` accepted a path
  that escaped the working directory. Partially fixed in the previous revision
  (path validation, traversal error variant) but the containment check itself
  was missing; see the first entry above.

### Added

- 29 tests. See the "Development" section of the README for what they cover and
  why the integration tests invoke the compiled binary rather than building the
  report struct in-process.

### Known limitations

Not bugs in this release, but behaviours a user will trip over:

- **Text and JSON modes disagree on exit codes.** Text mode exits `0` even when
  it reports a known-malicious package, unless `--fail-critical` is passed;
  JSON mode exits `1` on any error finding automatically. `--format json` is the
  stricter and more predictable CI gate. Documented in the README exit-code
  table rather than papered over, since changing either behaviour is a
  breaking change for existing callers.

### Added (pre-release work, folded into 0.1.0)

**This is a Rust binary crate (`sandbox-ffi`), not a Python package.** There is no
`pyproject.toml` and nothing is published to crates.io or PyPI. Install it by
building from source or with `cargo install --git`:

```bash
cargo install --git https://github.com/yunaremaia/sandbox-ffi-layers.git
```

The scope of this release is narrower than the project's roadmap. It ships a
`Cargo.lock` analyzer and a native-build-surface heuristic. Specifically, it does
**not** yet contain the advisory-database lookups or the runtime interception
layer described in the crate description — see **Not in this release** below.

- `Cargo.lock` parser producing the full package set with each package's
  dependencies, and a public `parse_cargo_lock` API.
- Native build surface analysis (`analyze_native_surface`) that flags two classes
  of entry in a lockfile:
  - **proc-macro crates** — a curated set of well-known proc-macro crate names
    (`proc-macro2`, `syn`, `quote`, `serde_derive`, `tokio-macros`, ...), plus a
    name heuristic that catches typosquats of `proc-macro2` such as `proc-macro1`
    and `proc-macro-en`.
  - **build-script dependencies** — packages that run code at build time.
- Known-malicious package blocklist covering the `proc-macro1` typosquat family,
  reported at `error` severity. A package that is both known-malicious and a build
  surface is reported once, as the block, not twice.
- `sandbox-ffi --check --lockfile <path>` for one-shot analysis, with `--format`
  and the `--json` shorthand, and `--fail-critical` to exit non-zero on findings
  for use as a CI gate.
- Lockfile path validation (`validate_lockfile_path`) rejecting traversal attempts,
  plus specific `not found` / `permission denied` / `invalid UTF-8` error
  messages instead of a single opaque failure.
- JSON output schema with `error` / `warning` / `passed` summary counts that
  partition the package set, and integration tests asserting that invariant and
  that timestamps are real wall-clock values rather than constants.
- GitHub Actions CI running `cargo test --release` and `cargo test`,
  `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo build --release`.
- `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1, with an enforcement contact),
  `CONTRIBUTING.md`, `SECURITY.md`, `FUNDING.yml`, and an AGPL-3.0 `LICENSE`.

### Not in this release

Stated explicitly so nothing here is mistaken for working functionality:

- **Advisory lookups are not implemented.** There is no PhantomDB, OSV, or RustSec
  integration in this release. The only threat data is the hardcoded
  `proc-macro1` typosquat blocklist.
- **`--watch` is a stub.** It prints that eBPF support is coming and exits `2`.
  There is no runtime interception in this release; `--check` is the only mode
  that does real work.
- **No SARIF output and no `--output` flag.** `--format` accepts `text` and
  `json` only; an unsupported value is rejected rather than ignored.
- **No CFFI or Python analysis.** The tool reads Rust `Cargo.lock` files.

[0.1.0]: https://github.com/yunaremaia/sandbox-ffi-layers/releases/tag/v0.1.0