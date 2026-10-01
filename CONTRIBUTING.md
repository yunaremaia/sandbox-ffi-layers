# Contributing

Thanks for your interest in contributing! `sandbox-ffi-layers` is a runtime
security gateway for AI coding agents, so correctness and review quality matter
more than speed of merging. This guide walks through the setup, the expected
workflow, and how changes are evaluated.

## Getting started

### Prerequisites

- **Rust** (stable toolchain, `rust-version = 1.80` or newer). The project
  builds on `stable`; no nightly features are used.
- **cargo** (installed with Rust via rustup or your system package manager).
- A GitHub account for opening issues and pull requests.

### Fork and clone

1. Fork the repository.
2. Clone your fork and confirm the toolchain works:

   ```bash
   git clone https://github.com/YOUR_USERNAME/sandbox-ffi-layers.git
   cd sandbox-ffi-layers
   cargo build --release
   ```

`cargo build --release` is the build the CI pipeline exercises, so it is a good
first check that your toolchain matches the project's expectations.

### Pick an issue

- Open issues labelled `good first issue` are a good place to start; they are
  scoped and reviewed for being newcomer-friendly.
- Leave a short comment on the issue you plan to work on so others know it is
  in progress, and link it from your pull request.
- If you want to work on something not described by an existing issue, open one
  first so the change is discussed before code is written.

### Make your change

Work on a separate branch off `main`:

```bash
git checkout -b my-feature
```

Make focused commits with clear messages. Keep each pull request small: a
reviewer can merge a small, well-scoped change quickly.

### Run the checks

CI runs four commands that must all pass before a pull request merges:

```bash
cargo build --release        # build
cargo test --release         # tests
cargo fmt -- --check         # formatting
cargo clippy -- -D warnings  # lint
```

Run all four locally before pushing. The two that catch most contributions:

- `cargo fmt -- --check` — output must match `rustfmt`, with no diff.
- `cargo clippy -- -D warnings` — clippy must pass with no warnings at all.

### Open a pull request

- Make sure the checks above pass locally.
- Push your branch to your fork:

  ```bash
  git push origin my-feature
  ```

- Open a pull request against `main` using the repository's pull request
  template (`.github/PULL_REQUEST_TEMPLATE.md`), with a clear description of
  the changes.
- Reference the issue it resolves in the description, e.g. `Fixes #12`.
- CI runs on every pull request and must be green before merge.

## Reporting issues

Open an issue at [GitHub Issues](https://github.com/yunaremaia/sandbox-ffi-layers/issues).

Use the issue templates (`.github/ISSUE_TEMPLATE/bug_report.md` and
`.github/ISSUE_TEMPLATE/feature_request.md`) when they fit. A good report
includes:

- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, version, toolchain)

## Security

This project's core threat model is supply-chain attacks on native dependency
builds. If you believe you have found a security vulnerability, avoid public
disclosure details and report it through a private channel (maintainer contact
via GitHub) rather than opening a public issue. This tool parses untrusted
input (`Cargo.lock` files), so a crash or panic on malformed input is
security-relevant, not just a style issue.

## Code style

- Follow `rustfmt` formatting — the `cargo fmt -- --check` gate is mandatory.
  Match the style of the surrounding code.
- Prefer explicit error handling over `unwrap()`/`expect()` in library paths.
  Panics on malformed input are security-relevant, not just style.
- Keep documentation and in-repo docs in sync with the behaviour you change.
- Run the configured linters and formatters before opening a pull request.

## Code of Conduct

By participating in this project you agree to uphold the project's code of
conduct. Be respectful and constructive in issues, pull requests, and reviews.

## License

By contributing you agree that your contributions are licensed under the
project's license (AGPL-3.0, see `LICENSE`).
