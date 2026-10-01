# Security Policy

## Scope

This policy applies to the `sandbox-ffi-layers` project
(`yunaremaia/sandbox-ffi-layers`), a runtime security gateway for AI coding
agents building with native dependencies (`build.rs`, `proc-macro`, CFFI).

We consider the following in scope:

- The `sandbox-ffi` command-line tool and its Cargo.lock parser
  (`src/cargo_lock.rs`).
- Lockfile handling, including format detection and checksum verification
  (see #37, #32).
- CLI flag handling, including `--format` and `--output` (see #36).
- Path validation for `--lockfile` (see #24).

Out of scope (and therefore not covered by this policy):

- The upstream supply-chain databases (PhantomDB, OSV, RustSec) queried at
  runtime.
- Third-party crates in `Cargo.lock`, other than their declared integrity
  (checksum) and known-malicious signatures.

## Reporting a Vulnerability

Please **do not open a public issue** for security vulnerabilities.
Private disclosure is preferred so we can coordinate a fix before details
become public.

- Report privately by emailing the maintainers (see package `authors` in
  `Cargo.toml`).
- Include: the affected version, a description of the vulnerability, steps to
  reproduce, and (if known) a suggested fix.
- You will receive an acknowledgement within **3 business days**. We aim to
  triage and respond with a mitigation plan within **14 days** of
  confirmation.

## Supported Versions

Only the most recent release is actively supported with security fixes.
Older releases are patched on a best-effort basis if the maintainers are
notified of an actively exploited vulnerability.

## Security Model

`sandbox-ffi-layers` is a pre-execution guard. It inspects `Cargo.lock` and
blocks native build surface BEFORE code runs. The security model assumes:

- The lockfile is a local, user-controlled input that may be malicious or
  tampered (see [Path traversal](#path-traversal) and [Cargo.lock
  integrity](#cargo.lock-integrity)).
- An attacker may control the build context (a compromised registry, a
  malicious dependency, or a modified lockfile) but does **not** control the
  `sandbox-ffi` binary itself.
- Blocking at this layer is a *gate*, not a root sandbox: `sandbox-ffi`
  reduces the attack surface but does not replace OS-level confinement (see
  [FFI boundary safety](#ffi-boundary-safety)).

### FFI boundary safety

`sandbox-ffi-layers` inspects and gates native build steps; it does not itself
execute `build.rs`, procedural macros, or CFFI code. The tool must never
execute or deserialize untrusted native code. Keep it that way: any code path
adding runtime interception must still rely on the OS sandbox (eBPF watch
mode, container boundaries) for actual enforcement.

### Cargo.lock integrity

Cargo.lock `[[package]] checksum` fields are the integrity anchor for
dependencies. The parser must:

- Validate the lockfile format version before parsing (#37).
- Verify checksums against expected values and detect missing or mismatched
  entries (#32).
- Never ignore a checksum mismatch silently; a tampered dependency must be
  reported.

### CLI flag safety

Flags must do what they say. Silently ignored flags (`--format`, `--output`)
hide configuration mistakes and can cause an operator to believe a check ran
that did not (#36). A rejected or unimplemented flag must fail loudly rather
than pass unnoticed.

### Path traversal

The `--lockfile` argument is a filesystem path. It must be validated so it
cannot read arbitrary files outside the working directory (#24): canonicalize
the path and reject escapes via `..`, absolute paths outside the workspace,
and symlinks that resolve outside of it. Error messages must reference the
path, never leak file contents.

## Reporting Bug Reports

Non-security bugs and feature requests should be filed as GitHub issues using
the provided templates. If you are unsure whether something is a security
vulnerability, err on the side of private disclosure.

## Thanks

Thank you for helping keep `sandbox-ffi-layers` and the AI coding agent
supply chain safe.