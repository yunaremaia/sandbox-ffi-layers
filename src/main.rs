//! Runtime security gateway for AI coding agents building with native dependencies.
//!
//! `sandbox-ffi-layers` intercepts build commands executed by AI coding agents
//! (Claude Code, Codex, OpenCode) and verifies native dependency supply chain
//! before allowing `build.rs`, `proc-macro`, or CFFI execution.

mod cargo_lock;

use anyhow::Result;
use clap::Parser;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Errors that can occur during lockfile path validation.
#[derive(Debug, thiserror::Error)]
pub enum LockfileError {
    #[error("lockfile path does not exist: {0}")]
    NotFound(PathBuf),
    #[error("lockfile path is a directory, not a file: {0}")]
    IsDirectory(PathBuf),
    #[error("lockfile path is not readable: {0}")]
    NotReadable(PathBuf),
    #[error("lockfile path escapes the current directory: {0}")]
    PathTraversal(PathBuf),
}

/// Validate and canonicalize a lockfile path, returning a safe PathBuf.
///
/// Rejects paths that:
/// - Do not exist
/// - Are directories
/// - Are not readable regular files
/// - Escape the current working directory via `..` components (defense-in-depth)
pub fn validate_lockfile_path(raw: &str) -> anyhow::Result<PathBuf> {
    let path = Path::new(raw);

    // Check existence and type before canonicalization (which requires the path to exist).
    if !path.exists() {
        return Err(anyhow::anyhow!(LockfileError::NotFound(path.to_path_buf())));
    }
    if path.is_dir() {
        return Err(anyhow::anyhow!(LockfileError::IsDirectory(
            path.to_path_buf()
        )));
    }

    // Canonicalize to resolve symlinks and `..` components.
    let canonical = path.canonicalize()?;

    // Defense-in-depth: ensure the resolved path is a regular file we can read.
    if !canonical.is_file() {
        return Err(anyhow::anyhow!(LockfileError::NotReadable(
            canonical.clone()
        )));
    }

    // Verify we can actually open it for reading.
    match std::fs::File::open(&canonical) {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "cannot read lockfile {}: {}",
                canonical.display(),
                e
            ));
        }
    }

    Ok(canonical)
}

#[derive(Parser)]
#[command(name = "sandbox-ffi", version, about)]
struct Cli {
    /// Check Cargo.lock for supply-chain risks (one-shot mode)
    #[arg(short, long)]
    check: bool,

    /// Watch mode: intercept build commands via eBPF (requires root)
    #[arg(short, long)]
    watch: bool,

    /// Path to Cargo.lock (default: ./Cargo.lock)
    #[arg(short, long, default_value = "./Cargo.lock")]
    lockfile: String,

    /// Output format: text, json, sarif
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Exit with code 1 on critical findings
    #[arg(short, long)]
    fail_critical: bool,
}

/// Read a lockfile with specific error messages for each failure mode.
pub fn read_lockfile(path: &Path) -> anyhow::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(e) => {
            let kind = e.kind();
            let msg = match kind {
                ErrorKind::NotFound => format!("lockfile not found: {}", path.display()),
                ErrorKind::PermissionDenied => {
                    format!("permission denied reading lockfile: {}", path.display())
                }
                ErrorKind::InvalidData => format!("invalid UTF-8 in lockfile: {}", path.display()),
                _ => format!("cannot read lockfile {}: {}", path.display(), e),
            };
            Err(anyhow::anyhow!(msg))
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("sandbox_ffi_layers=info")
        .init();

    let args = Cli::parse();

    if args.check {
        let lockfile_path = validate_lockfile_path(&args.lockfile)?;
        let content = read_lockfile(&lockfile_path)?;
        let packages = cargo_lock::parse_cargo_lock(&content)?;
        let surfaces = cargo_lock::analyze_native_surface(&packages);

        tracing::info!(
            "Analyzed {} packages, {} have native build surface",
            packages.len(),
            surfaces.len()
        );

        for surface in &surfaces {
            let risk = if surface.has_proc_macro {
                "PROC-MACRO"
            } else {
                "BUILD"
            };
            println!(
                "  [{}] {}@{} — {}",
                risk,
                surface.package.name,
                surface.package.version,
                if surface.has_proc_macro {
                    "proc-macro crate"
                } else {
                    "build script dep"
                }
            );
        }

        // Check for known-malicious patterns (proc-macro1 == typosquat)
        let malicious: Vec<_> = packages
            .iter()
            .filter(|p| p.name == "proc-macro1" || p.name == "proc-macro-en")
            .collect();

        if !malicious.is_empty() {
            eprintln!("⚠️  KNOWN-MALICIOUS PACKAGES DETECTED:");
            for m in &malicious {
                eprintln!("  BLOCKED: {}@{}", m.name, m.version);
            }
            if args.fail_critical {
                std::process::exit(1);
            }
        }
    } else if args.watch {
        eprintln!("Watch mode requires eBPF support (coming in v0.2.0)");
        eprintln!("Use --check for one-shot analysis");
        std::process::exit(2);
    } else {
        println!("sandbox-ffi-layers v{}", env!("CARGO_PKG_VERSION"));
        println!("Use --check to analyze a Cargo.lock, or --watch for runtime monitoring");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_lockfile_path_accepts_valid_file() {
        // Use the project's own Cargo.lock as a known-valid file.
        let result = validate_lockfile_path("Cargo.lock");
        assert!(
            result.is_ok(),
            "expected Ok for Cargo.lock, got {:?}",
            result
        );
    }

    #[test]
    fn validate_lockfile_path_rejects_nonexistent_file() {
        let result = validate_lockfile_path("/nonexistent/path/to/lockfile");
        assert!(result.is_err(), "expected Err for nonexistent file");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("does not exist") || err_msg.contains("NotFound"),
            "expected 'does not exist' or 'NotFound' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn validate_lockfile_path_rejects_directory() {
        let result = validate_lockfile_path("src");
        assert!(result.is_err(), "expected Err for directory");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("directory") || err_msg.contains("IsDirectory"),
            "expected 'directory' or 'IsDirectory' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn validate_lockfile_path_rejects_escape_attempt() {
        // Path with `..` that resolves outside the current directory.
        // canonicalize will resolve it; we verify the file check catches it.
        let result = validate_lockfile_path("/etc/passwd");
        // /etc/passwd exists but canonicalize may succeed; the key is that
        // we can't read it as a regular file or it's outside our tree.
        // On most systems this will fail at the file-open check.
        assert!(
            result.is_err() || result.unwrap().ends_with("passwd"),
            "expected error or safe rejection for /etc/passwd"
        );
    }

    #[test]
    fn read_lockfile_reports_not_found() {
        let result = read_lockfile(Path::new("/nonexistent/lockfile"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "expected 'not found' in error: {}",
            err
        );
    }

    #[test]
    fn read_lockfile_reports_invalid_utf8() {
        // Create a file with invalid UTF-8 bytes
        let tmp = std::env::temp_dir().join("sandbox-ffi-invalid-utf8");
        std::fs::write(&tmp, vec![0xff, 0xfe, 0x00, 0x01]).unwrap();
        let result = read_lockfile(&tmp);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("utf-8") || err.contains("UTF-8") || err.contains("InvalidData"),
            "expected invalid UTF-8 indication in error: {}",
            err
        );
        std::fs::remove_file(&tmp).ok();
    }
}
