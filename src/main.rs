//! Runtime security gateway for AI coding agents building with native dependencies.
//!
//! `sandbox-ffi-layers` intercepts build commands executed by AI coding agents
//! (Claude Code, Codex, OpenCode) and verifies native dependency supply chain
//! before allowing `build.rs`, `proc-macro`, or CFFI execution.

mod cargo_lock;

use anyhow::Result;
use clap::Parser;
use serde::Serialize;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Current UTC time as an RFC 3339 timestamp.
///
/// Implemented with `std` only rather than pulling in a date-time crate, so the
/// release build keeps its current dependency set. `SystemTime` is UTC by
/// definition, so only the civil-date conversion is needed (Howard Hinnant's
/// `civil_from_days`).
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, minute, second
    )
}

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

    // Containment check. `canonicalize` has already resolved every `..` and
    // symlink, so this is the only place a path-escape can be caught. Without
    // it `--lockfile /etc/passwd` reads any file the user can read and echoes
    // its contents into the parse error, which is the arbitrary file read this
    // variant was added to reject. `Path::starts_with` compares components, so
    // a sibling like `/root-evil` does not match a `/root` prefix.
    let cwd = std::env::current_dir()?.canonicalize()?;
    if !canonical.starts_with(&cwd) {
        return Err(anyhow::anyhow!(LockfileError::PathTraversal(
            path.to_path_buf()
        )));
    }

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

    /// Output format: text, json
    #[arg(short, long, default_value = "text", value_parser = ["text", "json"])]
    format: String,

    /// Output JSON format (shorthand for --format json)
    #[arg(long)]
    json: bool,

    /// Exit with code 1 on critical findings
    #[arg(long)]
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

#[derive(Serialize, Debug)]
struct JsonReport {
    version: String,
    timestamp: String,
    summary: JsonSummary,
    results: Vec<JsonResult>,
}

#[derive(Serialize, Debug)]
struct JsonSummary {
    total: usize,
    errors: usize,
    warnings: usize,
    passed: usize,
}

#[derive(Serialize, Debug)]
struct JsonResult {
    id: String,
    severity: String,
    message: String,
    file: String,
    line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestion: Option<String>,
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let is_json = args.json || args.format == "json";

    if !is_json {
        tracing_subscriber::fmt()
            .with_env_filter("sandbox_ffi_layers=info")
            .init();
    }

    if args.check {
        let lockfile_path = validate_lockfile_path(&args.lockfile)?;
        let content = read_lockfile(&lockfile_path)?;
        let packages = cargo_lock::parse_cargo_lock(&content)?;
        let surfaces = cargo_lock::analyze_native_surface(&packages);

        let malicious: Vec<_> = packages
            .iter()
            .filter(|p| p.name == "proc-macro1" || p.name == "proc-macro-en")
            .collect();

        if is_json {
            let total = packages.len();
            // A package can be both a known-malicious typosquat AND a native
            // build surface. Counting it in both buckets makes
            // errors + warnings + passed exceed `total`, so the summary stops
            // being a partition of the package set. Assign each package to
            // exactly one bucket, errors taking precedence, and emit results
            // for the same set the summary counts.
            let malicious_names: std::collections::HashSet<&str> =
                malicious.iter().map(|p| p.name.as_str()).collect();
            let unflagged_surfaces: Vec<_> = surfaces
                .iter()
                .filter(|s| !malicious_names.contains(s.package.name.as_str()))
                .collect();

            let errors = malicious.len();
            let warnings = unflagged_surfaces.len();
            let passed = total - errors - warnings;

            let mut results = Vec::new();
            for m in &malicious {
                results.push(JsonResult {
                    id: "known-malicious-package".to_string(),
                    severity: "error".to_string(),
                    message: format!(
                        "Blocked known malicious/typosquat package: {}@{}",
                        m.name, m.version
                    ),
                    file: args.lockfile.clone(),
                    line: 0,
                    suggestion: Some("Remove or replace this dependency immediately.".to_string()),
                });
            }

            for surface in &unflagged_surfaces {
                let risk_msg = if surface.has_proc_macro {
                    format!(
                        "proc-macro crate: {}@{}",
                        surface.package.name, surface.package.version
                    )
                } else {
                    format!(
                        "build script dependency: {}@{}",
                        surface.package.name, surface.package.version
                    )
                };
                results.push(JsonResult {
                    id: "native-build-surface".to_string(),
                    severity: "warning".to_string(),
                    message: risk_msg,
                    file: args.lockfile.clone(),
                    line: 0,
                    suggestion: Some(
                        "Review build scripts and proc-macros for untrusted execution.".to_string(),
                    ),
                });
            }

            let report = JsonReport {
                version: "1.0.0".to_string(),
                timestamp: now_rfc3339(),
                summary: JsonSummary {
                    total,
                    errors,
                    warnings,
                    passed,
                },
                results,
            };

            println!("{}", serde_json::to_string_pretty(&report)?);

            if errors > 0 || (args.fail_critical && warnings > 0) {
                std::process::exit(1);
            }
        } else {
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

            if !malicious.is_empty() {
                eprintln!("⚠️  KNOWN-MALICIOUS PACKAGES DETECTED:");
                for m in &malicious {
                    eprintln!("  BLOCKED: {}@{}", m.name, m.version);
                }
                std::process::exit(1);
            }

            if args.fail_critical && !surfaces.is_empty() {
                eprintln!("⚠️  {} native build surface(s) detected (fail-critical)", surfaces.len());
                std::process::exit(1);
            }
        }
    } else if args.watch {
        if is_json {
            eprintln!(r#"{{"error": "Watch mode requires eBPF support (coming in v0.2.0)"}}"#);
        } else {
            eprintln!("Watch mode requires eBPF support (coming in v0.2.0)");
            eprintln!("Use --check for one-shot analysis");
        }
        std::process::exit(2);
    } else {
        if is_json {
            println!(
                r#"{{"version": "1.0.0", "message": "sandbox-ffi-layers v{}"}}"#,
                env!("CARGO_PKG_VERSION")
            );
        } else {
            println!("sandbox-ffi-layers v{}", env!("CARGO_PKG_VERSION"));
            println!("Use --check to analyze a Cargo.lock, or --watch for runtime monitoring");
        }
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
        // This test previously asserted `is_err() || unwrap().ends_with(...)`,
        // which passes whether or not any guard exists — it could not detect
        // the missing containment check. It now asserts the escape is rejected.
        //
        // `/etc/passwd` is used because it is outside the working directory,
        // exists, and is a readable regular file: it clears every other check in
        // `validate_lockfile_path`, so only containment can reject it.
        let result = validate_lockfile_path("/etc/passwd");
        assert!(
            result.is_err(),
            "a path outside the working directory must be rejected, got {:?}",
            result.map(|p| p.display().to_string())
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("escapes the current directory"),
            "expected the traversal error, got: {err_msg}"
        );
    }

    #[test]
    fn validate_lockfile_path_rejects_a_sibling_directory_sharing_a_prefix() {
        // Regression guard for the containment check itself: a sibling named
        // `<cwd>-evil` starts with the *string* `<cwd>` but is not inside it.
        // Comparing strings would let this through; comparing `Path` components
        // does not.
        //
        // The file is created for real because a non-existent path is rejected
        // as "not found" before containment is ever reached, which would make
        // the assertion pass for the wrong reason.
        let cwd = std::env::current_dir().unwrap();
        let parent = cwd.parent().unwrap();
        let evil_dir = parent.join(format!(
            "{}-evil",
            cwd.file_name().unwrap().to_string_lossy()
        ));
        let evil_file = evil_dir.join("Cargo.lock");

        if std::fs::create_dir_all(&evil_dir).is_err() {
            eprintln!("skipping: cannot create sibling dir {}", evil_dir.display());
            return;
        }
        std::fs::write(&evil_file, "version = 3\n").unwrap();

        let result = validate_lockfile_path(evil_file.to_str().unwrap());
        let err_msg = result.unwrap_err().to_string();

        // Clean up regardless of the assertion outcome.
        let _ = std::fs::remove_file(&evil_file);
        let _ = std::fs::remove_dir(&evil_dir);

        assert!(
            err_msg.contains("escapes the current directory"),
            "a prefix-sharing sibling must be rejected as traversal, got: {err_msg}"
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

#[cfg(test)]
mod json_tests {
    use super::*;

    #[test]
    fn test_json_output_schema_structure() {
        let report = JsonReport {
            version: "1.0.0".to_string(),
            timestamp: "2026-09-18T12:00:00Z".to_string(),
            summary: JsonSummary {
                total: 10,
                errors: 1,
                warnings: 2,
                passed: 7,
            },
            results: vec![JsonResult {
                id: "test-finding".to_string(),
                severity: "error".to_string(),
                message: "Found test issue with unicode 🦀".to_string(),
                file: "Cargo.lock".to_string(),
                line: 42,
                suggestion: Some("Fix it".to_string()),
            }],
        };

        let serialized = serde_json::to_string(&report).unwrap();
        assert!(serialized.contains(r#""version":"1.0.0""#));
        assert!(serialized.contains(r#""total":10"#));
        assert!(serialized.contains(r#""errors":1"#));
        assert!(serialized.contains(r#""warnings":2"#));
        assert!(serialized.contains(r#""passed":7"#));
        assert!(serialized.contains(r#""severity":"error""#));
        assert!(serialized.contains("🦀"));

        let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed["version"], "1.0.0");
        assert_eq!(parsed["summary"]["total"], 10);
        assert_eq!(
            parsed["results"][0]["message"],
            "Found test issue with unicode 🦀"
        );
    }

    #[test]
    fn test_json_output_empty_results() {
        let report = JsonReport {
            version: "1.0.0".to_string(),
            timestamp: "2026-09-18T12:00:00Z".to_string(),
            summary: JsonSummary {
                total: 0,
                errors: 0,
                warnings: 0,
                passed: 0,
            },
            results: vec![],
        };

        let serialized = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed["summary"]["total"], 0);
        assert!(parsed["results"].as_array().unwrap().is_empty());
    }
}
