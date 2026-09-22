//! Runtime security gateway for AI coding agents building with native dependencies.
//!
//! `sandbox-ffi-layers` intercepts build commands executed by AI coding agents
//! (Claude Code, Codex, OpenCode) and verifies native dependency supply chain
//! before allowing `build.rs`, `proc-macro`, or CFFI execution.

mod cargo_lock;

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

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

    /// Output JSON format (shorthand for --format json)
    #[arg(long)]
    json: bool,

    /// Exit with code 1 on critical findings
    #[arg(short, long)]
    fail_critical: bool,
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
        let content = std::fs::read_to_string(&args.lockfile)?;
        let packages = cargo_lock::parse_cargo_lock(&content)?;
        let surfaces = cargo_lock::analyze_native_surface(&packages);

        let malicious: Vec<_> = packages
            .iter()
            .filter(|p| p.name == "proc-macro1" || p.name == "proc-macro-en")
            .collect();

        if is_json {
            let total = packages.len();
            let errors = malicious.len();
            let warnings = surfaces.len();
            let passed = total.saturating_sub(errors + warnings);

            let mut results = Vec::new();
            for m in &malicious {
                results.push(JsonResult {
                    id: "known-malicious-package".to_string(),
                    severity: "error".to_string(),
                    message: format!("Blocked known malicious/typosquat package: {}@{}", m.name, m.version),
                    file: args.lockfile.clone(),
                    line: 0,
                    suggestion: Some("Remove or replace this dependency immediately.".to_string()),
                });
            }

            for surface in &surfaces {
                let risk_msg = if surface.has_proc_macro {
                    format!("proc-macro crate: {}@{}", surface.package.name, surface.package.version)
                } else {
                    format!("build script dependency: {}@{}", surface.package.name, surface.package.version)
                };
                results.push(JsonResult {
                    id: "native-build-surface".to_string(),
                    severity: "warning".to_string(),
                    message: risk_msg,
                    file: args.lockfile.clone(),
                    line: 0,
                    suggestion: Some("Review build scripts and proc-macros for untrusted execution.".to_string()),
                });
            }

            let report = JsonReport {
                version: "1.0.0".to_string(),
                timestamp: "2026-09-18T12:00:00Z".to_string(),
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
                if args.fail_critical {
                    std::process::exit(1);
                }
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
            println!(r#"{{"version": "1.0.0", "message": "sandbox-ffi-layers v{}"}}"#, env!("CARGO_PKG_VERSION"));
        } else {
            println!("sandbox-ffi-layers v{}", env!("CARGO_PKG_VERSION"));
            println!("Use --check to analyze a Cargo.lock, or --watch for runtime monitoring");
        }
    }

    Ok(())
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
            results: vec![
                JsonResult {
                    id: "test-finding".to_string(),
                    severity: "error".to_string(),
                    message: "Found test issue with unicode 🦀".to_string(),
                    file: "Cargo.lock".to_string(),
                    line: 42,
                    suggestion: Some("Fix it".to_string()),
                }
            ],
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
        assert_eq!(parsed["results"][0]["message"], "Found test issue with unicode 🦀");
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