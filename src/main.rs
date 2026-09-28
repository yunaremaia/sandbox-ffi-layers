//! Runtime security gateway for AI coding agents building with native dependencies.
//!
//! `sandbox-ffi-layers` intercepts build commands executed by AI coding agents
//! (Claude Code, Codex, OpenCode) and verifies native dependency supply chain
//! before allowing `build.rs`, `proc-macro`, or CFFI execution.

mod cargo_lock;

use anyhow::Result;
use clap::Parser;

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

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("sandbox_ffi_layers=info")
        .init();

    let args = Cli::parse();

    if args.check {
        let content = std::fs::read_to_string(&args.lockfile)?;
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
