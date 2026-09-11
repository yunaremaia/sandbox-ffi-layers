//! Cargo.lock parser for extracting native dependencies.
//!
//! Identifies crates that have proc-macros, build.rs, or build dependencies
//! — the surface for supply-chain attacks at build time.

use std::collections::HashMap;

/// A package extracted from Cargo.lock.
#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub checksum: Option<String>,
    pub dependencies: Vec<String>,
}

/// Analysis result for a package with native build surface.
#[derive(Debug, Clone, PartialEq)]
pub struct NativeSurface {
    pub package: Package,
    pub has_proc_macro: bool,
    pub has_build_script: bool,
    pub has_build_dependencies: bool,
}

/// Parse Cargo.lock v3 format and return a list of packages.
pub fn parse_cargo_lock(content: &str) -> anyhow::Result<Vec<Package>> {
    let mut packages = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_checksum: Option<String> = None;
    let mut current_deps: Vec<String> = Vec::new();
    let mut in_package = false;
    let mut in_deps = false;
    let mut deps_buffer = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        
        if trimmed == "[[package]]" {
            // Save previous if exists
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                packages.push(Package {
                    name,
                    version,
                    checksum: current_checksum.take(),
                    dependencies: std::mem::take(&mut current_deps),
                });
            }
            in_package = true;
            in_deps = false;
            continue;
        }

        if !in_package {
            continue;
        }

        // Handle multi-line dependencies array
        if in_deps {
            deps_buffer.push_str(trimmed);
            if trimmed.contains(']') {
                // Parse the accumulated buffer
                let inner = deps_buffer
                    .trim_start_matches('[')
                    .trim_end_matches(']');
                current_deps = inner
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                in_deps = false;
                deps_buffer.clear();
            }
            continue;
        }

        if trimmed.starts_with("dependencies") {
            if trimmed.contains('[') && trimmed.contains(']') && trimmed.matches('"').count() >= 2 {
                // Single-line: dependencies = ["a", "b"]
                let start = trimmed.find('[').unwrap();
                let end = trimmed.rfind(']').unwrap();
                let inner = &trimmed[start + 1..end];
                current_deps = inner
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            } else if trimmed.contains('[') {
                // Multi-line starting
                in_deps = true;
                let start = trimmed.find('[').unwrap_or(0);
                deps_buffer = trimmed[start..].to_string();
                if deps_buffer.contains(']') {
                    // Closed on same line somehow
                    let inner = deps_buffer
                        .trim_start_matches('[')
                        .trim_end_matches(']');
                    current_deps = inner
                        .split(',')
                        .map(|s| s.trim().trim_matches('"').to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    in_deps = false;
                    deps_buffer.clear();
                }
            }
            continue;
        }

        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            match key {
                "name" => current_name = Some(value.to_string()),
                "version" => current_version = Some(value.to_string()),
                "checksum" => current_checksum = Some(value.to_string()),
                _ => {}
            }
        }
    }

    // Save last package
    if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
        packages.push(Package {
            name,
            version,
            checksum: current_checksum,
            dependencies: current_deps,
        });
    }

    Ok(packages)
}

/// Build a set of known proc-macro crate names for heuristic detection.
pub fn known_proc_macro_crates() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let macros = [
        ("serde_derive", "proc-macro for serde"),
        ("tokio-macros", "proc-macro for tokio"),
        ("async-trait", "proc-macro for async-trait"),
        ("thiserror-impl", "proc-macro for thiserror"),
        ("proc-macro2", "foundational proc-macro crate"),
        ("syn", "parsing foundation for proc-macros"),
        ("quote", "quoting foundation for proc-macros"),
        ("futures-macro", "proc-macro for futures"),
        ("tracing-attributes", "proc-macro for tracing"),
        ("pin-project-internal", "proc-macro for pin-project"),
        ("zerocopy-derive", "proc-macro for zerocopy"),
        ("strum_macros", "proc-macro for strum"),
        ("displaydoc", "proc-macro for displaydoc"),
        ("validator-derive", "proc-macro for validator"),
    ];
    for (name, desc) in macros {
        map.insert(name.to_string(), desc.to_string());
    }
    map
}

/// Heuristic: detect if a crate name looks like a proc-macro crate.
fn looks_like_proc_macro(name: &str) -> bool {
    // Known proc-macro patterns (including typosquats of proc-macro2)
    if name == "proc-macro1" || name == "proc-macro-en" {
        return true;
    }
    if name.contains("macro") && !name.contains("macos") {
        return true;
    }
    // Derive/impl macros: serde_derive, thiserror-impl, futures-macro, etc.
    if name.ends_with("_derive")
        || name.ends_with("-impl")
        || name.ends_with("_macros")
        || name.ends_with("-macros")
    {
        return true;
    }
    if name == "syn" || name == "quote" {
        return true;
    }
    false
}

/// Analyze packages and return those with native build surface.
///
/// Heuristic: a crate has native surface if:
/// 1. It's a known proc-macro crate (by name heuristic)
/// 2. It has build-dependencies in Cargo.toml (we'd need Cargo.toml info; for now we flag based on name)
///
/// For MVP, we use a name-based heuristic. Full implementation would require
/// inspecting the actual crate source.
pub fn analyze_native_surface(packages: &[Package]) -> Vec<NativeSurface> {
    let proc_macros = known_proc_macro_crates();

    packages
        .iter()
        .map(|pkg| {
            let has_proc_macro = proc_macros.contains_key(&pkg.name) || looks_like_proc_macro(&pkg.name);
            let has_build_script = pkg.name.contains("build") || pkg.name == "cc" || pkg.name == "cmake";
            let has_build_dependencies = !pkg.dependencies.is_empty()
                && pkg
                    .dependencies
                    .iter()
                    .any(|d| d.contains("build") || d == "cc");

            NativeSurface {
                package: pkg.clone(),
                has_proc_macro,
                has_build_script,
                has_build_dependencies,
            }
        })
        .filter(|s| s.has_proc_macro || s.has_build_script || s.has_build_dependencies)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cargo_lock_basic() {
        let input = r#"
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "arrayref"
version = "0.3.10"
checksum = "f7347e8e8b21f0af847a0ffb4f2e3a99a5afa8ed3e4099e7a0561adb8cb3d966"
dependencies = [
 "proc-macro1",
]

[[package]]
name = "proc-macro1"
version = "1.0.107"
checksum = "a6b1e72e39b5d6a87d6867def29ae66ad9f2d7e3c2e1d3e4c6d5c6e7f8a9b0c1d"

[[package]]
name = "serde"
version = "1.0.228"
checksum = "f75b0e4b64c0b4e4e5b8f5a5a5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5b5c"
"#;

        let packages = parse_cargo_lock(input).unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "arrayref");
        assert_eq!(packages[0].version, "0.3.10");
        assert_eq!(packages[0].dependencies, vec!["proc-macro1"]);
        assert_eq!(packages[1].name, "proc-macro1");
        assert_eq!(packages[2].name, "serde");
    }

    #[test]
    fn analyze_native_surface_detects_proc_macro() {
        let input = r#"
version = 3

[[package]]
name = "serde_derive"
version = "1.0.228"

[[package]]
name = "arrayref"
version = "0.3.10"

[[package]]
name = "proc-macro1"
version = "1.0.107"
"#;

        let packages = parse_cargo_lock(input).unwrap();
        let surfaces = analyze_native_surface(&packages);

        // serde_derive should be flagged as proc-macro
        let serde_derive = surfaces.iter().find(|s| s.package.name == "serde_derive");
        assert!(serde_derive.is_some());
        assert!(serde_derive.unwrap().has_proc_macro);

        // proc-macro1 should be flagged (typosquat heuristic)
        let proc_macro1 = surfaces.iter().find(|s| s.package.name == "proc-macro1");
        assert!(proc_macro1.is_some());
        assert!(proc_macro1.unwrap().has_proc_macro);
    }

    #[test]
    fn parse_cargo_lock_single_line_deps() {
        let input = r#"
version = 3

[[package]]
name = "serde"
version = "1.0.228"
dependencies = ["serde_derive", "cfg-if"]
"#;

        let packages = parse_cargo_lock(input).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].dependencies, vec!["serde_derive", "cfg-if"]);
    }

    #[test]
    fn looks_like_proc_macro_detects_typosquats() {
        assert!(looks_like_proc_macro("proc-macro1"));
        assert!(looks_like_proc_macro("proc-macro-en"));
        assert!(looks_like_proc_macro("serde_derive"));
        assert!(looks_like_proc_macro("futures-macro"));
        assert!(!looks_like_proc_macro("serde"));
        assert!(!looks_like_proc_macro("tokio"));
    }
}
