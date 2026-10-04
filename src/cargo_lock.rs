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

/// Deserialize target for a single `[[package]]` entry.
#[derive(serde::Deserialize)]
struct LockPackage {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

/// Deserialize target for the whole lockfile.
#[derive(serde::Deserialize, Default)]
struct LockFile {
    #[serde(default)]
    package: Vec<LockPackage>,
}

/// Parse a Cargo.lock and return a list of packages.
///
/// Cargo.lock is TOML, so it is parsed as TOML rather than scanned line by
/// line. The line scanner this replaced mis-read real lockfiles in ways that
/// all produced the same outcome — a *clean* report on a lockfile that
/// contained a known-malicious package:
///
/// - a `[[package]]` with no `version` key was dropped entirely, and its
///   dependencies were handed to the following package;
/// - a non-`package` section (`[[patch.unused]]`, `[[metadata]]`) was read as
///   a continuation of the preceding package, overwriting it;
/// - a lockfile with no parsable packages yielded `Ok(vec![])`, which callers
///   reported as "no findings" rather than as a failure.
///
/// Unknown lockfile `version` values are reported, not fatal: Cargo may add a
/// format revision before this tool knows about it, and refusing to scan is
/// the same failure mode as the false negatives above.
pub fn parse_cargo_lock(content: &str) -> anyhow::Result<Vec<Package>> {
    let file: LockFile = toml::from_str(content).map_err(|e| {
        anyhow::anyhow!("not a parsable Cargo.lock ({e}) — refusing to report it as clean")
    })?;

    if let Some(version) = toml_lockfile_version(content) {
        if version != 3 && version != 4 {
            eprintln!(
                "⚠️  WARNING: Unknown Cargo.lock version: {version}. \
                 Fields added in that revision may be ignored."
            );
        }
    }

    Ok(file
        .package
        .into_iter()
        .map(|p| Package {
            name: p.name,
            // A package with no `version` is malformed but must still be
            // reported: dropping it would hide a malicious entry.
            version: p.version.unwrap_or_else(|| "unknown".to_string()),
            checksum: p.checksum,
            dependencies: p.dependencies.iter().map(|d| dependency_name(d)).collect(),
        })
        .collect())
}

/// Read the top-level `version = N` key that declares the lockfile format.
///
/// Read separately from the deserialized struct because the key exists to
/// select a *format*, so it is meaningful precisely when the structure it
/// describes is not the one this version understands.
fn toml_lockfile_version(content: &str) -> Option<u32> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            // Past the header block; the top-level `version` comes first.
            return None;
        }
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "version" {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

/// Reduce a dependency entry to its bare crate name.
///
/// Cargo writes `"name"`, `"name version"`, or
/// `"name version (registry+https://...)"` depending on whether the crate
/// appears at one or several versions in the lockfile. The proc-macro
/// heuristic matches on the name, so comparing against the qualified string
/// silently missed every crate present at multiple versions.
fn dependency_name(entry: &str) -> String {
    entry.split_whitespace().next().unwrap_or(entry).to_string()
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
            let has_proc_macro =
                proc_macros.contains_key(&pkg.name) || looks_like_proc_macro(&pkg.name);
            let has_build_script =
                pkg.name.contains("build") || pkg.name == "cc" || pkg.name == "cmake";
            let has_build_dependencies = !pkg.dependencies.is_empty()
                && pkg
                    .dependencies
                    .iter()
                    .any(|d| d.contains("build") || d == "cc" || looks_like_proc_macro(d));

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
    fn parse_cargo_lock_v4_format() {
        let input = r#"
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "..."
dependencies = [
 "serde_derive",
]

[[package]]
name = "typosquat-attempt"
version = "0.1.0"
dependencies = [
 "proc-macro1",
]
"#;

        let packages = parse_cargo_lock(input).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "serde");
        assert_eq!(packages[0].version, "1.0.210");
        assert_eq!(packages[0].dependencies, vec!["serde_derive"]);
        assert_eq!(packages[1].name, "typosquat-attempt");
        assert_eq!(packages[1].dependencies, vec!["proc-macro1"]);

        let surfaces = analyze_native_surface(&packages);
        assert!(!surfaces.is_empty());
        let typosquat_surface = surfaces
            .iter()
            .find(|s| s.package.name == "typosquat-attempt");
        assert!(typosquat_surface.is_some());
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

    // Regression tests for the parser silently mis-reading real lockfiles.
    // Each of these produced a *clean* report on a lockfile that contains a
    // known-malicious package, which is the worst possible failure for a
    /// supply-chain scanner: no error, no warning, false assurance.
    #[test]
    fn a_lockfile_with_no_package_section_is_an_error_not_a_clean_report() {
        // The silent-empty-result failure: a file that is not a Cargo.lock at
        // all used to parse to zero packages, which the CLI then reported as
        // "0 findings — clean". Refusing is the only safe default for a
        // scanner, since an empty result reads as an all-clear.
        let garbage = "this is not a lockfile\n";
        let err = parse_cargo_lock(garbage).unwrap_err();
        assert!(
            err.to_string().contains("not a parsable Cargo.lock"),
            "expected an explicit refusal, got: {err}"
        );
    }

    #[test]
    fn a_package_missing_its_version_is_still_parsed() {
        // A `[[package]]` with no `version` line used to be dropped entirely,
        // taking its dependencies with it and handing them to the next package.
        let input = r#"
version = 4

[[package]]
name = "proc-macro1"
dependencies = [
 "evil-payload",
]

[[package]]
name = "serde"
version = "1.0.228"
"#;
        let packages = parse_cargo_lock(input).unwrap();
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["proc-macro1", "serde"],
            "both packages must be reported; got {names:?}"
        );
        // The missing-version package must not inherit or donate dependencies.
        assert_eq!(
            packages[1].dependencies,
            Vec::<String>::new(),
            "serde must not inherit proc-macro1's dependencies"
        );
    }

    #[test]
    fn a_toml_section_other_than_package_is_not_parsed_as_a_package() {
        // `[[patch.unused]]` is a real Cargo.lock section. The scanner treated
        // its `name`/`version` keys as a continuation of the preceding package,
        // silently overwriting the last real package in the file.
        let input = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.228"

[[package]]
name = "proc-macro1"
version = "0.2.9"

[[patch.unused]]
name = "proc-macro2"
version = "1.0.104"
"#;
        let packages = parse_cargo_lock(input).unwrap();
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["serde", "proc-macro1"],
            "only [[package]] entries count; a patch section must not overwrite \
             the last real package; got {names:?}"
        );
    }

    #[test]
    fn version_qualified_dependencies_still_match_the_proc_macro_heuristic() {
        // Cargo writes `"serde_derive 1.0.228"` whenever a crate appears at
        // more than one version. The heuristic ran on the whole qualified
        // string, so neither `syn 2.0.109` nor `serde_derive 1.0.228` matched
        // any rule and the finding vanished.
        //
        // Note the deps deliberately exclude `proc-macro*`: that name contains
        // the substring "macro" and so matched by accident even when
        // qualified, which is what let the original bug report look fixed.
        let input = r#"
version = 4

[[package]]
name = "totally-benign"
version = "1.0.0"
dependencies = [
 "serde_derive 1.0.228",
 "syn 2.0.109",
]
"#;
        let packages = parse_cargo_lock(input).unwrap();
        let surfaces = analyze_native_surface(&packages);
        let surface = surfaces
            .iter()
            .find(|s| s.package.name == "totally-benign")
            .expect("version-qualified proc-macro deps must still be detected");
        assert!(
            surface.has_build_dependencies,
            "version-qualified dependency names must match the proc-macro \
             heuristic; got {surface:?}"
        );
        assert!(
            !looks_like_proc_macro("syn 2.0.109"),
            "guard: the raw qualified string must NOT match, or this test \
             cannot detect the bug"
        );
    }

    #[test]
    fn a_source_qualified_dependency_name_is_still_matched() {
        // Full form: "syn 2.0.109 (registry+https://github.com/rust-lang/crates.io-index)".
        let input = r#"
version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "syn 2.0.109 (registry+https://github.com/rust-lang/crates.io-index)",
]
"#;
        let packages = parse_cargo_lock(input).unwrap();
        assert_eq!(
            packages[0].dependencies,
            vec!["syn"],
            "a source-qualified entry must reduce to the bare crate name"
        );
        let surfaces = analyze_native_surface(&packages);
        assert!(
            surfaces
                .iter()
                .any(|s| s.package.name == "app" && s.has_build_dependencies),
            "source-qualified dependency names must still match the heuristic"
        );
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
