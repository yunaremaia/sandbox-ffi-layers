//! Integration tests for `--format json`.
//!
//! These invoke the compiled binary rather than constructing `JsonReport`
//! in-process. The unit tests in `src/main.rs` serialize a struct they build
//! by hand, so they cannot catch a bug in how the report is *assembled* —
//! which is exactly how a hardcoded timestamp and a summary that double-counts
//! a package both reached a green CI.

use assert_cmd::Command;
use serde_json::Value;

/// Lockfile where every package is both a known-malicious typosquat and a
/// native build surface. The overlap is what breaks the summary partition.
const OVERLAPPING: &str = r#"
version = 3

[[package]]
name = "proc-macro1"
version = "0.2.9"

[[package]]
name = "proc-macro-en"
version = "1.0.1"
"#;

/// Lockfile with one malicious package, one unrelated build-script package,
/// and packages that are neither.
const MIXED: &str = r#"
version = 3

[[package]]
name = "proc-macro1"
version = "0.2.9"

[[package]]
name = "cc"
version = "1.0.99"

[[package]]
name = "serde"
version = "1.0.204"

[[package]]
name = "libc"
version = "0.2.155"
"#;

fn write_lockfile(name: &str, body: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(name), body).unwrap();
    dir
}

fn run_json(dir: &tempfile::TempDir, name: &str) -> Value {
    let out = Command::cargo_bin("sandbox-ffi")
        .unwrap()
        .args(["-c", "-l", name, "--json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    // A report with errors exits 1 by design (issue #21), so the exit code is
    // not asserted here; only the emitted document matters.
    let stdout = String::from_utf8(out.stdout).unwrap();
    let start = stdout
        .find('{')
        .unwrap_or_else(|| panic!("no JSON object in stdout: {stdout:?}"));
    serde_json::from_str(&stdout[start..]).unwrap()
}

/// A lockfile whose `proc-macro1` entry is preceded by a `[[patch.unused]]`
/// section. Before the parser was fixed, the patch section's keys overwrote the
/// preceding package, so the malicious entry vanished from the result set and
/// the tool reported a clean lockfile.
const PATCH_OVERWRITE: &str = r#"
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

/// A lockfile where the only native-build signal is a version-qualified
/// dependency. Cargo emits the qualified form whenever a crate is present at
/// more than one version, which is the normal case in a real lockfile.
const VERSION_QUALIFIED_DEP: &str = r#"
version = 4

[[package]]
name = "totally-benign"
version = "1.0.0"
dependencies = [
 "serde_derive 1.0.228",
 "syn 2.0.109",
]
"#;

#[test]
fn a_patch_section_does_not_hide_a_malicious_package() {
    let dir = write_lockfile("patch.lock", PATCH_OVERWRITE);
    let doc = run_json(&dir, "patch.lock");
    let messages: Vec<&str> = doc["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["message"].as_str().unwrap())
        .collect();

    assert!(
        messages.iter().any(|m| m.contains("proc-macro1")),
        "proc-macro1 must be reported; a [[patch.unused]] section must not \
         overwrite the preceding package. Got: {messages:?}"
    );
    assert_eq!(doc["summary"]["errors"], 1);
}

#[test]
fn a_version_qualified_dependency_still_raises_a_warning() {
    let dir = write_lockfile("qualified.lock", VERSION_QUALIFIED_DEP);
    let doc = run_json(&dir, "qualified.lock");

    assert_eq!(
        doc["summary"]["warnings"], 1,
        "a proc-macro dependency qualified by version must still be detected; \
         got {doc}"
    );
}

#[test]
fn an_unparsable_lockfile_is_an_error_not_a_clean_report() {
    let dir = write_lockfile("garbage.lock", "this is not a lockfile\n");
    let out = Command::cargo_bin("sandbox-ffi")
        .unwrap()
        .args(["-c", "-l", "garbage.lock", "--json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    // The failure mode this guards is reporting an unparsable file as "0
    // findings", which reads as an all-clear. It must be a non-zero exit with
    // a message naming the problem.
    assert!(
        !out.status.success(),
        "an unparsable lockfile must not exit successfully (would read as clean)"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("not a parsable Cargo.lock"),
        "expected an explicit refusal on stderr, got: {stderr}"
    );
}

#[test]
fn summary_is_a_partition_of_the_package_set() {
    let dir = write_lockfile("overlap.lock", OVERLAPPING);
    let doc = run_json(&dir, "overlap.lock");
    let s = &doc["summary"];

    let total = s["total"].as_u64().unwrap();
    let errors = s["errors"].as_u64().unwrap();
    let warnings = s["warnings"].as_u64().unwrap();
    let passed = s["passed"].as_u64().unwrap();

    assert_eq!(
        errors + warnings + passed,
        total,
        "summary must partition the package set; got {s}"
    );
}

#[test]
fn results_length_matches_the_summary_counts() {
    let dir = write_lockfile("overlap.lock", OVERLAPPING);
    let doc = run_json(&dir, "overlap.lock");

    let results = doc["results"].as_array().unwrap().len() as u64;
    let errors = doc["summary"]["errors"].as_u64().unwrap();
    let warnings = doc["summary"]["warnings"].as_u64().unwrap();

    assert_eq!(
        results,
        errors + warnings,
        "one result per counted finding; got {} results for {} errors + {} warnings",
        results,
        errors,
        warnings
    );
}

#[test]
fn a_malicious_package_is_not_also_reported_as_a_build_surface() {
    let dir = write_lockfile("overlap.lock", OVERLAPPING);
    let doc = run_json(&dir, "overlap.lock");

    let messages: Vec<&str> = doc["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["message"].as_str().unwrap())
        .collect();

    let surface_hits = messages
        .iter()
        .filter(|m| m.contains("proc-macro crate") || m.contains("build script dependency"))
        .count();
    assert_eq!(
        surface_hits, 0,
        "proc-macro1 is already reported as an error; it must not double-count \
         as a native-build-surface warning: {messages:?}"
    );
}

#[test]
fn an_unrelated_build_script_package_is_still_a_warning() {
    let dir = write_lockfile("mixed.lock", MIXED);
    let doc = run_json(&dir, "mixed.lock");

    assert_eq!(doc["summary"]["total"], 4);
    assert_eq!(doc["summary"]["errors"], 1);
    assert_eq!(
        doc["summary"]["warnings"], 1,
        "cc is a build-script dependency and is not malicious"
    );
    assert_eq!(doc["summary"]["passed"], 2);

    let ids: Vec<&str> = doc["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"known-malicious-package"));
    assert!(ids.contains(&"native-build-surface"));
}

#[test]
fn timestamp_is_the_wall_clock_and_not_a_constant() {
    let dir = write_lockfile("mixed.lock", MIXED);

    let first = run_json(&dir, "mixed.lock")["timestamp"]
        .as_str()
        .unwrap()
        .to_string();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let second = run_json(&dir, "mixed.lock")["timestamp"]
        .as_str()
        .unwrap()
        .to_string();

    assert_ne!(
        first, second,
        "two runs a second apart must not report an identical timestamp"
    );
    assert!(
        !first.starts_with("2026-09-18T12:00:00"),
        "timestamp must not be the old hardcoded constant; got {first}"
    );

    // Shape check: RFC 3339 in UTC, and within a few seconds of the system clock.
    // Compared with a tolerance rather than string equality: the binary stamps
    // the time it started, and `date` is read a moment later, so an exact
    // match would fail whenever the run straddles a second boundary.
    assert!(
        first.len() == 20 && first.ends_with('Z') && first.contains('T'),
        "expected an RFC 3339 UTC timestamp like 2026-10-01T12:00:00Z, got {first}"
    );

    let now = std::process::Command::new("date")
        .arg("-u")
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output()
        .unwrap();
    let expected = String::from_utf8(now.stdout).unwrap().trim().to_string();
    assert!(
        first >= expected || within_a_few_seconds(&first, &expected),
        "reported timestamp {first} should be within a few seconds of the \
         system clock {expected}"
    );
}

/// True when `a` and `b` are the same instant within a small tolerance,
/// tolerating the second boundary crossing between two reads.
fn within_a_few_seconds(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Option<i64> {
        let d = chrono_like_seconds(s)?;
        Some(d)
    };
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => (x - y).abs() <= 5,
        _ => false,
    }
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` into a comparable second count.
fn chrono_like_seconds(s: &str) -> Option<i64> {
    let (date, time) = s.split_once('T')?;
    let (y, m, d) = (
        date.get(0..4)?.parse::<i64>().ok()?,
        date.get(5..7)?.parse::<i64>().ok()?,
        date.get(8..10)?.parse::<i64>().ok()?,
    );
    let (hh, mm, ss) = (
        time.get(0..2)?.parse::<i64>().ok()?,
        time.get(3..5)?.parse::<i64>().ok()?,
        time.get(6..8)?.parse::<i64>().ok()?,
    );
    // Days from civil (inverse of the algorithm used in main.rs), sufficient
    // for a tolerance comparison.
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = y_adj.div_euclid(400);
    let yoe = y_adj - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

#[test]
fn every_run_reports_a_distinct_timestamp_over_time() {
    let dir = write_lockfile("mixed.lock", MIXED);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..3 {
        let ts = run_json(&dir, "mixed.lock")["timestamp"]
            .as_str()
            .unwrap()
            .to_string();
        seen.insert(ts);
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }
    assert_eq!(
        seen.len(),
        3,
        "each invocation should stamp its own time; saw {seen:?}"
    );
}
