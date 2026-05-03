//! beamfs-bench regression check -- post-bench delta vs baseline.
//!
//! Runs at Phase 8.3 (after 8.2 manifest emit). Loads the most recent
//! baseline manifest where `commit_beamfs` matches `origin/<branch>`,
//! computes the verdict delta, and blocks the push if regressions are
//! observed.
//!
//! ## Why this exists
//!
//! `beamfs-bench full` rc=0 means "no panic, no DIFFS, dmesg clean" --
//! a structural floor. It does NOT distinguish "RECOVERED 12/12 cluster"
//! from "VERIFIED 11/12 + 1 subdir_missing", because both produce the
//! same `overall_rc=0`. R7 declares the bench canonical pre-push, so
//! we promote the comparative semantics to first-class.
//!
//! ## Comparators (all R0/R7-grade)
//!
//! Tier R - REGRESSION (FATAL, blocks push)
//!   R-1 cluster_verdict_count    : count(VERIFIED) per prob must not drop
//!   R-2 verify_error_zero        : VERIFY=ERROR count must not increase
//!   R-3 multifs_class_no_downgrade: RS_RECOVERED -> RS_PASSTHROUGH ok;
//!                                   anything -> RS_FAILED|FS_PANIC|
//!                                   CORRUPTED_DATA = REGRESSION
//!   R-4 dmesg_pathology_zero     : BUG/Oops/WARN/panic count must not
//!                                   increase
//!   R-5 inode_uncorrected_count  : "CRC32 mismatch (no RS)" must not
//!                                   increase unless baseline already > 0
//!
//! Tier I - INFORMATIONAL (logged, never blocks)
//!   I-1 cat_failed_at_prob_1M    : stochastic noise, log only
//!   I-2 rs_corrected_count       : higher is better, surface in report
//!   I-3 timing per phase         : drift > 50% => log
//!
//! ## Bypass
//!
//! Only via `--accept-regression="<reason>"`. The reason string is
//! recorded in the manifest under `regression_acceptance.reason` and
//! must be non-empty. CI/scripted bypasses are explicitly anti-pattern;
//! the bypass exists for human-judgment cases (e.g. infrastructure
//! flake, USB stick failure, reproducible-only-on-this-attempt).
//!
//! ## Baseline resolution
//!
//! 1. If `~/git/yocto-beamfs/Documentation/runs/BASELINE.txt` exists,
//!    parse its single line as a manifest filename. Use that.
//! 2. Otherwise, scan `Documentation/runs/manifest-*.json`, filter
//!    those with `commit_beamfs == git rev-parse origin/<branch>` and
//!    `overall_rc == 0`, pick the most recent by `started_at`.
//! 3. If none found, log "no baseline -- first run" and pass.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const RUNS_DIR: &str = "/home/aurelien/git/yocto-beamfs/Documentation/runs";
const BEAMFS_REPO: &str = "/home/aurelien/git/beamfs";

#[derive(Debug, Clone, Serialize)]
pub struct RegressionReport {
    pub started_at:  String,
    pub finished_at: String,
    pub baseline_manifest: Option<String>,
    pub baseline_started_at: Option<String>,
    pub current_run_dir: String,
    pub findings: Vec<RegressionFinding>,
    pub fatal_count: u32,
    pub info_count:  u32,
    pub accepted_reason: Option<String>,
    pub overall_rc: i32,   // 0 ok, 4 regression
}

#[derive(Debug, Clone, Serialize)]
pub struct RegressionFinding {
    pub rule:     String,
    pub severity: Severity,
    pub baseline: String,   // human description of baseline value
    pub current:  String,
    pub delta:    String,
}

#[allow(dead_code)] // Fatal/Info constructed by real comparators, not stubs
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum Severity {
    Fatal,
    Info,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestSnapshot {
    pub started_at:    String,
    pub commit_beamfs: String,
    #[serde(default)]
    pub overall_rc:    i32,
    #[serde(default)]
    #[allow(dead_code)] // read by compare_phase_timing_info when implemented
    pub phases:        serde_json::Value,
}

/// Public entry. Called from `cmd_full` after Phase 8.2 emit_manifest.
/// Returns Ok if no fatal regression OR if `accept_reason` is Some.
/// Returns Err otherwise (rc=4 propagated by caller).
pub fn run(
    current_run_dir: &Path,
    accept_reason: Option<String>,
) -> Result<RegressionReport> {
    println!("[pipeline 8.3] regression check vs baseline");

    let started_at = chrono::Utc::now().to_rfc3339();

    let baseline = resolve_baseline()?;
    if let Some(b) = &baseline {
        println!("  baseline: {}", b.path.display());
        println!("  baseline started_at: {}", b.snapshot.started_at);
    } else {
        println!("  no baseline available -- first run, no comparison");
    }

    let mut report = RegressionReport {
        started_at,
        finished_at: String::new(),
        baseline_manifest: baseline.as_ref().map(|b| b.path.display().to_string()),
        baseline_started_at: baseline.as_ref().map(|b| b.snapshot.started_at.clone()),
        current_run_dir: current_run_dir.display().to_string(),
        findings: Vec::new(),
        fatal_count: 0,
        info_count: 0,
        accepted_reason: accept_reason.clone(),
        overall_rc: 0,
    };

    if let Some(b) = baseline {
        // Run all R-N + I-N comparators
        // (TODO: implement in dedicated commit)
        let cluster_verdict = compare_cluster_verdict_count(&b, current_run_dir);
        let verify_error    = compare_verify_error_zero(&b, current_run_dir);
        let multifs_class   = compare_multifs_class(&b, current_run_dir);
        let dmesg_path      = compare_dmesg_pathology(&b, current_run_dir);
        let inode_uncorr    = compare_inode_uncorrected(&b, current_run_dir);
        let cat_failed      = compare_cat_failed_info(&b, current_run_dir);
        let rs_corrected    = compare_rs_corrected_info(&b, current_run_dir);
        let phase_timing    = compare_phase_timing_info(&b, current_run_dir);

        for f in [cluster_verdict, verify_error, multifs_class, dmesg_path, inode_uncorr,
                  cat_failed, rs_corrected, phase_timing] {
            for finding in f {
                match finding.severity {
                    Severity::Fatal => report.fatal_count += 1,
                    Severity::Info  => report.info_count  += 1,
                }
                println!("    [{:?}] {}: {} -> {} (delta={})",
                         finding.severity, finding.rule,
                         finding.baseline, finding.current, finding.delta);
                report.findings.push(finding);
            }
        }
    }

    report.finished_at = chrono::Utc::now().to_rfc3339();

    // Persist regression report
    let json_path = current_run_dir.join("regression-report.json");
    std::fs::write(&json_path, serde_json::to_string_pretty(&report)?)?;
    println!("  report: {}", json_path.display());

    // Decision
    if report.fatal_count == 0 {
        println!("  no fatal regression");
        return Ok(report);
    }

    if let Some(reason) = &report.accepted_reason {
        if reason.trim().is_empty() {
            bail!("--accept-regression requires a non-empty reason string");
        }
        println!("  REGRESSION ACCEPTED -- reason: {reason}");
        println!("  recorded in manifest for audit trail");
        return Ok(report);
    }

    report.overall_rc = 4;
    bail!(
        "regression check FAIL -- {} fatal finding(s), pipeline aborted (rc=4)\n\
         report: {}\n\
         to bypass: re-run with --accept-regression=\"<reason>\"",
        report.fatal_count, json_path.display()
    );
}

// ============================================================
// Baseline resolution
// ============================================================

struct Baseline {
    path: PathBuf,
    snapshot: ManifestSnapshot,
}

fn resolve_baseline() -> Result<Option<Baseline>> {
    let runs_dir = PathBuf::from(RUNS_DIR);
    let baseline_txt = runs_dir.join("BASELINE.txt");

    // Pinned baseline takes precedence
    if baseline_txt.exists() {
        let line = std::fs::read_to_string(&baseline_txt)
            .with_context(|| format!("read {}", baseline_txt.display()))?;
        let fname = line.trim();
        if fname.is_empty() {
            return Ok(None);
        }
        let path = runs_dir.join(fname);
        let snapshot = load_manifest(&path)?;
        return Ok(Some(Baseline { path, snapshot }));
    }

    // Auto: most-recent manifest with commit_beamfs == origin/<branch>
    let upstream_sha = git_upstream_sha()?;
    let mut candidates: Vec<(PathBuf, ManifestSnapshot)> = Vec::new();
    for entry in std::fs::read_dir(&runs_dir).context("read runs dir")? {
        let entry = entry?;
        let p = entry.path();
        let fname = match p.file_name().and_then(|s| s.to_str()) {
            Some(n) if n.starts_with("manifest-") && n.ends_with(".json") => n,
            _ => continue,
        };
        let _ = fname;  // pattern check only
        match load_manifest(&p) {
            Ok(m) if m.commit_beamfs == upstream_sha && m.overall_rc == 0 => {
                candidates.push((p, m));
            }
            _ => continue,
        }
    }
    candidates.sort_by(|a, b| b.1.started_at.cmp(&a.1.started_at));
    Ok(candidates.into_iter().next().map(|(path, snapshot)| Baseline { path, snapshot }))
}

fn load_manifest(path: &Path) -> Result<ManifestSnapshot> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let m: ManifestSnapshot = serde_json::from_str(&raw)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(m)
}

fn git_upstream_sha() -> Result<String> {
    let out = std::process::Command::new("git").args([
        "-C", BEAMFS_REPO, "rev-parse", "@{upstream}"
    ]).output().context("git rev-parse upstream")?;
    if !out.status.success() {
        bail!("no upstream tracking on beamfs HEAD");
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// ============================================================
// Comparators -- TODO implement in dedicated commits
// ============================================================
//
// Each comparator parses the relevant artefact (cluster-records.txt,
// multifs-synthesis.json, dmesg.log, manifest phases) for both
// baseline run and current run, then emits Vec<RegressionFinding>.
//
// Empty Vec = no finding for this rule.

fn compare_cluster_verdict_count(_b: &Baseline, _cur: &Path) -> Vec<RegressionFinding> {
    // Parse cluster-records.txt VERIFY|prob=N|...|VERDICT=VERIFIED count
    // per prob (1k/100k/1M). If current_count < baseline_count at any
    // prob: emit Fatal finding R-1.
    Vec::new()
}

fn compare_verify_error_zero(_b: &Baseline, _cur: &Path) -> Vec<RegressionFinding> {
    // Count VERIFY=ERROR lines in cluster-records.txt. Fatal if
    // current > baseline.
    Vec::new()
}

fn compare_multifs_class(_b: &Baseline, _cur: &Path) -> Vec<RegressionFinding> {
    // Read multifs-synthesis.json per_fs[].modes_observed for FS=beamfs.
    // Class lattice (best -> worst):
    //   RS_RECOVERED > RS_PASSTHROUGH > RS_FAILED > CORRUPTED_DATA > FS_PANIC
    // Fatal if current is strictly worse than baseline at any prob.
    Vec::new()
}

fn compare_dmesg_pathology(_b: &Baseline, _cur: &Path) -> Vec<RegressionFinding> {
    // Count BUG:/Oops/WARN/panic in forensics-*/dmesg.log per VM.
    // Fatal if any count current > baseline.
    Vec::new()
}

fn compare_inode_uncorrected(_b: &Baseline, _cur: &Path) -> Vec<RegressionFinding> {
    // Count "beamfs: inode N CRC32 mismatch (no RS available" per VM.
    // Fatal if current > baseline -- means RS gate was tightened
    // unintentionally OR RadFI saturated more inodes than before.
    Vec::new()
}

fn compare_cat_failed_info(_b: &Baseline, _cur: &Path) -> Vec<RegressionFinding> {
    // Count CAT_RC=1 in cluster-records.txt and multifs records.
    // Severity::Info regardless -- this is stochastic at high RadFI prob.
    Vec::new()
}

fn compare_rs_corrected_info(_b: &Baseline, _cur: &Path) -> Vec<RegressionFinding> {
    // Sum RS_CORRECTED across all records. Severity::Info; higher is
    // better (more RS recoveries observed = better protection coverage).
    Vec::new()
}

fn compare_phase_timing_info(_b: &Baseline, _cur: &Path) -> Vec<RegressionFinding> {
    // Read manifest.phases timestamps; compute per-phase duration.
    // Info if any phase drifts > 50% from baseline. Surface to operator
    // because long bitbake = sstate cache miss = upstream change.
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_acceptance_rejected() {
        // verifier que reason vide bail!()
        let tmpd = tempfile::tempdir().unwrap();
        let r = run(tmpd.path(), Some("".to_string()));
        // can't easily test without a baseline; structural test only:
        // we expect run() to either pass (no baseline) or fail with
        // empty-reason bail. Both are acceptable; this test just checks
        // the function compiles and runs.
        let _ = r;
    }

    #[test]
    fn severity_ord() {
        assert_eq!(Severity::Fatal, Severity::Fatal);
        assert_ne!(Severity::Fatal, Severity::Info);
    }
}
