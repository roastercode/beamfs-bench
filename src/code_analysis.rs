//! beamfs-bench code analysis -- MIL/kernel.org-grade pre-bench gate.
//!
//! Runs at Phase 0.0bis (after Phase 0.0 isolation, before Phase 0.1
//! clean-trees). Performs static analysis, security scanning, and
//! kernel coding standard validation before the bench burns 8+ minutes
//! on a build that will never be merged.
//!
//! ## Stratification (R8 + DoD Phase 7 mainline-scope)
//!
//! Three tiers, ordered by reviewer authority:
//!
//! ### Tier 1 - FATAL (blocks pipeline)
//! kernel.org submission gate. checkpatch, sparse, smatch, coccinelle,
//! clang -Werror, gcc -fanalyzer, GPG verify, gitleaks, cargo audit
//! (HIGH+ severity), cargo clippy -D warnings.
//!
//! ### Tier 2 - WARN (logged, non-blocking)
//! cppcheck --inconclusive, flawfinder, semgrep, cargo geiger,
//! kernel-doc, MISRA non-mandatory.
//!
//! ### Tier 3 - REPORT (audit trail JSON only, full mode)
//! Frama-C WP/value analysis, scan-build (clang static analyzer),
//! lcov coverage. Heavy tools, run on `--full` flag only.
//!
//! ## Scope
//!
//! Tier 1 runs incrementally on `git diff HEAD..origin/<branch>` to
//! keep latency <30s in normal R19 cycle. Tier 2-3 run full-module on
//! `--full-code-analysis` flag, weekly cadence.
//!
//! Output goes to `<run_dir>/code-analysis/` with one log per tool +
//! `code-analysis-summary.json` for manifest integration.
//!
//! ## Failure semantics
//!
//! Any Tier 1 violation aborts the pipeline with rc=3 (distinct from
//! rc=2 runtime failure) and tarballs `<run_dir>/code-analysis/` to
//! `/tmp/code-analysis-<TS>.tar.gz` for offline review.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

const BEAMFS_REPO: &str = "/home/aurelien/git/beamfs";
#[allow(dead_code)] // referenced by run_lockstep_r9_sha256 when implemented
const YOCTO_REPO:  &str = "/home/aurelien/git/yocto-beamfs";
const BENCH_REPO:  &str = "/home/aurelien/git/beamfs-bench";

/// Tool execution outcome. `Skip` means the tool is unavailable on the
/// host (logged but not fatal even at Tier 1, because partial coverage
/// is better than no run; the Tier 1 gate fires only on actual
/// findings, not on missing binaries).
#[allow(dead_code)] // Pass/Findings/Error constructed by real tool wrappers, not stubs
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum ToolOutcome {
    Pass,
    Findings { count: u32, severity: String, log_path: String },
    Skip { reason: String },
    Error { message: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolReport {
    pub name: String,
    pub tier: u8,
    pub outcome: ToolOutcome,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeAnalysisReport {
    pub started_at:  String,
    pub finished_at: String,
    pub mode: AnalysisMode,
    pub diff_base: String,         // e.g. "origin/diag/double-free-block"
    pub files_analysed: Vec<String>,
    pub tier1: Vec<ToolReport>,
    pub tier2: Vec<ToolReport>,
    pub tier3: Vec<ToolReport>,
    pub tier1_pass: bool,
    pub tier2_warnings: u32,
    pub overall_rc: i32,           // 0 ok, 3 tier1 fail
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum AnalysisMode {
    Incremental,    // diff HEAD..origin (default for R19 cycle)
    Full,           // full module re-analysis (--full-code-analysis)
}

/// Public entry. Called from `cmd_full` between 0.0_isolation_r21 and
/// 0.1_clean_trees. Errors propagate to bail!() in main, which emits
/// rc=3 and tarballs the partial report.
pub fn run(mode: AnalysisMode, run_dir: &Path) -> Result<CodeAnalysisReport> {
    println!("[pipeline 0.0bis] code analysis (tier 1/2/3, mode={mode:?})");

    let analysis_dir = run_dir.join("code-analysis");
    std::fs::create_dir_all(&analysis_dir)
        .with_context(|| format!("create {}", analysis_dir.display()))?;

    let started_at = chrono::Utc::now().to_rfc3339();
    let diff_base = git_diff_base()?;
    let files = files_in_scope(mode, &diff_base)?;

    println!("  mode: {mode:?}");
    println!("  diff base: {diff_base}");
    println!("  files in scope: {}", files.len());

    let mut report = CodeAnalysisReport {
        started_at,
        finished_at: String::new(),
        mode,
        diff_base,
        files_analysed: files.iter().map(|p| p.display().to_string()).collect(),
        tier1: Vec::new(),
        tier2: Vec::new(),
        tier3: Vec::new(),
        tier1_pass: true,
        tier2_warnings: 0,
        overall_rc: 0,
    };

    // ============== TIER 1 (FATAL) ==============
    println!("\n  [tier 1 - FATAL]");
    report.tier1.push(run_checkpatch_strict(&files, &analysis_dir));
    report.tier1.push(run_sparse(&analysis_dir));
    report.tier1.push(run_smatch(&analysis_dir));
    report.tier1.push(run_coccinelle(&analysis_dir));
    report.tier1.push(run_clang_werror(&files, &analysis_dir));
    report.tier1.push(run_gcc_fanalyzer(&files, &analysis_dir));
    report.tier1.push(run_gpg_verify_commits(&analysis_dir));
    report.tier1.push(run_gitleaks(&analysis_dir));
    report.tier1.push(run_cargo_audit_high(&analysis_dir));
    report.tier1.push(run_cargo_clippy_pedantic(&analysis_dir));
    report.tier1.push(run_kernel_doc_validate(&files, &analysis_dir));
    report.tier1.push(run_naming_r17_check(&analysis_dir));
    report.tier1.push(run_emdash_r16_check(&analysis_dir));
    report.tier1.push(run_lockstep_r9_sha256(&analysis_dir));

    for r in &report.tier1 {
        log_tool(r);
        if matches!(&r.outcome, ToolOutcome::Findings { .. } | ToolOutcome::Error { .. }) {
            report.tier1_pass = false;
        }
    }

    // ============== TIER 2 (WARN) ==============
    println!("\n  [tier 2 - WARN]");
    report.tier2.push(run_cppcheck_inconclusive(&files, &analysis_dir));
    report.tier2.push(run_flawfinder(&files, &analysis_dir));
    report.tier2.push(run_semgrep(&files, &analysis_dir));
    report.tier2.push(run_cargo_geiger(&analysis_dir));
    report.tier2.push(run_misra_advisory(&files, &analysis_dir));

    for r in &report.tier2 {
        log_tool(r);
        if matches!(&r.outcome, ToolOutcome::Findings { .. }) {
            report.tier2_warnings += 1;
        }
    }

    // ============== TIER 3 (REPORT, full mode only) ==============
    if mode == AnalysisMode::Full {
        println!("\n  [tier 3 - REPORT]");
        report.tier3.push(run_frama_c(&files, &analysis_dir));
        report.tier3.push(run_scan_build(&analysis_dir));
        report.tier3.push(run_lcov(&analysis_dir));
        for r in &report.tier3 {
            log_tool(r);
        }
    } else {
        println!("\n  [tier 3 skipped -- run with --full-code-analysis to enable]");
    }

    report.finished_at = chrono::Utc::now().to_rfc3339();

    // Write summary JSON
    let json_path = analysis_dir.join("code-analysis-summary.json");
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&json_path, &json)?;
    println!("\n  summary: {}", json_path.display());

    if !report.tier1_pass {
        report.overall_rc = 3;
        let dump = dump_to_tmp_tarball(&analysis_dir)?;
        bail!(
            "code analysis Tier 1 FAIL -- pipeline aborted (rc=3)\n\
             findings dumped to {}\n\
             review and fix before retrying R19",
            dump.display()
        );
    }
    if report.tier2_warnings > 0 {
        println!("\n  WARNING: {} tier-2 findings -- non-blocking, review before push",
                 report.tier2_warnings);
    }

    Ok(report)
}

// ============================================================
// Helpers (git, file scope, logging, tarball)
// ============================================================

fn git_diff_base() -> Result<String> {
    // upstream of current branch
    let out = Command::new("git").args([
        "-C", BEAMFS_REPO, "rev-parse", "--abbrev-ref", "@{upstream}"
    ]).output().context("git rev-parse upstream")?;
    if !out.status.success() {
        bail!("no upstream tracking branch on beamfs HEAD");
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn files_in_scope(mode: AnalysisMode, diff_base: &str) -> Result<Vec<PathBuf>> {
    match mode {
        AnalysisMode::Incremental => {
            let out = Command::new("git").args([
                "-C", BEAMFS_REPO, "diff", "--name-only", &format!("{diff_base}..HEAD")
            ]).output().context("git diff name-only")?;
            let raw = String::from_utf8_lossy(&out.stdout);
            Ok(raw.lines()
                .filter(|f| f.ends_with(".c") || f.ends_with(".h") || f.ends_with(".rs"))
                .map(|f| PathBuf::from(BEAMFS_REPO).join(f))
                .filter(|p| p.exists())
                .collect())
        }
        AnalysisMode::Full => {
            let mut v = Vec::new();
            for repo in &[BEAMFS_REPO, BENCH_REPO] {
                for entry in walkdir::WalkDir::new(repo).max_depth(4) {
                    let entry = entry?;
                    if let Some(ext) = entry.path().extension() {
                        if matches!(ext.to_str(), Some("c") | Some("h") | Some("rs")) {
                            v.push(entry.path().to_path_buf());
                        }
                    }
                }
            }
            Ok(v)
        }
    }
}

fn log_tool(r: &ToolReport) {
    let tag = match &r.outcome {
        ToolOutcome::Pass => "PASS",
        ToolOutcome::Findings { .. } => "FINDINGS",
        ToolOutcome::Skip { .. } => "SKIP",
        ToolOutcome::Error { .. } => "ERROR",
    };
    println!("    [{tag:>8}] {} ({} ms)", r.name, r.duration_ms);
}

fn dump_to_tmp_tarball(analysis_dir: &Path) -> Result<PathBuf> {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let dest = PathBuf::from(format!("/tmp/code-analysis-{ts}.tar.gz"));
    let parent = analysis_dir.parent().unwrap_or_else(|| Path::new("."));
    let dirname = analysis_dir.file_name().unwrap();
    let st = Command::new("tar").args([
        "-czf", &dest.to_string_lossy(), "-C", &parent.to_string_lossy(),
        &dirname.to_string_lossy(),
    ]).status().context("tar dump")?;
    if !st.success() {
        bail!("tar dump failed");
    }
    Ok(dest)
}

// ============================================================
// TIER 1 -- FATAL tool wrappers (TODO: implement bodies)
// ============================================================

// Each wrapper returns a `ToolReport` with timing. The body of each
// `run_*` is a stub that calls the tool, parses its output, and
// classifies the result. None of these is implemented yet -- this
// scaffolding is the contract; the bodies follow in dedicated commits
// once tool availability on spartian-1 is verified.

fn run_checkpatch_strict(_files: &[PathBuf], _out: &Path) -> ToolReport {
    // scripts/checkpatch.pl --strict --no-tree --terse on each .c/.h
    // diff. Hard-fail on any "ERROR:" line.
    todo_tool("checkpatch_strict", 1)
}

fn run_sparse(_out: &Path) -> ToolReport {
    // make C=2 CHECK="sparse -Wsparse-all -Wbitwise" M=$BEAMFS_REPO
    // Requires sparse from kernel.org git or distro pkg.
    todo_tool("sparse", 1)
}

fn run_smatch(_out: &Path) -> ToolReport {
    // make CHECK=smatch C=2 M=$BEAMFS_REPO
    // Dan Carpenter's static analyzer; fsdevel-recommended.
    todo_tool("smatch", 1)
}

fn run_coccinelle(_out: &Path) -> ToolReport {
    // make coccicheck COCCI=scripts/coccinelle/api/ M=$BEAMFS_REPO
    // Run all kernel-shipped semantic patches against fs/beamfs.
    todo_tool("coccinelle", 1)
}

fn run_clang_werror(_files: &[PathBuf], _out: &Path) -> ToolReport {
    // clang -Wall -Wextra -Wsign-compare -Wshadow -Werror -fsyntax-only
    // Pre-mainline diagnostic surface beyond gcc default.
    todo_tool("clang_werror", 1)
}

fn run_gcc_fanalyzer(_files: &[PathBuf], _out: &Path) -> ToolReport {
    // gcc -fanalyzer -Wanalyzer-* -fsyntax-only
    // Path-sensitive bug detection (taint, double-free, NPD, leak).
    todo_tool("gcc_fanalyzer", 1)
}

fn run_gpg_verify_commits(_out: &Path) -> ToolReport {
    // for each commit in HEAD..origin: git verify-commit
    // R29 GPG signing enforcement.
    todo_tool("gpg_verify", 1)
}

fn run_gitleaks(_out: &Path) -> ToolReport {
    // gitleaks detect --source=$BEAMFS_REPO --no-banner
    // R35 secrets-never-in-chat companion: secrets-never-in-repo.
    todo_tool("gitleaks", 1)
}

fn run_cargo_audit_high(_out: &Path) -> ToolReport {
    // cd beamfs-bench && cargo audit --json
    // Fail on HIGH or CRITICAL RustSec advisory.
    todo_tool("cargo_audit_high", 1)
}

fn run_cargo_clippy_pedantic(_out: &Path) -> ToolReport {
    // cargo clippy --all-targets --all-features -- -D warnings
    //   -D clippy::pedantic -D clippy::nursery -A clippy::module_name_repetitions
    todo_tool("cargo_clippy_pedantic", 1)
}

fn run_kernel_doc_validate(_files: &[PathBuf], _out: &Path) -> ToolReport {
    // scripts/kernel-doc -none $files
    // Doc comment syntax per Documentation/doc-guide/kernel-doc.rst
    todo_tool("kernel_doc", 1)
}

fn run_naming_r17_check(_out: &Path) -> ToolReport {
    // grep -E "Beam-Resilient|Beam Electromagnetic|FTRFS" .c .h .md .bb
    // Excludes context/archive/, papers/, academic citations whitelist.
    todo_tool("naming_r17", 1)
}

fn run_emdash_r16_check(_out: &Path) -> ToolReport {
    // grep -P "\xE2\x80\x94" on diff (U+2014 em-dash forbidden, R16).
    todo_tool("emdash_r16", 1)
}

fn run_lockstep_r9_sha256(_out: &Path) -> ToolReport {
    // sha256sum byte-identical check on the 11 lockstep .c/.h between
    // beamfs/ and yocto-beamfs/recipes-kernel/beamfs/files/beamfs-0.1.0/.
    // Duplicates pipeline 0.2 by design: code-analysis is self-contained
    // and runs BEFORE 0.1, so it cannot rely on later phases.
    todo_tool("lockstep_r9", 1)
}

// ============================================================
// TIER 2 -- WARN tool wrappers (TODO: implement bodies)
// ============================================================

fn run_cppcheck_inconclusive(_files: &[PathBuf], _out: &Path) -> ToolReport {
    // cppcheck --enable=all --inconclusive --std=c11 --xml-version=2
    todo_tool("cppcheck", 2)
}

fn run_flawfinder(_files: &[PathBuf], _out: &Path) -> ToolReport {
    // flawfinder --csv --minlevel=2 $files
    todo_tool("flawfinder", 2)
}

fn run_semgrep(_files: &[PathBuf], _out: &Path) -> ToolReport {
    // semgrep --config=p/c --config=p/security-audit --json
    todo_tool("semgrep", 2)
}

fn run_cargo_geiger(_out: &Path) -> ToolReport {
    // cargo geiger --output-format Json
    // unsafe-block census; informative for fsdevel reviewers.
    todo_tool("cargo_geiger", 2)
}

fn run_misra_advisory(_files: &[PathBuf], _out: &Path) -> ToolReport {
    // cppcheck --addon=misra --suppress=misraNN.NN $files
    // MISRA C:2012 advisory rules; mandatory rules are Tier 1 via cppcheck.
    todo_tool("misra_advisory", 2)
}

// ============================================================
// TIER 3 -- REPORT tool wrappers (full mode only)
// ============================================================

fn run_frama_c(_files: &[PathBuf], _out: &Path) -> ToolReport {
    // frama-c -wp -val $files; targeted at edac.c, alloc.c, super.c
    // critical paths. Heavy: ~minutes per file.
    todo_tool("frama_c", 3)
}

fn run_scan_build(_out: &Path) -> ToolReport {
    // scan-build --status-bugs make M=$BEAMFS_REPO
    // Clang static analyzer full-module run.
    todo_tool("scan_build", 3)
}

fn run_lcov(_out: &Path) -> ToolReport {
    // gcov + lcov genhtml; gated on selftests presence.
    todo_tool("lcov", 3)
}

// ============================================================
// Stub helper -- explicit unimplemented signal during scaffolding.
// ============================================================
fn todo_tool(name: &str, tier: u8) -> ToolReport {
    ToolReport {
        name: name.to_string(),
        tier,
        outcome: ToolOutcome::Skip {
            reason: "TODO: implement in dedicated commit (see code-analysis-tools.md)".to_string()
        },
        duration_ms: 0,
    }
}

// ============================================================
// Tests
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_classification_constants() {
        assert_eq!(todo_tool("x", 1).tier, 1);
        assert_eq!(todo_tool("x", 2).tier, 2);
        assert_eq!(todo_tool("x", 3).tier, 3);
    }

    #[test]
    fn analysis_mode_serializes() {
        let s = serde_json::to_string(&AnalysisMode::Incremental).unwrap();
        assert_eq!(s, "\"Incremental\"");
        let s = serde_json::to_string(&AnalysisMode::Full).unwrap();
        assert_eq!(s, "\"Full\"");
    }
}
