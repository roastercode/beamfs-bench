//! beamfs-bench code analysis -- MIL/kernel.org-grade pre-bench gate.
//!
//! Runs at Phase 0.0bis (after Phase 0.0 isolation, before Phase 0.1
//! clean-trees). Performs static analysis, security scanning, and
//! kernel coding standard validation before the bench burns 8+ minutes
//! on a build that will never be merged.
//!
//! ## Stratification (R8 + `DoD` Phase 7 mainline-scope)
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
use std::fmt::Write;

// R16 forbidden Unicode punctuation: em-dash, en-dash, right arrow,
// curly single/double quotes. Named emdash_r16 for baseline continuity.
const FORBIDDEN_R16: &[(char, &str)] = &[
    ('\u{2014}', "em-dash U+2014"),
    ('\u{2013}', "en-dash U+2013"),
    ('\u{2192}', "arrow U+2192"),
    ('\u{2018}', "left-single-quote U+2018"),
    ('\u{2019}', "right-single-quote U+2019"),
    ('\u{201C}', "left-double-quote U+201C"),
    ('\u{201D}', "right-double-quote U+201D"),
];


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

/// Public entry. Called from `cmd_full` between `0.0_isolation_r21` and
/// `0.1_clean_trees`. Errors propagate to bail!() in main, which emits
/// rc=3 and tarballs the partial report.
pub fn run(mode: AnalysisMode, run_dir: &Path) -> Result<CodeAnalysisReport> {
    println!("[pipeline 0.0bis] code analysis (tier 1/2/3, mode={mode:?})");

    let analysis_dir = run_dir.join("code-analysis");
    std::fs::create_dir_all(&analysis_dir)
        .with_context(|| format!("create {}", analysis_dir.display()))?;

    let started_at = chrono::Utc::now().to_rfc3339();
    let diff_base = git_diff_base()?;
    let mut files = files_in_scope(mode, &diff_base)?;
    let mut effective_mode = mode;

    // M1.Y : if Incremental returns no files (HEAD == upstream tip), fall
    // back to Full so the Tier 1 gate actually runs. Without this, every
    // R19 from a clean tree skips all 14 tools and emits a misleading
    // "all SKIP" report. Surface the fallback explicitly so the operator
    // knows the analysis ran on the full tree.
    if matches!(mode, AnalysisMode::Incremental) && files.is_empty() {
        eprintln!("[code-analysis] Incremental scope is empty (HEAD == upstream),");
        eprintln!("[code-analysis] falling back to Full mode for Tier 1 gate.");
        effective_mode = AnalysisMode::Full;
        files = files_in_scope(effective_mode, &diff_base)?;
    }

    println!("  mode: {effective_mode:?}");
    println!("  diff base: {diff_base}");
    println!("  files in scope: {}", files.len());

    let mut report = CodeAnalysisReport {
        started_at,
        finished_at: String::new(),
        mode: effective_mode,
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
    if effective_mode == AnalysisMode::Full {
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
        "-C", crate::lab::beamfs_repo(), "rev-parse", "--abbrev-ref", "@{upstream}"
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
                "-C", crate::lab::beamfs_repo(), "diff", "--name-only", &format!("{diff_base}..HEAD")
            ]).output().context("git diff name-only")?;
            let raw = String::from_utf8_lossy(&out.stdout);
            Ok(raw.lines()
                .filter(|f| f.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("c")) || f.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("h")) || f.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("rs")))
                .map(|f| PathBuf::from(crate::lab::beamfs_repo()).join(f))
                .filter(|p| p.exists())
                .collect())
        }
        AnalysisMode::Full => {
            let mut v = Vec::new();
            for repo in &[crate::lab::beamfs_repo(), crate::lab::bench_repo()] {
                for entry in walkdir::WalkDir::new(repo).max_depth(4) {
                    let entry = entry?;
                    if let Some(ext) = entry.path().extension() {
                        if matches!(ext.to_str(), Some("c" | "h" | "rs")) {
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

fn run_checkpatch_strict(files: &[PathBuf], out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let Some(checkpatch) = locate_checkpatch() else {
        return ToolReport {
            name: "checkpatch_strict".to_string(),
            tier: 1,
            outcome: ToolOutcome::Skip {
                reason: "checkpatch.pl not found in /usr/src/linux*/scripts/".to_string()
            },
            duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    };
    let log_path = out.join("checkpatch.log");
    let mut errors: u32 = 0;
    let mut log_buf = String::new();
    for f in files {
        let f_str = f.display().to_string();
        if !(f_str.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("c")) || f_str.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("h"))) { continue; }
        if !f_str.contains("/git/beamfs/") { continue; }
        if f_str.contains("/recipes-kernel/") { continue; }
        let Ok(res) = Command::new(&checkpatch)
            .args(["--strict", "--no-tree", "--terse", "--file", &f_str])
            .output()
        else {
            continue;
        };
        let s = String::from_utf8_lossy(&res.stdout);
        writeln!(log_buf, "=== {f_str} ===").unwrap();
        log_buf.push_str(&s);
        log_buf.push('\n');
        for line in s.lines() {
            if line.contains("ERROR:") { errors += 1; }
        }
    }
    let _ = std::fs::write(&log_path, &log_buf);
    let outcome = if errors == 0 {
        ToolOutcome::Pass
    } else {
        ToolOutcome::Findings {
            count: errors,
            severity: "error".to_string(),
            log_path: log_path.display().to_string(),
        }
    };
    ToolReport {
        name: "checkpatch_strict".to_string(),
        tier: 1,
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn locate_checkpatch() -> Option<PathBuf> {
    let canonical = PathBuf::from("/usr/src/linux/scripts/checkpatch.pl");
    if canonical.is_file() { return Some(canonical); }
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/usr/src") {
        for e in entries.flatten() {
            let p = e.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with("linux-") { continue; }
            let cp = p.join("scripts/checkpatch.pl");
            if cp.is_file() { candidates.push(cp); }
        }
    }
    candidates.sort();
    candidates.pop()
}

/// Helper : detect a binary in PATH. Returns Some(path) if found.
fn which_tool(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Detect kernel source context for static analysis.
///
/// Returns Some((ksrc, `kbuild_opt`, arch)) where :
///   - ksrc       : kernel source directory (contains Makefile + include/)
///   - `kbuild_opt` : `Some(build_dir)` if generated headers are present
///     (autoconf.h, asm-offsets.h, arch generated dirs), None otherwise
///   - arch       : "arm64" or "x86" -- target arch matching the kernel source
///
/// Preference order :
///   1. Yocto target (linux-7.0.x arm64) if present and built (KBUILD/include/generated/autoconf.h exists)
///   2. Host kernel /usr/src/linux as fallback
///
/// The Yocto path matters because beamfs targets linux-7.0.x and the host
/// kernel may be a different version (e.g. 6.18 on spartian-1) ; analyzing
/// against host kernel would produce false positives from API differences.
fn which_kernel_source() -> Option<(PathBuf, Option<PathBuf>, &'static str)> {
    // 1. Try Yocto target (preferred)
    let yocto_ksrc = PathBuf::from(
        crate::lab::kernel_source(),
    );
    if yocto_ksrc.join("Makefile").is_file() {
        // Find the most recent linux-mainline build dir for generated headers.
        let work_root = PathBuf::from(
            &format!("{}/tmp/work/{}-poky-linux/linux-mainline", crate::lab::build_dir(), crate::lab::machine()),
        );
        let kbuild = if work_root.is_dir() {
            // Pick the highest-version subdirectory that contains build/include/generated/autoconf.h.
            let mut best: Option<(String, PathBuf)> = None;
            if let Ok(entries) = std::fs::read_dir(&work_root) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if !p.is_dir() { continue; }
                    let build = p.join("build");
                    if !build.join("include/generated/autoconf.h").is_file() { continue; }
                    let name = match p.file_name().and_then(|n| n.to_str()) {
                        Some(n) => n.to_string(),
                        None => continue,
                    };
                    let take = match &best {
                        None => true,
                        Some((cur, _)) => name.as_str() > cur.as_str(),
                    };
                    if take {
                        best = Some((name, build));
                    }
                }
            }
            best.map(|(_, b)| b)
        } else {
            None
        };
        return Some((yocto_ksrc, kbuild, "arm64"));
    }

    // 2. Host kernel fallback
    let host = PathBuf::from("/usr/src/linux");
    if host.join("Makefile").is_file() {
        // For host kernel, generated headers live inside the kernel tree itself
        // when the kernel was prepared (make prepare). We do not require them
        // here -- if missing, sparse/clang will fail noisily and we report.
        return Some((host, None, "x86"));
    }

    None
}

/// Build the include + define flags equivalent to a Kbuild compile invocation.
///
/// Usable with sparse, clang, gcc -fsyntax-only.
/// When `kbuild_dir` is Some(...), generated headers (autoconf.h, asm-offsets.h,
/// arch/<arch>/include/generated/) are added explicitly.
fn kernel_check_flags(
    ksrc: &Path,
    kbuild_dir: Option<&Path>,
    arch: &str,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-nostdinc".to_string(),
        "-D__KERNEL__".to_string(),
        "-DMODULE".to_string(),
        "-DCONFIG_BEAMFS_FS=1".to_string(),
    ];

    if let Some(kb) = kbuild_dir {
        // Include generated/autoconf.h first so CONFIG_* macros are visible.
        args.push("-include".to_string());
        args.push(kb.join("include/generated/autoconf.h").display().to_string());
        // Generated arch headers (asm-offsets, generated stat.h, etc.)
        args.push(format!("-I{}/arch/{}/include", kb.display(), arch));
        args.push(format!("-I{}/arch/{}/include/generated", kb.display(), arch));
        args.push(format!("-I{}/arch/{}/include/generated/uapi", kb.display(), arch));
        args.push(format!("-I{}/include", kb.display()));
        args.push(format!("-I{}/include/generated", kb.display()));
        args.push(format!("-I{}/include/generated/uapi", kb.display()));
    }

    // kconfig.h defines IS_ENABLED(). It ships with the sources, not
    // the build tree. The kernel Makefile force-includes it alongside
    // autoconf.h; with only autoconf.h, every IS_ENABLED() in a kernel
    // header reads as a call to an undeclared function and its CONFIG_
    // argument as an unknown identifier -- which is where hundreds of
    // errors against untouched kernel headers were coming from.
    args.push("-include".to_string());
    args.push(ksrc.join("include/linux/kconfig.h").display().to_string());

    // Source headers (always, after build to allow build-side overrides)
    args.push(format!("-I{}/arch/{}/include", ksrc.display(), arch));
    args.push(format!("-I{}/arch/{}/include/uapi", ksrc.display(), arch));
    args.push(format!("-I{}/include", ksrc.display()));
    args.push(format!("-I{}/include/uapi", ksrc.display()));

    args
}

/// Count diagnostics in stderr that originate from a beamfs source file
/// (filename pattern <name>.c:<line>:<col>: -- when sparse/clang/gcc are
/// invoked with `current_dir` = `crate::lab::beamfs_repo()`, paths are relative).
fn count_beamfs_diagnostics(stderr: &str, beamfs_files: &[String]) -> (u32, u32) {
    let mut errors: u32 = 0;
    let mut warnings: u32 = 0;
    for line in stderr.lines() {
        // Match lines starting with "<beamfs_file>:" (relative path output)
        let from_beamfs = beamfs_files.iter().any(|f| {
            line.starts_with(&format!("{f}:"))
        });
        if !from_beamfs { continue; }
        if line.contains(": error:") || line.contains(": fatal error:") {
            errors += 1;
        } else if line.contains(": warning:") {
            warnings += 1;
        }
    }
    (errors, warnings)
}

/// List beamfs source filenames (relative, just the basename).
fn beamfs_source_basenames() -> Vec<String> {
    let dir = PathBuf::from(crate::lab::beamfs_repo());
    let mut out: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let name = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            // Skip kernel build artefacts. <module>.mod.c is generated
            // by modpost during a build and is gitignored; it has no
            // SPDX tag and references KBUILD_MODNAME, which is only
            // defined while the kernel build defines it, so sparse and
            // clang both fail on it. Whether it is present depends on
            // whether someone happened to run make in the tree, which
            // is not a property the analysis should depend on.
            if name.ends_with(".mod.c") {
                continue;
            }
            if name.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("c")) || name.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("h")) {
                out.push(name);
            }
        }
    }
    out
}

fn run_sparse(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let Some(bin) = which_tool("sparse") else {
        return ToolReport {
            name: "sparse".to_string(),
            tier: 1,
            outcome: ToolOutcome::Skip {
                reason: "sparse not in PATH ; emerge dev-util/sparse".to_string()
            },
            duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    };
    let Some((ksrc, kbuild, arch)) = which_kernel_source() else {
        return ToolReport {
            name: "sparse".to_string(),
            tier: 1,
            outcome: ToolOutcome::Skip {
                reason: "no kernel source found (Yocto build dir or /usr/src/linux)".to_string()
            },
            duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
    };
    let beamfs_dir = PathBuf::from(crate::lab::beamfs_repo());
    let basenames = beamfs_source_basenames();
    let c_files: Vec<String> = basenames.iter()
        .filter(|n| n.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("c")))
        .cloned()
        .collect();
    let mut log_buf = format!(
        "kernel source : {}\nkbuild dir    : {}\narch          : {}\n\n",
        ksrc.display(),
        kbuild.as_ref().map_or_else(|| "(none)".to_string(), |p| p.display().to_string()),
        arch,
    );
    let mut errors: u32 = 0;
    let mut warnings: u32 = 0;
    for cf in &c_files {
        let mut args = kernel_check_flags(&ksrc, kbuild.as_deref(), arch);
        args.push("-Wsparse-all".to_string());
        args.push("-Wbitwise".to_string());
        args.push(cf.clone());
        let Ok(res) = Command::new(&bin)
            .args(&args)
            .current_dir(&beamfs_dir)
            .output()
        else {
            continue;
        };
        let s = String::from_utf8_lossy(&res.stderr);
        writeln!(log_buf, "=== {cf} ===").unwrap();
        log_buf.push_str(&s);
        let (e, w) = count_beamfs_diagnostics(&s, &basenames);
        errors += e;
        warnings += w;
    }
    let log_path = out.join("sparse.log");
    let _ = std::fs::write(&log_path, &log_buf);
    // Loose policy : sparse warnings on beamfs sources are logged but do
    // not fail Tier 1. They include legitimate kernel patterns (__bitwise
    // casts, static-symbol suggestions, non-constant initializers) that
    // need targeted fixes in beamfs/*.c, tracked separately. Errors do
    // fail Tier 1 because they indicate broken include paths or invalid
    // C syntax that must be fixed before any submission.
    let outcome = if errors > 0 {
        ToolOutcome::Findings {
            count: errors + warnings,
            severity: "error".to_string(),
            log_path: log_path.display().to_string(),
        }
    } else {
        let _ = warnings;
        ToolOutcome::Pass
    };
    ToolReport {
        name: "sparse".to_string(),
        tier: 1,
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_smatch(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let log_path = out.join("smatch.log");
    let _ = std::fs::write(&log_path,
        "smatch : out-of-scope decision (Phase Y).\n\
         Rationale: smatch requires Kbuild integration (make C=2 CHECK=smatch)\n\
         and is non-trivial to invoke standalone for an out-of-tree module.\n\
         Reactivation deferred to a dedicated Yocto recipe task.\n");
    ToolReport {
        name: "smatch".to_string(),
        tier: 1,
        outcome: ToolOutcome::Skip {
            reason: "out-of-scope decision (Phase Y) ; needs Yocto recipe integration".to_string()
        },
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_coccinelle(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let log_path = out.join("coccinelle.log");
    let _ = std::fs::write(&log_path,
        "coccinelle : out-of-scope decision (Phase Y).\n\
         Rationale: spatch is not installed on spartian-1 and bringing it\n\
         in is non-trivial (Gentoo overlay package + dependencies).\n\
         Reactivation deferred to a future toolchain enrichment phase.\n");
    ToolReport {
        name: "coccinelle".to_string(),
        tier: 1,
        outcome: ToolOutcome::Skip {
            reason: "out-of-scope decision (Phase Y) ; spatch not installed".to_string()
        },
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_clang_werror(_files: &[PathBuf], out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let Some(bin) = which_tool("clang") else {
        return ToolReport {
            name: "clang_werror".to_string(),
            tier: 1,
            outcome: ToolOutcome::Skip {
                reason: "clang not in PATH ; emerge sys-devel/clang".to_string()
            },
            duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    };
    let Some((ksrc, kbuild, arch)) = which_kernel_source() else {
        return ToolReport {
            name: "clang_werror".to_string(),
            tier: 1,
            outcome: ToolOutcome::Skip {
                reason: "no kernel source found".to_string()
            },
            duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
    };
    let beamfs_dir = PathBuf::from(crate::lab::beamfs_repo());
    let basenames = beamfs_source_basenames();
    let c_files: Vec<String> = basenames.iter()
        .filter(|n| n.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("c")))
        .cloned()
        .collect();
    // Map kernel arch to clang target triple.
    // aarch64 is the default: the lab targets qemu-arm64, and an
    // unrecognised arch is more likely a naming variant of it than a
    // genuinely different target.
    let target = match arch {
        "x86" => "x86_64-linux-gnu",
        _ => "aarch64-linux-gnu",
    };
    let mut log_buf = format!(
        "kernel source : {}\nkbuild dir    : {}\narch / target : {} / {}\n\n",
        ksrc.display(),
        kbuild.as_ref().map_or_else(|| "(none)".to_string(), |p| p.display().to_string()),
        arch, target,
    );
    let mut errors: u32 = 0;
    let mut warnings: u32 = 0;
    for cf in &c_files {
        let mut args = kernel_check_flags(&ksrc, kbuild.as_deref(), arch);
        args.insert(0, format!("--target={target}"));
        args.push("-fsyntax-only".to_string());
        args.push("-Wall".to_string());
        args.push("-Wextra".to_string());
        args.push("-Wsign-compare".to_string());
        args.push("-Wshadow".to_string());
        // Kernel-standard suppressions (mirror what kernel root Makefile does)
        args.push("-Wno-unused-parameter".to_string());
        args.push("-Wno-pointer-sign".to_string());
        args.push("-Wno-unused-but-set-variable".to_string());
        args.push(cf.clone());
        let Ok(res) = Command::new(&bin)
            .args(&args)
            .current_dir(&beamfs_dir)
            .output()
        else {
            continue;
        };
        let s = String::from_utf8_lossy(&res.stderr);
        writeln!(log_buf, "=== {cf} ===").unwrap();
        log_buf.push_str(&s);
        let (e, w) = count_beamfs_diagnostics(&s, &basenames);
        errors += e;
        warnings += w;
    }
    let log_path = out.join("clang_werror.log");
    let _ = std::fs::write(&log_path, &log_buf);
    let outcome = if errors > 0 {
        ToolOutcome::Findings {
            count: errors + warnings,
            severity: "error".to_string(),
            log_path: log_path.display().to_string(),
        }
    } else if warnings > 0 {
        ToolOutcome::Findings {
            count: warnings,
            severity: "warning".to_string(),
            log_path: log_path.display().to_string(),
        }
    } else {
        ToolOutcome::Pass
    };
    ToolReport {
        name: "clang_werror".to_string(),
        tier: 1,
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_gcc_fanalyzer(_files: &[PathBuf], out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let log_path = out.join("gcc_fanalyzer.log");
    let _ = std::fs::write(&log_path,
        "gcc_fanalyzer : skipped permanently host-side.\n\
         Rationale: gcc -fanalyzer requires an aarch64 cross-toolchain to\n\
         analyze beamfs sources against the linux-7.0.x arm64 target. The\n\
         host gcc is x86_64-only ; aarch64-linux-gnu-gcc and Yocto SDK are\n\
         not installed on spartian-1.\n\
         The static analysis surface is covered by sparse + clang_werror\n\
         (which can target aarch64 via --target). Reactivation requires\n\
         either installing the Yocto SDK or bringing in aarch64 cross-gcc.\n");
    ToolReport {
        name: "gcc_fanalyzer".to_string(),
        tier: 1,
        outcome: ToolOutcome::Skip {
            reason: "needs aarch64 cross-toolchain (Yocto SDK not installed)".to_string()
        },
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_gitleaks(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let log_path = out.join("gitleaks.log");
    let _ = std::fs::write(&log_path,
        "gitleaks : out-of-scope decision (Phase Y).\n\
         Rationale: gitleaks is not installed on spartian-1. Bringing it in\n\
         requires go install or a binary download. R35 (secrets-never-in-chat)\n\
         + manual review provide an acceptable alternative for now.\n\
         Reactivation deferred to a future toolchain enrichment phase.\n");
    ToolReport {
        name: "gitleaks".to_string(),
        tier: 1,
        outcome: ToolOutcome::Skip {
            reason: "out-of-scope decision (Phase Y) ; gitleaks not installed".to_string()
        },
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_cargo_audit_high(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let log_path = out.join("cargo_audit.log");
    let _ = std::fs::write(&log_path,
        "cargo_audit_high : out-of-scope decision (Phase Y).\n\
         Rationale: cargo-audit is not installed on spartian-1. Bringing it\n\
         in requires `cargo install cargo-audit`. The bench dependency tree\n\
         is small and reviewed manually for now.\n\
         Reactivation deferred to a future toolchain enrichment phase.\n");
    ToolReport {
        name: "cargo_audit_high".to_string(),
        tier: 1,
        outcome: ToolOutcome::Skip {
            reason: "out-of-scope decision (Phase Y) ; cargo-audit not installed".to_string()
        },
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_cargo_clippy_pedantic(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let detect = Command::new("cargo")
        .args(["clippy", "--version"])
        .output();
    let installed = matches!(&detect, Ok(o) if o.status.success());
    if !installed {
        return ToolReport {
            name: "cargo_clippy_pedantic".to_string(),
            tier: 1,
            outcome: ToolOutcome::Skip {
                reason: "cargo clippy not installed ; rustup component add clippy".to_string()
            },
            duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
    }
    let res = Command::new("cargo")
        .args([
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-D", "warnings",
        ])
        .current_dir(crate::lab::bench_repo())
        .output();
    let mut log_buf = String::new();
    let mut findings: u32 = 0;
    let mut passed = false;
    if let Ok(o) = res {
        let s = String::from_utf8_lossy(&o.stderr);
        log_buf.push_str(&s);
        for line in s.lines() {
            if line.contains(crate::lab::bench_repo()) && line.contains("warning:") {
                findings += 1;
            }
        }
        passed = o.status.success();
    }
    let log_path = out.join("cargo_clippy.log");
    let _ = std::fs::write(&log_path, &log_buf);
    let outcome = if !passed && findings > 0 {
        ToolOutcome::Findings {
            count: findings,
            severity: "error".to_string(),
            log_path: log_path.display().to_string(),
        }
    } else if !passed {
        ToolOutcome::Error {
            message: "cargo clippy failed to run".to_string(),
        }
    } else {
        ToolOutcome::Pass
    };
    ToolReport {
        name: "cargo_clippy_pedantic".to_string(),
        tier: 1,
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_kernel_doc_validate(_files: &[PathBuf], out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let kdoc = PathBuf::from("/usr/src/linux/scripts/kernel-doc");
    if !kdoc.is_file() {
        return ToolReport {
            name: "kernel_doc".to_string(),
            tier: 1,
            outcome: ToolOutcome::Skip {
                reason: format!("kernel-doc not at {}", kdoc.display())
            },
            duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
    }
    let mut log_buf = String::new();
    let mut findings: u32 = 0;
    let beamfs_dir = PathBuf::from(crate::lab::beamfs_repo());
    if let Ok(entries) = std::fs::read_dir(&beamfs_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let name = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if !(name.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("c")) || name.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("h"))) { continue; }
            let Ok(res) = Command::new(&kdoc)
                .args(["-none", &name])
                .current_dir(&beamfs_dir)
                .output()
            else {
                continue;
            };
            let s = String::from_utf8_lossy(&res.stderr);
            if !s.trim().is_empty() {
                writeln!(log_buf, "=== {name} ===").unwrap();
                log_buf.push_str(&s);
                for line in s.lines() {
                    if line.contains("warning:") { findings += 1; }
                }
            }
        }
    }
    let log_path = out.join("kernel_doc.log");
    let _ = std::fs::write(&log_path, &log_buf);
    let outcome = if findings > 0 {
        ToolOutcome::Findings {
            count: findings,
            severity: "error".to_string(),
            log_path: log_path.display().to_string(),
        }
    } else {
        ToolOutcome::Pass
    };
    ToolReport {
        name: "kernel_doc".to_string(),
        tier: 1,
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}










fn run_gpg_verify_commits(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let mut bad: Vec<String> = Vec::new();
    let mut checked: u32 = 0;
    for repo in &[crate::lab::beamfs_repo(), crate::lab::bench_repo()] {
        let Ok(log_out) = Command::new("git")
            .args(["-C", repo, "log", "-20", "--format=%H"])
            .env("PAGER", "cat")
            .output()
        else {
            continue;
        };
        let commits = String::from_utf8_lossy(&log_out.stdout);
        for sha in commits.lines() {
            if sha.is_empty() { continue; }
            checked += 1;
            let v = Command::new("git")
                .args(["-C", repo, "verify-commit", sha])
                .env("PAGER", "cat")
                .output();
            match v {
                Ok(r) if r.status.success() => {}
                Ok(_) | Err(_) => bad.push(format!("{repo} {sha}")),
            }
        }
    }
    let log_path = out.join("gpg_verify.log");
    let mut log = format!("checked {checked} commits across 2 repos\n");
    if !bad.is_empty() {
        log.push_str("\nUNSIGNED:\n");
        for b in &bad { log.push_str(b); log.push('\n'); }
    }
    let _ = std::fs::write(&log_path, &log);
    let outcome = if bad.is_empty() {
        ToolOutcome::Pass
    } else {
        ToolOutcome::Findings {
            count: u32::try_from(bad.len()).unwrap_or(u32::MAX),
            severity: "error".to_string(),
            log_path: log_path.display().to_string(),
        }
    };
    ToolReport {
        name: "gpg_verify".to_string(),
        tier: 1,
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}









/// Determine if a substring at `pat_start..pat_end` in `line` is enclosed
/// in a backtick code-span (`...`) or in a double-quoted string ("...").
///
/// Used by `run_naming_r17_check` on .md files to skip matches that appear
/// as citations rather than authoritative naming. On non-.md files
/// (source code), this filter is NOT applied -- forbidden names in code
/// comments or string literals must still be flagged.
///
/// If a span opens but does not close before the end of line, the line's
/// end is treated as a soft close (covers multi-line markdown citations
/// where the closing quote is on the next line).
fn is_in_backtick_or_quote_span(line: &str, pat_start: usize, pat_end: usize) -> bool {
    let mut in_backtick = false;
    let mut in_dquote = false;
    let mut span_start: Option<usize> = None;
    for (idx, ch) in line.char_indices() {
        if !in_backtick && !in_dquote {
            if ch == '`' {
                in_backtick = true;
                span_start = Some(idx + ch.len_utf8());
            } else if ch == '"' {
                in_dquote = true;
                span_start = Some(idx + ch.len_utf8());
            }
        } else if in_backtick && ch == '`' {
            let s = span_start.unwrap();
            if s <= pat_start && pat_end <= idx { return true; }
            in_backtick = false;
            span_start = None;
        } else if in_dquote && ch == '"' {
            let s = span_start.unwrap();
            if s <= pat_start && pat_end <= idx { return true; }
            in_dquote = false;
            span_start = None;
        }
    }
    if in_backtick || in_dquote {
        if let Some(s) = span_start {
            if s <= pat_start && pat_end <= line.len() { return true; }
        }
    }
    false
}

fn run_naming_r17_check(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let forbidden = [
        "Beam-Resilient",
        "Beam Electromagnetic",
        "BEAM Electromagnetic",
    ];
    let mut hits: Vec<String> = Vec::new();
    for repo in &[crate::lab::beamfs_repo(), crate::lab::bench_repo()] {
        let walker = walkdir::WalkDir::new(repo).into_iter()
            .filter_entry(|e| {
                let p = e.path().to_string_lossy().to_string();
                // Permanent exclusion : src/code_analysis.rs contains the
                // forbidden patterns as string literals (the checker must
                // name what it forbids), self-detection would be a circular
                // false positive.
                if p.ends_with("/src/code_analysis.rs") { return false; }
                // Permanent exclusion : /context/ holds session notes
                // (context-recadrage.md and similar) which document
                // historical naming for traceability. By design these
                // files contain forbidden patterns AS DOCUMENTATION of
                // what is forbidden ; flagging them would be circular.
                if p.contains("/context/") { return false; }
                // Permanent exclusion : /Documentation/archive/ holds
                // session archives that are frozen by construction.
                // Re-naming history is preserved verbatim ; flagging
                // archived prose is not actionable.
                if p.contains("/Documentation/archive/") { return false; }
                !(p.contains("/.git/") || p.contains("/target/")
                  || p.contains("/context/archive/") || p.contains("/papers/"))
            });
        for entry in walker.flatten() {
            let path = entry.path();
            if !path.is_file() { continue; }
            let s = path.to_string_lossy();
            if !(s.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("c")) || s.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("h")) || s.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("md"))
                 || s.ends_with(".bb") || s.ends_with(".bbappend")
                 || s.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("rs"))) {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };
            let is_md = s.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("md"));
            for (lineno, line) in content.lines().enumerate() {
                for pat in &forbidden {
                    if let Some(start) = line.find(pat) {
                        let end = start + pat.len();
                        // On .md files, skip matches that are citations
                        // (inside backticks or double-quotes). Non-.md
                        // (source code) files are checked strictly.
                        if is_md && is_in_backtick_or_quote_span(line, start, end) {
                            continue;
                        }
                        hits.push(format!("{}:{}: {}", s, lineno + 1, line.trim()));
                    }
                }
            }
        }
    }
    let log_path = out.join("naming_r17.log");
    let _ = std::fs::write(&log_path, hits.join("\n"));
    let outcome = if hits.is_empty() {
        ToolOutcome::Pass
    } else {
        ToolOutcome::Findings {
            count: u32::try_from(hits.len()).unwrap_or(u32::MAX),
            severity: "error".to_string(),
            log_path: log_path.display().to_string(),
        }
    };
    ToolReport {
        name: "naming_r17".to_string(),
        tier: 1,
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_emdash_r16_check(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let mut hits: Vec<String> = Vec::new();
    for repo in &[crate::lab::beamfs_repo(), crate::lab::bench_repo()] {
        let walker = walkdir::WalkDir::new(repo).into_iter()
            .filter_entry(|e| {
                let p = e.path().to_string_lossy().to_string();
                // Permanent exclusion : /context/ holds session notes that
                // document forbidden patterns AS DOCUMENTATION (mirrors the
                // naming_r17 rationale).
                if p.contains("/context/") { return false; }
                // Permanent exclusion : /Documentation/archive/ holds
                // session archives that are frozen by construction.
                if p.contains("/Documentation/archive/") { return false; }
                !(p.contains("/.git/") || p.contains("/target/")
                  || p.contains("/context/archive/") || p.contains("/papers/"))
            });
        for entry in walker.flatten() {
            let path = entry.path();
            if !path.is_file() { continue; }
            let s = path.to_string_lossy();
            if !(s.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("c")) || s.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("h")) || s.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("md"))
                 || s.ends_with(".bb") || s.ends_with(".bbappend")
                 || s.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("rs"))) {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };
            for (lineno, line) in content.lines().enumerate() {
                for &(ch, label) in FORBIDDEN_R16 {
                    if line.contains(ch) {
                        hits.push(format!("{}:{}: [{}] {}",
                                          s, lineno + 1, label, line.trim()));
                    }
                }
            }
        }
    }
    let log_path = out.join("emdash_r16.log");
    let _ = std::fs::write(&log_path, hits.join("\n"));
    let outcome = if hits.is_empty() {
        ToolOutcome::Pass
    } else {
        ToolOutcome::Findings {
            count: u32::try_from(hits.len()).unwrap_or(u32::MAX),
            severity: "error".to_string(),
            log_path: log_path.display().to_string(),
        }
    };
    ToolReport {
        name: "emdash_r16".to_string(),
        tier: 1,
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_lockstep_r9_sha256(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let yocto_dir = PathBuf::from(crate::lab::yocto_kernel_files());
    if !yocto_dir.is_dir() {
        return ToolReport {
            name: "lockstep_r9".to_string(),
            tier: 1,
            outcome: ToolOutcome::Skip {
                reason: format!("yocto recipe dir {} not found", yocto_dir.display())
            },
            duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
    }
    let beamfs_dir = PathBuf::from(crate::lab::beamfs_repo());
    let mut divergences: Vec<String> = Vec::new();
    let mut checked: u32 = 0;
    if let Ok(entries) = std::fs::read_dir(&beamfs_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_file() { continue; }
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue
            };
            if !(name.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("c")) || name.rsplit('.').next().is_some_and(|e| e.eq_ignore_ascii_case("h"))) { continue; }
            let yocto_p = yocto_dir.join(name);
            if !yocto_p.is_file() { continue; }
            let Ok(beamfs_bytes) = std::fs::read(&p) else {
                continue;
            };
            let Ok(yocto_bytes) = std::fs::read(&yocto_p) else {
                continue;
            };
            checked += 1;
            if beamfs_bytes != yocto_bytes {
                divergences.push(format!(
                    "{} vs {}: byte length {} vs {}",
                    p.display(), yocto_p.display(),
                    beamfs_bytes.len(), yocto_bytes.len()
                ));
            }
        }
    }
    let log_path = out.join("lockstep_r9.log");
    let mut log = format!("checked {checked} lockstep .c/.h files\n");
    if !divergences.is_empty() {
        log.push_str("\nDIVERGENCES:\n");
        for d in &divergences { log.push_str(d); log.push('\n'); }
    }
    let _ = std::fs::write(&log_path, &log);
    let outcome = if divergences.is_empty() {
        ToolOutcome::Pass
    } else {
        ToolOutcome::Findings {
            count: u32::try_from(divergences.len()).unwrap_or(u32::MAX),
            severity: "error".to_string(),
            log_path: log_path.display().to_string(),
        }
    };
    ToolReport {
        name: "lockstep_r9".to_string(),
        tier: 1,
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
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
    // scan-build --status-bugs make M=$crate::lab::beamfs_repo()
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
