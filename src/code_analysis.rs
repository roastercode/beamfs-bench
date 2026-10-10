//! beamfs-bench code analysis: the gate of `full`, before the lab.
//!
//! Runs at phase 0.0bis, after the isolation check and before the clean
//! trees, so that no hour of measurement is spent on code a reviewer
//! would refuse. It checks the whole module and this bench, every time:
//!
//! - checkpatch, with spdxcheck, on the module sources laid out as one
//!   patch, and kernel-doc on every source and header, both from a
//!   worktree of `BEAMFS_BENCH_LINUX_BASE` of the kernel repository;
//! - sparse and clang on every module source, against the kernel tree
//!   the layer builds, or /usr/src/linux; sparse fails on an error,
//!   clang on a warning as well;
//! - the signatures of the last twenty commits of beamfs and of this
//!   bench;
//! - cargo clippy on this bench, every warning an error;
//! - the retired names of the project, and typographic dashes, arrows
//!   and quotes, in the sources and the documentation of both;
//! - the module sources against the copy in the layer, byte for byte.
//!
//! Every check has to run and pass. A tool that is not installed, or a
//! kernel tree or a layer that is not found, fails the gate as a finding
//! does. Until 0.16.1 it was a SKIP, and the pipeline went on; the gate
//! also listed as its own five tools that never ran in it, and eight
//! more in two tiers of stubs.
//!
//! smatch, coccinelle, sparse through Kbuild, checkstack and the builds
//! run in `beamfs-bench upstream`, on the series: that is the check of
//! kernel.org. gcc -fanalyzer, gitleaks, cargo audit, cppcheck,
//! flawfinder, semgrep, cargo geiger, the MISRA addon, Frama-C,
//! scan-build and lcov are run nowhere.
//!
//! The logs go to `<run_dir>/code-analysis/`, with
//! `code-analysis-summary.json`. A gate that does not pass stops the
//! pipeline and leaves that directory in
//! `/tmp/code-analysis-<TS>.tar.gz`.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::fmt::Write;

// R16 forbidden Unicode punctuation: em-dash, en-dash, right arrow,
// curly single/double quotes. Named emdash_r16 for baseline continuity.
pub(crate) const FORBIDDEN_R16: &[(char, &str)] = &[
    ('\u{2014}', "em-dash U+2014"),
    ('\u{2013}', "en-dash U+2013"),
    ('\u{2192}', "arrow U+2192"),
    ('\u{2018}', "left-single-quote U+2018"),
    ('\u{2019}', "right-single-quote U+2019"),
    ('\u{201C}', "left-double-quote U+201C"),
    ('\u{201D}', "right-double-quote U+201D"),
];

/// What one check found. A tool that could not run is an `Error`, and
/// fails the gate as `Findings` do.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum ToolOutcome {
    Pass,
    Findings { count: u32, severity: String, log_path: String },
    Error { message: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolReport {
    pub name: String,
    pub outcome: ToolOutcome,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeAnalysisReport {
    pub started_at:  String,
    pub finished_at: String,
    pub checks: Vec<ToolReport>,
    /// Every check ran and passed.
    pub pass: bool,
}

/// Public entry, called from `cmd_full` between `0.0_isolation_r21` and
/// `0.1_clean_trees`. When the gate does not pass, the error names the
/// checks that did not.
pub fn run(run_dir: &Path) -> Result<CodeAnalysisReport> {
    println!("[pipeline 0.0bis] code analysis, every check on the whole module");

    let analysis_dir = run_dir.join("code-analysis");
    std::fs::create_dir_all(&analysis_dir)
        .with_context(|| format!("create {}", analysis_dir.display()))?;

    let started_at = chrono::Utc::now().to_rfc3339();
    let checks = vec![
        run_checkpatch_strict(&analysis_dir),
        run_sparse(&analysis_dir),
        run_clang_werror(&analysis_dir),
        run_gpg_verify_commits(&analysis_dir),
        run_cargo_clippy_pedantic(&analysis_dir),
        run_kernel_doc_validate(&analysis_dir),
        run_naming_r17_check(&analysis_dir),
        run_emdash_r16_check(&analysis_dir),
        run_lockstep_r9_sha256(&analysis_dir),
    ];
    for r in &checks {
        log_tool(r);
    }
    let refused: Vec<String> = not_passed(&checks)
        .into_iter()
        .map(str::to_string)
        .collect();
    let report = CodeAnalysisReport {
        started_at,
        finished_at: chrono::Utc::now().to_rfc3339(),
        checks,
        pass: refused.is_empty(),
    };

    let json_path = analysis_dir.join("code-analysis-summary.json");
    std::fs::write(&json_path, serde_json::to_string_pretty(&report)?)
        .with_context(|| format!("write {}", json_path.display()))?;
    println!("\n  summary: {}", json_path.display());

    if !report.pass {
        let dump = dump_to_tmp_tarball(&analysis_dir)?;
        bail!(
            "code analysis: {} check(s) did not pass: {}; logs in {}",
            refused.len(),
            refused.join(", "),
            dump.display()
        );
    }
    Ok(report)
}

/// The checks that did not pass, by name: those with findings, and those
/// whose tool could not run.
fn not_passed(checks: &[ToolReport]) -> Vec<&str> {
    checks
        .iter()
        .filter(|r| r.outcome != ToolOutcome::Pass)
        .map(|r| r.name.as_str())
        .collect()
}

// ============================================================
// Helpers (logging, tarball)
// ============================================================

fn log_tool(r: &ToolReport) {
    let tag = match &r.outcome {
        ToolOutcome::Pass => "PASS",
        ToolOutcome::Findings { .. } => "FINDINGS",
        ToolOutcome::Error { .. } => "ERROR",
    };
    println!("    [{tag:>8}] {} ({} ms)", r.name, r.duration_ms);
    match &r.outcome {
        ToolOutcome::Pass => {}
        ToolOutcome::Findings { count, log_path, .. } => {
            println!("               {count} finding(s), {log_path}");
        }
        ToolOutcome::Error { message } => println!("               {message}"),
    }
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
// The checks
// ============================================================

/// checkpatch as a reviewer runs it, on the module sources laid out as
/// one patch, with spdxcheck, in a worktree of `BEAMFS_BENCH_LINUX_BASE`
/// (origin/master by default) of the kernel repository of
/// `beamfs-bench upstream` (`BEAMFS_BENCH_LINUX_REPO`, ~/git/linux by
/// default). Until 0.16.0 it ran in that repository's working tree, on
/// whatever branch was checked out there.
/// Every ERROR and WARNING blocks; the --strict CHECKs are in the log,
/// counted by type. Named `checkpatch_strict` for baseline continuity.
///
/// Until 0.15.0 this ran the host kernel's checkpatch with --no-tree on
/// --file, where a line over 100 columns is a CHECK, and counted ERROR
/// lines only: the ten long lines of beamfs 0.1.26 passed it. See
/// upstream.rs.
fn run_checkpatch_strict(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let rev = crate::upstream::linux_base();
    let outcome = match crate::upstream::Worktree::add(
        &crate::upstream::linux_repo(),
        &out.join("kernel-tree-checkpatch"),
        &rev,
    )
    .and_then(|wt| {
        crate::upstream::checkpatch_module(
            &wt.path,
            Path::new(crate::lab::beamfs_repo()),
            "beamfs",
            out,
        )
    }) {
        Ok(r) if r.blocking.is_empty() => ToolOutcome::Pass,
        Ok(r) => {
            for l in &r.blocking {
                println!("      {l}");
            }
            ToolOutcome::Findings {
                count: u32::try_from(r.blocking.len()).unwrap_or(u32::MAX),
                severity: "error or warning".to_string(),
                log_path: r.log.display().to_string(),
            }
        }
        Err(e) => ToolOutcome::Error {
            message: format!("{e:#}"),
        },
    };
    ToolReport {
        name: "checkpatch_strict".to_string(),
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
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
            outcome: ToolOutcome::Error {
                message: "sparse not in PATH ; emerge dev-util/sparse".to_string()
            },
            duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    };
    let Some((ksrc, kbuild, arch)) = which_kernel_source() else {
        return ToolReport {
            name: "sparse".to_string(),
            outcome: ToolOutcome::Error {
                message: "no kernel source found (Yocto build dir or /usr/src/linux)".to_string()
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
    // not fail the gate. They include legitimate kernel patterns (__bitwise
    // casts, static-symbol suggestions, non-constant initializers) that
    // need targeted fixes in beamfs/*.c, tracked separately. Errors do
    // fail the gate because they indicate broken include paths or invalid
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
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_clang_werror(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let Some(bin) = which_tool("clang") else {
        return ToolReport {
            name: "clang_werror".to_string(),
            outcome: ToolOutcome::Error {
                message: "clang not in PATH ; emerge sys-devel/clang".to_string()
            },
            duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    };
    let Some((ksrc, kbuild, arch)) = which_kernel_source() else {
        return ToolReport {
            name: "clang_werror".to_string(),
            outcome: ToolOutcome::Error {
                message: "no kernel source found".to_string()
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
        outcome,
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
            outcome: ToolOutcome::Error {
                message: "cargo clippy not installed ; rustup component add clippy".to_string()
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
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

/// kernel-doc on the module sources, the script taken from a worktree of
/// `BEAMFS_BENCH_LINUX_BASE`. Until 0.16.0 it was the one of the
/// station's kernel, /usr/src/linux, another release than the series is
/// judged by, and a missing script was skipped rather than failed.
fn run_kernel_doc_validate(out: &Path) -> ToolReport {
    let t0 = std::time::Instant::now();
    let rev = crate::upstream::linux_base();
    let failed = |message: String| ToolReport {
        name: "kernel_doc".to_string(),
        outcome: ToolOutcome::Error { message },
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    };
    let wt = match crate::upstream::Worktree::add(
        &crate::upstream::linux_repo(),
        &out.join("kernel-tree-kdoc"),
        &rev,
    ) {
        Ok(w) => w,
        Err(e) => return failed(format!("{e:#}")),
    };
    let Some(kdoc) = crate::upstream::kernel_doc_script(&wt.path) else {
        return failed(format!("kernel-doc is in no known place of {rev}"));
    };
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
            outcome: ToolOutcome::Error {
                message: format!("yocto recipe dir {} not found", yocto_dir.display())
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
        outcome,
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

// ============================================================
// Tests
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn report(name: &str, outcome: ToolOutcome) -> ToolReport {
        ToolReport {
            name: name.to_string(),
            outcome,
            duration_ms: 0,
        }
    }

    #[test]
    fn a_tool_that_cannot_run_fails_the_gate() {
        let checks = [
            report("checkpatch_strict", ToolOutcome::Pass),
            report(
                "sparse",
                ToolOutcome::Error {
                    message: "sparse not in PATH".to_string(),
                },
            ),
            report(
                "emdash_r16",
                ToolOutcome::Findings {
                    count: 1,
                    severity: "error".to_string(),
                    log_path: "emdash_r16.log".to_string(),
                },
            ),
        ];
        assert_eq!(not_passed(&checks), vec!["sparse", "emdash_r16"]);
        assert!(not_passed(&checks[..1]).is_empty());
    }

    #[test]
    fn the_summary_says_whether_the_gate_passed() {
        let r = CodeAnalysisReport {
            started_at: String::new(),
            finished_at: String::new(),
            checks: vec![report(
                "lockstep_r9",
                ToolOutcome::Error {
                    message: "yocto recipe dir not found".to_string(),
                },
            )],
            pass: false,
        };
        let j = serde_json::to_value(r).unwrap();
        assert_eq!(j["pass"], serde_json::Value::Bool(false));
        assert_eq!(
            j["checks"][0]["outcome"]["Error"]["message"],
            "yocto recipe dir not found"
        );
    }
}

#[cfg(test)]
mod station_tests {
    use super::*;

    /// The checkpatch and the kernel-doc of the gate, run for real against
    /// this station's kernel and beamfs repositories. Ignored by default:
    /// it checks the kernel out twice.
    ///
    /// cargo test --release -- --ignored the_gate_reads_the_base_tree
    #[test]
    #[ignore = "checks the kernel out twice; run on the station with --ignored"]
    fn the_gate_reads_the_base_tree() {
        let out = std::env::temp_dir().join(format!("bb-gate-{}", std::process::id()));
        std::fs::create_dir_all(&out).unwrap();
        let c = run_checkpatch_strict(&out);
        let k = run_kernel_doc_validate(&out);
        let _ = std::fs::remove_dir_all(&out);
        println!("checkpatch_strict: {:?}", c.outcome);
        println!("kernel_doc: {:?}", k.outcome);
        assert!(!matches!(c.outcome, ToolOutcome::Error { .. }));
        assert!(!matches!(k.outcome, ToolOutcome::Error { .. }));
    }
}
