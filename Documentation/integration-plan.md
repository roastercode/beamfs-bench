# beamfs-bench main.rs / pipeline.rs integration plan

This document specifies the byte-exact insertion points for
code_analysis (Phase 0.0bis) and regression_check (Phase 8.3).

## main.rs -- Phase 0.0bis insert (after Phase 0.0 record)

Anchor (count==1):

```rust
    pipeline::record(&mut manifest, "0.0_isolation_r21", 0);

    // Phase 0.1
    if let Err(e) = pipeline::verify_clean_working_trees() {
```

Replace with:

```rust
    pipeline::record(&mut manifest, "0.0_isolation_r21", 0);

    // Phase 0.0bis -- MIL/kernel.org code analysis gate
    let code_analysis_mode = if full_code_analysis {
        code_analysis::AnalysisMode::Full
    } else {
        code_analysis::AnalysisMode::Incremental
    };
    let analysis_run_dir = std::path::PathBuf::from("/tmp/beamfs-bench-current-run");
    std::fs::create_dir_all(&analysis_run_dir)?;
    if let Err(e) = code_analysis::run(code_analysis_mode, &analysis_run_dir) {
        return Err(pipeline::fail(&mut manifest, "0.0bis_code_analysis", &e));
    }
    pipeline::record(&mut manifest, "0.0bis_code_analysis", 0);

    // Phase 0.1
    if let Err(e) = pipeline::verify_clean_working_trees() {
```

## main.rs -- Phase 8.3 insert (after Phase 8.2 emit_manifest)

Anchor (count==1):

```rust
    // Phase 8.2
    manifest.overall_rc  = analyse_rc;
    manifest.finished_at = pipeline::now_iso();
    let _ = pipeline::emit_manifest(&manifest);

    println!();
    println!("================================================================");
    println!(" beamfs-bench full complete - exit code {analyse_rc}");
```

Replace with:

```rust
    // Phase 8.2
    manifest.overall_rc  = analyse_rc;
    manifest.finished_at = pipeline::now_iso();
    let _ = pipeline::emit_manifest(&manifest);

    // Phase 8.3 -- regression check vs baseline (R7 canonical pre-push)
    // Only run if bench was functionally OK; pointless to compare a
    // crashed run.
    if analyse_rc == 0 {
        let current_run_dir = analyse::current_run_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/beamfs-bench-current-run"));
        if let Err(e) = regression_check::run(&current_run_dir, accept_regression.clone()) {
            return Err(pipeline::fail(&mut manifest, "8.3_regression_check", &e));
        }
        pipeline::record(&mut manifest, "8.3_regression_check", 0);
        // Re-emit manifest with phase 8.3 record + regression report ref
        let _ = pipeline::emit_manifest(&manifest);
    }

    println!();
    println!("================================================================");
    println!(" beamfs-bench full complete - exit code {analyse_rc}");
```

## main.rs -- CLI flags additions

Anchor (in `Command::Full { ... }` enum variant):

```rust
    Full {
        #[arg(long)]
        auto_confirm: bool,
        ...
    },
```

Add two flags:

```rust
    Full {
        #[arg(long)]
        auto_confirm: bool,
        ...
        /// Run Tier 3 code analysis (Frama-C, scan-build, lcov).
        /// Heavy: adds minutes to pipeline. Recommended weekly.
        #[arg(long)]
        full_code_analysis: bool,
        /// Bypass regression check with explicit reason string.
        /// Recorded in manifest for audit trail. Empty string rejected.
        #[arg(long)]
        accept_regression: Option<String>,
    },
```

## main.rs -- module declarations

Anchor (top of file, after existing `mod` lines):

```rust
mod analyse;
mod bitrot;
mod bootstrap;
...
```

Add:

```rust
mod code_analysis;
mod regression_check;
```

## analyse.rs -- expose current_run_dir

Add public accessor for the run directory so regression_check can
locate cluster-records.txt et al:

```rust
pub fn current_run_dir() -> Option<PathBuf> {
    // Logic depends on how analyse.rs currently tracks the run dir.
    // Either return last-set static, or expose via a return value
    // change to run().
    // TODO: implement based on current analyse.rs structure.
    None
}
```

## Order of operations for the implementing commit

1. `Cargo.toml`: add walkdir + tempfile (anchor M5)
2. Drop `code_analysis.rs` and `regression_check.rs` into `src/`
3. `main.rs`: add `mod` lines + CLI flags + Phase 0.0bis + Phase 8.3
4. `analyse.rs`: expose current_run_dir
5. `cargo build --release` -- must succeed with TODO stubs
6. `cargo test` -- structural tests pass
7. `cargo clippy --all-targets -- -D warnings` -- pre-Tier1 self-check
8. Run `beamfs-bench full --auto-confirm` -- code-analysis Phase 0.0bis
   should report all-Skip (TODO stubs), pipeline continues, regression
   Phase 8.3 should report no-baseline first run, pipeline passes
9. Commit beamfs-bench (single repo, R19 not gated on bench self-test)
