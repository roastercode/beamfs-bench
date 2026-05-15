//! analyse.rs  -  forensic-instrumented multifs run.
//!
//! ## Scopes
//!
//! - `quick`    : multifs(probs=[1000000]) + post-capture master only
//!   (dmesg + RadFI + lsmod). No ftrace, no perf, no cluster.
//! - `standard` : multifs(probs=default) + post-capture all 4 nodes
//!   (dmesg + RadFI + lsmod) + RS journal SB on master.
//!   No ftrace, no perf, no cluster_*.
//! - `full`     : multifs(probs=default) + cluster_setup/attack/verify
//!   on master + 3 computes + ftrace function_graph on all
//!   nodes + perf record on master + RS journal SB on master
//!   + crash-report if any verdict failed.
//!
//! All scopes write into `<repo>/Documentation/runs/Tir-analyse-multifs-<TS>/`
//! and produce a tarball `<run_dir>.tar.gz` at the end (unless --no-tarball).
//!
//! The wrapped multifs run uses `pre_validated_mappings` so the user is
//! prompted exactly ONCE for the device validation table  -  at the start of
//! analyse, not again inside multifs.

use anyhow::{Context, Result};
use chrono::Local;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cluster;
use crate::devices;
use crate::forensics::{self, Scope};
use crate::forensics_host;
use crate::multifs::{self, MultifsConfig, DEFAULT_VM_NAME};
use crate::usb_health::SlotVerdict;

/// Configuration for an analyse run.
#[derive(Debug, Clone)]
pub struct AnalyseConfig {
    pub scope: Scope,
    pub auto_confirm: bool,
    pub dry_run: bool,
    pub make_tarball: bool,
    pub vm_name: String,
    /// Enable host-side bpftrace probes during the run.
    /// Requires NOPASSWD sudo on bpftrace ; otherwise skipped gracefully.
    pub bpftrace_host: bool,
    /// Fault injector to use: "radfi" or "emufi". Propagated to multifs
    /// + cluster scopes. Default: "radfi".
    pub injector: String,
    /// USB pre-flight verdicts captured by usb_health::run() in Phase 0.0a.
    /// Used to build the runtime (fs, vd) mapping via build_fs_mapping
    /// without any hardcoded DEFAULT_FS_LIST. Empty Vec is allowed only
    /// when scope=Standard or Quick is invoked without lifecycle/full
    /// (in that case multifs cannot run, but analyse can still capture
    /// host-level forensics).
    pub usb_verdicts: Vec<SlotVerdict>,
}

impl Default for AnalyseConfig {
    fn default() -> Self {
        Self {
            scope: Scope::Standard,
            auto_confirm: false,
            dry_run: false,
            make_tarball: true,
            bpftrace_host: false,
            vm_name: DEFAULT_VM_NAME.to_string(),
            injector: "radfi".to_string(),
            usb_verdicts: Vec::new(),
        }
    }
}

/// S3.1-cluster : parse cluster_setup_all outputs and compute the
/// union of per-node target_block_range, in sector units. Each
/// node may host the target_file at a different physical extent
/// (4 independent beamfs instances), so we take min(start) and
/// max(end) across reachable nodes to cover them all. RadFI then
/// flips inside this union, never on SB / inode 1 / inode table.
///
/// Returns None if no node emitted a valid range (e.g. old worker.sh
/// without the S3.1-cluster fields, or filefrag absent on the VM).
/// In that case, the caller MUST remove the env vars so the worker
/// falls back to whole-device injection (legacy, broadcast behaviour).
fn compute_cluster_target_range(setup: &[cluster::ClusterActionResult]) -> Option<(u64, u64)> {
    let mut min_start: Option<u64> = None;
    let mut max_end: Option<u64> = None;
    for r in setup {
        let mut start: Option<u64> = None;
        let mut end: Option<u64> = None;
        for tok in r.raw_output.trim().split('|') {
            if let Some((k, v)) = tok.split_once('=') {
                match k {
                    "TARGET_BLOCK_RANGE_START" => start = v.trim().parse().ok(),
                    "TARGET_BLOCK_RANGE_END"   => end   = v.trim().parse().ok(),
                    _ => {}
                }
            }
        }
        if let (Some(s), Some(e)) = (start, end) {
            if e > s {
                min_start = Some(min_start.map_or(s, |cur| cur.min(s)));
                max_end   = Some(max_end.map_or(e, |cur| cur.max(e)));
            }
        }
    }
    match (min_start, max_end) {
        (Some(s), Some(e)) if e > s => Some((s, e)),
        _ => None,
    }
}

/// S3.1-cluster : set or remove the TARGET_BLOCK_RANGE_* env vars
/// according to the computed union. Mirrors the multifs.rs::Phase 3
/// set/remove block. Must be called before each cluster_attack_all
/// (the range may evolve across setup_again iterations between probs).
fn apply_cluster_target_range(range: Option<(u64, u64)>) {
    match range {
        Some((s, e)) => {
            std::env::set_var("TARGET_BLOCK_RANGE_START", s.to_string());
            std::env::set_var("TARGET_BLOCK_RANGE_END",   e.to_string());
            println!("  [S3.1-cluster] target_block_range = [{s}, {e}) sectors");
        }
        None => {
            std::env::remove_var("TARGET_BLOCK_RANGE_START");
            std::env::remove_var("TARGET_BLOCK_RANGE_END");
            println!("  [S3.1-cluster] target_block_range UNAVAILABLE -- fallback to whole-device injection");
        }
    }
}

pub fn run(cfg: &AnalyseConfig) -> Result<i32> {
    let ts = Local::now();
    let ts_compact = ts.format("%Y%m%d-%H%M%S").to_string();
    let ts_human = ts.format("%Y-%m-%d %H:%M:%S").to_string();

    let repo_root = multifs::locate_repo_root()
        .context("could not locate yocto-beamfs repo root")?;

    println!("================================================================");
    println!(" beamfs-bench analyse -- scope={} -- {ts_human}", cfg.scope.as_str());
    println!("================================================================");

    // ----------------------------------------------------------------
    // Step 1: Device validation (single prompt for the whole analyse run)
    // ----------------------------------------------------------------
    // L5 : runtime fs mapping from Phase 0.0a verdicts.
    let fs_list_owned = crate::usb_health::build_fs_mapping(&cfg.usb_verdicts);
    if fs_list_owned.is_empty() {
        return Err(anyhow::anyhow!(
            "analyse::run : usb_verdicts is empty, cannot build fs_list.              Caller must populate AnalyseConfig.usb_verdicts via              usb_health::run() before invoking analyse."
        ));
    }
    let fs_list_refs: Vec<(&str, &str)> = fs_list_owned.iter()
        .map(|(f, v)| (f.as_str(), v.as_str()))
        .collect();
    let validated = devices::discover_and_validate(
        &cfg.vm_name,
        &fs_list_refs,
        cfg.auto_confirm,
        cfg.dry_run,
    ).context("device validation failed")?;

    // ----------------------------------------------------------------
    // Step 2a: Deploy worker on all 4 nodes BEFORE discover_cluster.
    //
    // discover_cluster invokes the worker via SSH on each node, so the
    // worker MUST already be present. We deploy blindly (we don't yet
    // know which nodes are reachable). Per-node failures are silent and
    // surface as reachable=false in the next step.
    //
    // This is done unconditionally for ALL scopes, including quick: the
    // forensic post-capture (dmesg/lsmod) does not need the worker, but
    // having an accurate cluster topology table on every run is worth
    // the ~4 quick scp invocations.
    // ----------------------------------------------------------------
    println!();
    println!("[discover] Pre-deploying worker on all 4 nodes (for cluster topology)...");
    // We use a synthetic ClusterNode list with all 4 nodes flagged reachable
    // so deploy_worker_all attempts each one. discover_cluster afterwards
    // will report the real reachability state.
    let bootstrap_nodes: Vec<crate::cluster::ClusterNode> = crate::cluster::CLUSTER_NODES
        .iter()
        .map(|(ip, hostname)| crate::cluster::ClusterNode {
            ip: ip.to_string(),
            expected_hostname: hostname.to_string(),
            discovered: crate::cluster::NodeState {
                reachable: true,
                ..Default::default()
            },
        })
        .collect();
    let deploy_pre = cluster::deploy_worker_all(&bootstrap_nodes)
        .context("pre-deploy worker for cluster discovery")?;
    for (host, r) in &deploy_pre {
        match r {
            Ok(()) => println!("  {host} : deployed"),
            Err(e) => println!("  {host} : deploy failed (will appear unreachable): {e:#}"),
        }
    }

    // ----------------------------------------------------------------
    // Step 2b: Now query cluster topology with the worker in place
    // ----------------------------------------------------------------
    println!();
    println!("[discover] Cluster topology...");
    let nodes = cluster::discover_cluster()
        .context("cluster discovery failed")?;
    let cluster_table = cluster::render_cluster_table(&nodes);
    print!("{cluster_table}");

    let any_unreachable = nodes.iter().any(|n| !n.discovered.reachable);
    if any_unreachable && cfg.scope != Scope::Quick {
        eprintln!("beamfs-bench: WARNING  -  at least one cluster node is unreachable.");
        eprintln!("beamfs-bench: forensic capture will skip those nodes.");
    }

    // ----------------------------------------------------------------
    // Step 3: Create run dir + persist topology table for audit
    // ----------------------------------------------------------------
    let run_dir_prefix = match cfg.scope {
        Scope::Quick => "beamfs-bench-analyse-quick",
        Scope::Standard => "beamfs-bench-analyse",
        Scope::Full => "beamfs-bench-analyse-full",
    };
    let run_dir = repo_root
        .join("Documentation/runs")
        .join(format!("{run_dir_prefix}-{ts_compact}"));
    fs::create_dir_all(&run_dir)
        .with_context(|| format!("create_dir_all {:?}", run_dir))?;
    fs::write(run_dir.join("cluster-topology.txt"), &cluster_table)
        .context("write cluster-topology.txt")?;
    let scope_str = cfg.scope.as_str();
    fs::write(run_dir.join("scope.txt"), format!("{scope_str}\n"))
        .context("write scope.txt")?;

    // ----------------------------------------------------------------
    // Step 4: Worker deployment already done at step 2a (pre-discovery).
    // No-op here; left as a checkpoint for log readability.
    // ----------------------------------------------------------------
    println!();
    println!("[deploy] Worker already deployed at step 2a (skipping).");

    // ----------------------------------------------------------------
    // Step 5: Pre-capture (clear dmesg, arm ftrace if full)
    // ----------------------------------------------------------------
    println!();
    println!("[pre]    Clear dmesg + arm forensics (scope={scope_str})...");
    let pre_results = forensics::pre_capture_all(&nodes, cfg.scope)
        .context("pre-capture setup failed")?;
    for (host, r) in &pre_results {
        match r {
            Ok(()) => println!("  {host} : ok"),
            Err(e) => println!("  {host} : pre-capture warning: {e:#}"),
        }
    }

    // Host-side capture (companion to forensics::pre_capture_all).
    // Best-effort : failures here log a warning but do not abort the run.
    if let Err(e) = forensics_host::pre_capture_host(&run_dir, cfg.scope, cfg.bpftrace_host) {
        eprintln!("  host pre-capture warning: {e:#}");
    }

    if cfg.scope == Scope::Full {
        println!("[pre]    Start perf record on master...");
        if let Err(e) = forensics::start_perf_master() {
            eprintln!("beamfs-bench: perf record failed to start: {e:#}  -  continuing without perf.");
        }
    }

    // ----------------------------------------------------------------
    // Step 6: Wrapped multifs run (master only, on the validated USB sticks)
    // ----------------------------------------------------------------
    println!();
    println!("[run]    Wrapped multifs...");
    let mut multifs_cfg = MultifsConfig {
        run_dir_prefix: "beamfs-bench-multifs".to_string(),
        skip_worker_deploy: true,  // we already deployed
        suppress_synthesis_print: true,
        pre_validated_mappings: Some(validated.clone()),
        auto_confirm: true,  // already validated
        injector: cfg.injector.clone(),
        // L5 : populate fs_list from verdicts (default is empty).
        fs_list: fs_list_owned.clone(),
        ..MultifsConfig::default()
    };
    if cfg.scope == Scope::Quick {
        multifs_cfg.probs = vec![1_000_000];
    }
    let multifs_result = match multifs::run_with_config(&multifs_cfg) {
        Ok(r) => Some(r),
        Err(e) => {
            eprintln!("beamfs-bench: multifs run failed: {e:#}");
            None
        }
    };

    // Capture run log link into the analyse run dir
    if let Some(ref r) = multifs_result {
        let _ = std::os::unix::fs::symlink(&r.run_dir, run_dir.join("tir-internal"));
        let _ = fs::copy(r.run_dir.join("synthesis.md"), run_dir.join("multifs-synthesis.md"));
        let _ = fs::copy(r.run_dir.join("synthesis.json"), run_dir.join("multifs-synthesis.json"));
        let _ = fs::copy(r.run_dir.join("all-records.txt"), run_dir.join("multifs-all-records.txt"));
    }

    // ----------------------------------------------------------------
    // Step 7: Cluster-wide attack (full only)
    // ----------------------------------------------------------------
    let mut cluster_records_path: Option<PathBuf> = None;
    if cfg.scope == Scope::Full {
        // S3.1-cluster : union of per-node target_block_range, refreshed
        // at every cluster_setup_all. Unconditionally assigned by both
        // branches of the immediately-following setup-or-retry block;
        // no initializer to keep the compiler enforcing that invariant.
        // Subsequent re-assignments inside the prob loop are guarded by
        // `if probs.last() != Some(&prob)` and are dead on the final
        // iteration (intentional ; cluster_target_range is consumed at
        // the TOP of each loop iter via apply_cluster_target_range).
        #[allow(unused_assignments)]
        let mut cluster_target_range: Option<(u64, u64)>;

        println!();
        println!("[cluster] cluster_setup on all reachable nodes...");
        let setup = cluster::cluster_setup_all(&nodes, &ts_compact, &cfg.injector)
            .context("cluster_setup_all failed")?;
        for r in &setup {
            println!("  {} : {}", r.host, r.raw_output);
        }
        // func-1 fix B placement INITIAL: same retry+bootstrap pattern as
        // the inter-prob block below. Without this, the FIRST probability
        // iteration could hit subdir_missing if /data was already in a
        // degraded state (e.g. previous mega run aborted, mount stale).
        // Empirical evidence: mega run 20260501-225142 cluster-records.txt
        // showed 8 events subdir_missing at prob=1000 (first iter), then
        // 12/12 RECOVERED at prob=100k and 1M.
        let any_error_initial = setup.iter()
            .any(|r| r.raw_output.contains("ERROR"));
        if any_error_initial {
            println!("[cluster] initial setup detected ERROR, running bootstrap_data on all nodes...");
            for r in &setup {
                if r.raw_output.contains("ERROR") {
                    println!("    {} : {}", r.host, r.raw_output);
                }
            }
            // Best-effort bootstrap; if /data was lost, this re-mounts it
            let _ = cluster::bootstrap_data_all(&nodes, &cfg.injector);
            // Then retry setup one more time
            println!("[cluster] cluster_setup final retry after bootstrap...");
            let setup_final = cluster::cluster_setup_all(&nodes, &ts_compact, &cfg.injector)
                .context("cluster_setup_all initial retry failed")?;
            for r in &setup_final {
                println!("    {} : {}", r.host, r.raw_output);
            }
            // S3.1-cluster : use the retried setup output as the
            // authoritative source for target_block_range.
            cluster_target_range = compute_cluster_target_range(&setup_final);
        } else {
            // S3.1-cluster : no retry needed, use initial setup output.
            cluster_target_range = compute_cluster_target_range(&setup);
        }

        // Sweep the same probs as multifs for consistency. Probs come from
        // multifs_cfg.probs (already adjusted for quick scope above).
        let probs = multifs_cfg.probs.clone();
        let cluster_log = run_dir.join("cluster-records.txt");
        let mut cf = fs::File::create(&cluster_log)
            .with_context(|| format!("create {:?}", cluster_log))?;

        for &prob in &probs {
            println!();
            println!("[cluster] cluster_attack prob={prob} on all reachable nodes...");
            // S3.1-cluster : apply env vars BEFORE attack so cluster.rs::worker_cmd
            // forwards them via SSH and worker.sh::cluster_attack pushes them to
            // debugfs (target_block_range_{start,end}). RadFI then narrows the
            // injection to the target_file's physical extents, never SB nor inode 1.
            apply_cluster_target_range(cluster_target_range);
            let atk = cluster::cluster_attack_all(&nodes, &ts_compact, prob, &cfg.injector)
                .context("cluster_attack_all failed")?;
            for r in &atk {
                println!("  {} : {}", r.host, r.raw_output);
                writeln!(cf, "ATTACK|prob={prob}|{}", r.raw_output)?;
            }

            println!("[cluster] cluster_verify after prob={prob}...");
            let verif = cluster::cluster_verify_all(&nodes, &ts_compact, &cfg.injector)
                .context("cluster_verify_all failed")?;
            for r in &verif {
                println!("  {} : {}", r.host, r.raw_output);
                writeln!(cf, "VERIFY|prob={prob}|{}", r.raw_output)?;
            }

            // B.4 (M1 C3) : derive 5-class verdict per (host, prob) and
            // write DERIVED| lines to cluster-records.txt. The verdict is
            // computed in synthesis::extract_cluster_verdict from the
            // ATTACK + VERIFY records of this same prob iteration. The
            // records were just written above so we re-read the file.
            //
            // Note : we re-read the entire cluster_log here. For the
            // current 4-node x 3-prob layout this is 24 lines max ;
            // optimisation deferred until/if it becomes a hot path.
            cf.flush().context("flush cluster_log before derived verdict")?;
            let buf = std::fs::read_to_string(&cluster_log)
                .context("re-read cluster_log for verdict derivation")?;
            for r in &atk {
                if let Some(v) = crate::synthesis::extract_cluster_verdict(&buf, &r.host, prob) {
                    writeln!(cf, "DERIVED|prob={prob}|host={}|verdict={}", r.host, v)?;
                }
                // Phase A.1: companion verdict_detail line. Same input,
                // additionally exploits DMESG_UNCORRECTABLE and DMESG_EIO
                // signals to distinguish KERNEL_PANIC / DETECTED_FAIL_CLOSED /
                // INACCESSIBLE / SILENT_CORRUPTION from the legacy 5-class
                // taxonomy. Downstream tooling that does not know this line
                // can safely ignore it.
                if let Some(vd) = crate::synthesis::extract_cluster_verdict_detail(&buf, &r.host, prob) {
                    writeln!(cf, "DERIVED|prob={prob}|host={}|verdict_detail={}", r.host, vd)?;
                }
            }

            // Re-create the test layout for the next probability iteration
            // (cluster_verify removes the subdir at the end).
            //
            // Critical: previously this used `let _ =` which silently dropped
            // any setup failure. If /data was umounted collaterally between
            // probs (RadFI attack on vdb may corrupt mount state), all
            // subsequent attack/verify would fail with subdir_missing.
            //
            // Now: check setup outputs and retry once via bootstrap_data
            // if any node reports SETUP=ERROR.
            if probs.last() != Some(&prob) {
                println!("[cluster] cluster_setup again for next prob...");
                let setup_again = cluster::cluster_setup_all(&nodes, &ts_compact, &cfg.injector)
                    .context("cluster_setup_all retry failed")?;
                // S3.1-cluster : refresh range from the new setup outputs.
                // The target_file extent layout can change because cluster_verify
                // unlinks the previous $SUBDIR and cluster_setup recreates it.
                cluster_target_range = compute_cluster_target_range(&setup_again);
                let any_error = setup_again.iter()
                    .any(|r| r.raw_output.contains("ERROR"));
                if any_error {
                    println!("[cluster] setup retry detected ERROR, running bootstrap_data on all nodes...");
                    for r in &setup_again {
                        if r.raw_output.contains("ERROR") {
                            println!("    {} : {}", r.host, r.raw_output);
                        }
                    }
                    // Best-effort bootstrap; if /data was lost, this re-mounts it
                    let _ = cluster::bootstrap_data_all(&nodes, &cfg.injector);
                    // Then retry setup one more time
                    println!("[cluster] cluster_setup final retry after bootstrap...");
                    let setup_final = cluster::cluster_setup_all(&nodes, &ts_compact, &cfg.injector)
                        .context("cluster_setup_all final retry failed")?;
                    for r in &setup_final {
                        println!("    {} : {}", r.host, r.raw_output);
                    }
                    // S3.1-cluster : range from the retried setup outputs.
                    cluster_target_range = compute_cluster_target_range(&setup_final);
                }
            }
        }

        // S3.1-cluster : cleanup env vars after the cluster sweep is done.
        std::env::remove_var("TARGET_BLOCK_RANGE_START");
        std::env::remove_var("TARGET_BLOCK_RANGE_END");

        cluster_records_path = Some(cluster_log);
    }

    // ----------------------------------------------------------------
    // Step 8: Stop perf, post-capture forensics
    // ----------------------------------------------------------------
    if cfg.scope == Scope::Full {
        println!();
        println!("[post]   Stop perf record on master...");
        let _ = forensics::stop_perf_master();
    }

    println!();
    println!("[post]   Forensic capture (scope={scope_str})...");
    let post_results = forensics::post_capture_all(&nodes, &run_dir, cfg.scope)
        .context("post-capture failed")?;
    for (host, r) in &post_results {
        match r {
            Ok(p) => println!("  {host} : {} ", p.display()),
            Err(e) => println!("  {host} : FAILED ({e:#})"),
        }
    }

    // Host-side post-capture (companion to forensics::post_capture_all).
    if let Err(e) = forensics_host::post_capture_host(&run_dir, cfg.scope, cfg.bpftrace_host) {
        eprintln!("  host post-capture warning: {e:#}");
    }

    // ----------------------------------------------------------------
    // Step 9: Crash report if anything failed
    // ----------------------------------------------------------------
    let exit_code = aggregate_exit_code(
        &multifs_result,
        &run_dir,
        &cluster_records_path,
        &multifs_cfg.probs,
        &nodes,
    );
    if exit_code != 0 {
        let tir_log = run_dir.join("multifs-all-records.txt");
        let tir_log_opt = if tir_log.exists() { Some(tir_log.as_path()) } else { None };
        forensics::write_crash_report(&run_dir, &ts_human, exit_code, tir_log_opt)
            .context("write crash report")?;
        eprintln!("beamfs-bench: crash report written to {}", run_dir.join("crash-report.md").display());
    }

    // ----------------------------------------------------------------
    // Step 10: Tarball (unless --no-tarball)
    // ----------------------------------------------------------------
    let mut archive_path: Option<PathBuf> = None;
    if cfg.make_tarball {
        println!();
        println!("[tar]    Archive...");
        let archive = make_tarball(&run_dir).context("create tarball")?;
        let size = std::fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
        println!("  {} ({} bytes)", archive.display(), size);
        archive_path = Some(archive);
    }

    // ----------------------------------------------------------------
    // Step 11: Summary
    // ----------------------------------------------------------------
    println!();
    println!("================================================================");
    println!(" beamfs-bench analyse complete -- scope={scope_str}");
    println!("================================================================");
    println!("Run dir : {}", run_dir.display());
    if let Some(ref a) = archive_path {
        println!("Archive : {}", a.display());
    }
    if let Some(ref r) = multifs_result {
        println!("Multifs : {}", r.run_dir.display());
    }
    if let Some(p) = cluster_records_path {
        println!("Cluster : {}", p.display());
    }
    println!("Exit    : {exit_code}");

    let _ = validated;  // silence unused warning if not used downstream
    Ok(exit_code)
}

/// Aggregate exit_code from multifs + cluster verdicts.
///
/// Trouvaille 2 fix : prior code returned 0 iff multifs_result.is_some(),
/// which ignored the actual verdict content. R19 Phase 6 criterion
/// "12/12 RECOVERED DIFFS=0" is now enforced here.
///
/// Decision rules :
///   - multifs_result == None                       -> 1 (hard fail)
///   - any beamfs (multifs) verdict != RS_RECOVERED|RS_PASSTHROUGH -> 1
///   - any cluster (host, prob) verdict != RS_RECOVERED|RS_PASSTHROUGH -> 1
///   - legacy multifs FS (ext4) FS_PANIC at any prob is ALLOWED
///     (R19 explicitly says "ext4/btrfs FS_PANIC at prob=1M is expected
///     and non-blocking ; only beamfs must RECOVERED 3/3").
///   - else -> 0
fn aggregate_exit_code(
    multifs_result: &Option<crate::multifs::MultifsResult>,
    run_dir: &Path,
    cluster_records_path: &Option<PathBuf>,
    multifs_probs: &[u32],
    cluster_nodes: &[crate::cluster::ClusterNode],
) -> i32 {
    // Rule 1
    if multifs_result.is_none() {
        return 1;
    }

    // Rule 2 : beamfs in multifs scope
    let multifs_log = run_dir.join("multifs-all-records.txt");
    if multifs_log.exists() {
        if let Ok(records) = std::fs::read_to_string(&multifs_log) {
            for &prob in multifs_probs {
                let v = crate::synthesis::extract_verdict(&records, "beamfs", prob);
                if !verdict_is_pass(v.as_deref()) {
                    eprintln!(
                        "[exit_code] FAIL : multifs beamfs prob={prob} verdict={:?} (expected RS_RECOVERED or RS_PASSTHROUGH)",
                        v.as_deref().unwrap_or("?"),
                    );
                    return 1;
                }
            }
        } else {
            eprintln!("[exit_code] FAIL : cannot read {}", multifs_log.display());
            return 1;
        }
    } else {
        eprintln!("[exit_code] FAIL : missing {}", multifs_log.display());
        return 1;
    }

    // Rule 3 : cluster scope (Full only ; cluster_records_path None means
    // scope was Quick or Standard, where cluster phase did not run).
    if let Some(cl_path) = cluster_records_path {
        if let Ok(records) = std::fs::read_to_string(cl_path) {
            for n in cluster_nodes {
                if !n.discovered.reachable {
                    continue;
                }
                let host = &n.expected_hostname;
                for &prob in multifs_probs {
                    let v = crate::synthesis::extract_cluster_verdict(&records, host, prob);
                    if !verdict_is_pass(v.as_deref()) {
                        eprintln!(
                            "[exit_code] FAIL : cluster host={host} prob={prob} verdict={:?} (expected RS_RECOVERED or RS_PASSTHROUGH)",
                            v.as_deref().unwrap_or("?"),
                        );
                        return 1;
                    }
                }
            }
        } else {
            eprintln!("[exit_code] FAIL : cannot read {}", cl_path.display());
            return 1;
        }
    }

    0
}

/// Verdict-pass predicate : the only states that count as a clean pass
/// for beamfs (FEC-protected) are RS_RECOVERED (FEC corrected the flip)
/// and RS_PASSTHROUGH (no flip reached data, FEC unused but data intact).
/// Every other state (CORRUPTED_DATA, RS_FAILED, FS_PANIC, ?) is a fail.
fn verdict_is_pass(v: Option<&str>) -> bool {
    matches!(v, Some("RS_RECOVERED") | Some("RS_PASSTHROUGH"))
}

pub fn make_tarball(run_dir: &Path) -> Result<PathBuf> {
    let parent = run_dir.parent()
        .ok_or_else(|| anyhow::anyhow!("run_dir has no parent"))?;
    let name = run_dir.file_name()
        .ok_or_else(|| anyhow::anyhow!("run_dir has no basename"))?
        .to_string_lossy()
        .to_string();

    // 0.1 enrichment: copy the most recent manifest .json + .json.asc
    // alongside the run_dir/host/ before tar. Establishes the run <-> tarball
    // link (manifest path was previously only on disk under Documentation/runs/).
    {
        let host_dir = run_dir.join("host");
        let manifest_dir = std::path::Path::new(
            "/home/aurelien/git/yocto-beamfs/Documentation/runs"
        );
        if let Ok(entries) = std::fs::read_dir(manifest_dir) {
            // Bug C fix: filter STRICTLY on names ending in `.json` (not
            // `.json.asc`), so sort_by_key + last() picks the most recent
            // manifest .json, and the .asc lookup builds the correct path.
            let mut manifests: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().to_string();
                    n.starts_with("manifest-") && n.ends_with(".json")
                })
                .collect();
            manifests.sort_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
            if let Some(latest) = manifests.last() {
                let stem = latest.path();
                let stem_str = stem.to_string_lossy().to_string();
                // Copy .json (always)
                let dst_json = host_dir.join(latest.file_name());
                let _ = std::fs::copy(&stem, &dst_json);
                // Copy .json.asc if it exists alongside
                let asc_src = format!("{stem_str}.asc");
                if std::path::Path::new(&asc_src).exists() {
                    let asc_name = format!("{}.asc", latest.file_name().to_string_lossy());
                    let _ = std::fs::copy(&asc_src, host_dir.join(asc_name));
                }
            }
        }
    }

    // 0.1 enrichment: write MANIFEST.sha256 at run_dir root listing every
    // file's sha256. Allows post-extraction integrity check by users.
    {
        let manifest_path = run_dir.join("MANIFEST.sha256");
        let cmd = format!(
            "cd {} && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > {}",
            run_dir.display(),
            manifest_path.display(),
        );
        let _ = Command::new("bash").arg("-c").arg(&cmd).status();
    }

    // Tarball lives under /tmp/ (not next to run_dir under Documentation/runs/),
    // aligning analyse/full behavior with mega (cf. src/mega.rs). Keeps
    // run_dir as the canonical source of truth on disk; the tarball is a
    // transient archive for sharing/investigation.
    let archive = Path::new("/tmp").join(format!("{name}.tar.gz"));

    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(parent)
        .arg(&name)
        .status()
        .context("spawn tar")?;
    if !status.success() {
        return Err(anyhow::anyhow!("tar failed (exit {:?})", status.code()));
    }
    Ok(archive)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_is_pass_accepts_rs_recovered() {
        assert!(verdict_is_pass(Some("RS_RECOVERED")));
    }

    #[test]
    fn verdict_is_pass_accepts_rs_passthrough() {
        assert!(verdict_is_pass(Some("RS_PASSTHROUGH")));
    }

    #[test]
    fn verdict_is_pass_rejects_corrupted() {
        assert!(!verdict_is_pass(Some("CORRUPTED_DATA")));
    }

    #[test]
    fn verdict_is_pass_rejects_rs_failed() {
        assert!(!verdict_is_pass(Some("RS_FAILED")));
    }

    #[test]
    fn verdict_is_pass_rejects_fs_panic() {
        assert!(!verdict_is_pass(Some("FS_PANIC")));
    }

    #[test]
    fn verdict_is_pass_rejects_none() {
        assert!(!verdict_is_pass(None));
    }
}
