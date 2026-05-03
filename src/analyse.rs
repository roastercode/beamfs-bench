//! analyse.rs — forensic-instrumented multifs run.
//!
//! ## Scopes
//!
//! - `quick`    : multifs(probs=[1000000]) + post-capture master only
//!                (dmesg + RadFI + lsmod). No ftrace, no perf, no cluster.
//! - `standard` : multifs(probs=default) + post-capture all 4 nodes
//!                (dmesg + RadFI + lsmod) + RS journal SB on master.
//!                No ftrace, no perf, no cluster_*.
//! - `full`     : multifs(probs=default) + cluster_setup/attack/verify
//!                on master + 3 computes + ftrace function_graph on all
//!                nodes + perf record on master + RS journal SB on master
//!                + crash-report if any verdict failed.
//!
//! All scopes write into `<repo>/Documentation/runs/Tir-analyse-multifs-<TS>/`
//! and produce a tarball `<run_dir>.tar.gz` at the end (unless --no-tarball).
//!
//! The wrapped multifs run uses `pre_validated_mappings` so the user is
//! prompted exactly ONCE for the device validation table — at the start of
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
use crate::multifs::{self, MultifsConfig, DEFAULT_FS_LIST, DEFAULT_VM_NAME};

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
    let fs_list_refs: Vec<(&str, &str)> = DEFAULT_FS_LIST.iter().copied().collect();
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
        eprintln!("beamfs-bench: WARNING — at least one cluster node is unreachable.");
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
            eprintln!("beamfs-bench: perf record failed to start: {e:#} — continuing without perf.");
        }
    }

    // ----------------------------------------------------------------
    // Step 6: Wrapped multifs run (master only, on the validated USB sticks)
    // ----------------------------------------------------------------
    println!();
    println!("[run]    Wrapped multifs...");
    let mut multifs_cfg = MultifsConfig::default();
    multifs_cfg.run_dir_prefix = "beamfs-bench-multifs".to_string();
    multifs_cfg.skip_worker_deploy = true;  // we already deployed
    multifs_cfg.suppress_synthesis_print = true;
    multifs_cfg.pre_validated_mappings = Some(validated.clone());
    multifs_cfg.auto_confirm = true;  // already validated
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
        println!();
        println!("[cluster] cluster_setup on all reachable nodes...");
        let setup = cluster::cluster_setup_all(&nodes, &ts_compact)
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
            let _ = cluster::bootstrap_data_all(&nodes);
            // Then retry setup one more time
            println!("[cluster] cluster_setup final retry after bootstrap...");
            let setup_final = cluster::cluster_setup_all(&nodes, &ts_compact)
                .context("cluster_setup_all initial retry failed")?;
            for r in &setup_final {
                println!("    {} : {}", r.host, r.raw_output);
            }
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
            let atk = cluster::cluster_attack_all(&nodes, &ts_compact, prob)
                .context("cluster_attack_all failed")?;
            for r in &atk {
                println!("  {} : {}", r.host, r.raw_output);
                writeln!(cf, "ATTACK|prob={prob}|{}", r.raw_output)?;
            }

            println!("[cluster] cluster_verify after prob={prob}...");
            let verif = cluster::cluster_verify_all(&nodes, &ts_compact)
                .context("cluster_verify_all failed")?;
            for r in &verif {
                println!("  {} : {}", r.host, r.raw_output);
                writeln!(cf, "VERIFY|prob={prob}|{}", r.raw_output)?;
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
                let setup_again = cluster::cluster_setup_all(&nodes, &ts_compact)
                    .context("cluster_setup_all retry failed")?;
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
                    let _ = cluster::bootstrap_data_all(&nodes);
                    // Then retry setup one more time
                    println!("[cluster] cluster_setup final retry after bootstrap...");
                    let setup_final = cluster::cluster_setup_all(&nodes, &ts_compact)
                        .context("cluster_setup_all final retry failed")?;
                    for r in &setup_final {
                        println!("    {} : {}", r.host, r.raw_output);
                    }
                }
            }
        }
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
    let exit_code = if multifs_result.is_some() { 0 } else { 1 };
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
