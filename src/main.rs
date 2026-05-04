//! beamfs-bench - unified bench harness for beamfs resilience testing.
//!
//! Replaces the legacy bash harness (Tir-*.sh, ~1176 lines) with a single
//! Rust binary exposing one subcommand per test scope.
//!
//! ## Subcommands (in this 0.2.0 release)
//!
//! - `version`  : print version + build info
//! - `multifs`  : multi-FS head-to-head bench (5 FS x 3 probs by default)
//!   with mandatory device validation prompt before mkfs.
//! - `analyse`  : multifs + forensic capture (3 scopes: quick/standard/full).
//!   Full scope = ftrace + perf + cluster-wide attack on the
//!   4 nodes (master + 3 computes).
//! - `full`     : VM lifecycle + cluster bootstrap + analyse scope=full.
//!   One-command autonomous bench. Required to pass before
//!   any commit/push (R0/R19 of context-recadrage).
//! - `metadata` : NOT YET IMPLEMENTED (Test A: superblock/inode/journal attack)
//! - `crash`    : NOT YET IMPLEMENTED (Test B: virsh destroy mid-write)
//! - `bitrot`   : NOT YET IMPLEMENTED (Test C: dd random on offline partition)
//! - `fsck`     : NOT YET IMPLEMENTED (Test D: e2fsck recovery post-FS_PANIC)
//!
//! ## Safety model (anti-NAK / R12 / R13 of context-recadrage)
//!
//! Before any mkfs/dd/destructive action, beamfs-bench runs a device
//! validation pipeline:
//!
//!   1. `virsh dumpxml <vm>` on the host (no sudo if user is in libvirt group).
//!   2. Parse XML, extract <source dev="..."/> for each virtio-blk target.
//!   3. Resolve symlinks to get the kernel device + size.
//!   4. Render a validation table with by-id paths.
//!   5. Prompt [y/N] (default = N = abort), unless --auto-confirm.
//!   6. Persist the validated mapping in <run_dir>/devices-validated.txt.
//!
//! For analyse --scope=full, beamfs-bench also discovers the cluster
//! topology via `discover_cluster` worker action and renders a per-node
//! state table BEFORE any cluster-wide destructive action.
//!
//! Author: Aurelien DESBRIERES <aurelien@hackers.camp>
//! License: GPL-2.0-only

use clap::{Parser, Subcommand, ValueEnum};

mod analyse;
mod bitrot;
mod bootstrap;
mod cluster;
mod code_analysis;
mod crash;
mod devices;
mod forensics;
mod forensics_host;
mod fsck;
mod lifecycle;
mod mega;
mod metadata;
mod multifs;
mod pipeline;
mod regression_check;
mod host_auth;
mod ssh;
mod synthesis;

const BEAMFS_BENCH_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "beamfs-bench",
    version = BEAMFS_BENCH_VERSION,
    about = "Unified bench harness for beamfs resilience testing",
    long_about = "Replaces the legacy bash harness (Tir-*.sh) with a single \
                  Rust binary. Each subcommand corresponds to one resilience \
                  test scope. Run `beamfs-bench help <subcommand>` for details."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print version and build info, then exit.
    Version,

    /// Multi-FS head-to-head bench under RadFI live injection.
    /// Targets 5 FS x 3 probabilities by default.
    /// REQUIRES: device validation prompt (or --auto-confirm).
    Multifs {
        /// Skip the [y/N] prompt and proceed (use only in CI / scripted runs).
        #[arg(long)]
        auto_confirm: bool,

        /// Render the device validation table and EXIT WITHOUT prompting.
        /// Useful to verify the mapping before a real run.
        #[arg(long)]
        dry_run: bool,
    },

    /// multifs + forensic capture (dmesg + RadFI + ftrace + perf + cluster).
    /// Three scopes available (--scope=quick|standard|full).
    Analyse {
        /// Forensic scope. Default = standard.
        #[arg(long, value_enum, default_value_t = ScopeArg::Standard)]
        scope: ScopeArg,

        /// Skip the device validation prompt.
        #[arg(long)]
        auto_confirm: bool,

        /// Render the validation table and EXIT WITHOUT prompting.
        #[arg(long)]
        dry_run: bool,

        /// Skip the final tar.gz archive generation.
        #[arg(long)]
        no_tarball: bool,

        /// Enable host-side bpftrace probes (requires NOPASSWD sudo on bpftrace).
        #[arg(long)]
        bpftrace: bool,
    },

    /// Full bench: VM lifecycle + cluster /data bootstrap + analyse --scope=full.
    /// One command, autonomous, deterministic. R0/R19: must exit 0 before any
    /// commit/push.
    Full {
        /// Skip the device validation prompt.
        #[arg(long)]
        auto_confirm: bool,
        /// Skip the final tar.gz archive generation.
        #[arg(long)]
        no_tarball: bool,
        /// Enable host-side bpftrace probes (requires NOPASSWD sudo on bpftrace).
        #[arg(long)]
        bpftrace: bool,
        /// Destroy VMs after bench (default: leave running).
        #[arg(long)]
        shutdown: bool,
        /// Assume cluster already up + /data mounted (skip lifecycle + bootstrap).
        /// Use only for repeated runs on a known-good cluster.
        #[arg(long)]
        skip_vm_bootstrap: bool,
        /// Skip the bitbake image rebuild (use existing canonical .ext2).
        /// Use when iterating on the pipeline itself; never skip in R19 production.
        #[arg(long)]
        skip_bitbake: bool,
        /// Run Tier 3 code analysis (Frama-C, scan-build, lcov). Heavy.
        #[arg(long)]
        full_code_analysis: bool,
        /// Bypass regression check with explicit reason. Empty rejected.
        #[arg(long)]
        accept_regression: Option<String>,
        /// Format cluster /data with mkfs.beamfs -O per_inode_rs (v5
        /// PER_INODE_RS feature flag, bit 8 of s_feat_incompat).
        /// Func-12 sub-3/sub-4: empirical activation of the decoupled
        /// per-inode RS protection on scheme=2 UNIVERSAL_INLINE volume.
        #[arg(long)]
        per_inode_rs: bool,
    },

    /// Test A - metadata-targeted attack (superblock, inode bitmap, journal).
    /// New scope, not in legacy harness.
    Metadata,

    /// Test B - crash consistency (virsh destroy mid-write + remount).
    /// New scope, not in legacy harness.
    Crash,

    /// Test C - bit-rot offline (dd random on offline partition, then read).
    /// New scope, not in legacy harness.
    Bitrot,

    /// Test D - fsck recovery post-FS_PANIC.
    /// New scope, not in legacy harness.
    Fsck,

    /// Test E - mega: pipeline + analyse Full + bitrot + metadata + crash + fsck.
    /// Consolidates everything into ONE tarball under /tmp/ for investigation.
    /// Captures Yocto build logs, kernel config, modinfo, git HEADs, and
    /// post-attack forensics (dmesg, radfi-counters, lsmod, ftrace, rs-journal SB).
    Mega,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScopeArg {
    /// 1 prob (saturation only), no ftrace, no perf, master only forensics.
    Quick,
    /// Default probs, no ftrace, no perf, all 4 nodes dmesg/radfi forensics.
    Standard,
    /// Default probs, ftrace + perf + cluster_setup/attack/verify on 4 nodes.
    Full,
}

impl ScopeArg {
    fn to_scope(self) -> forensics::Scope {
        match self {
            ScopeArg::Quick => forensics::Scope::Quick,
            ScopeArg::Standard => forensics::Scope::Standard,
            ScopeArg::Full => forensics::Scope::Full,
        }
    }
}

fn cmd_version() -> i32 {
    println!("beamfs-bench {}", BEAMFS_BENCH_VERSION);
    println!("license GPL-2.0-only");
    println!("status: full + multifs + analyse + bitrot + metadata + crash + fsck implemented");
    0
}

/// Configuration for cmd_full. Aggregates the 8 flags exposed by
/// `Command::Full` so the pipeline orchestrator does not run into
/// clippy::too_many_arguments and reads naturally for future flags.
struct FullConfig {
    auto_confirm: bool,
    no_tarball: bool,
    shutdown: bool,
    skip_vm_bootstrap: bool,
    skip_bitbake: bool,
    bpftrace: bool,
    full_code_analysis: bool,
    accept_regression: Option<String>,
    per_inode_rs: bool,
}

/// Full bench pipeline: lifecycle (VM up) + bootstrap (/data) + analyse scope=full.
/// R0/R19: exit 0 only when all phases complete cleanly.
fn cmd_full(cfg: FullConfig) -> anyhow::Result<i32> {
    use anyhow::Context;
    let FullConfig {
        auto_confirm, no_tarball, shutdown, skip_vm_bootstrap,
        skip_bitbake, bpftrace, full_code_analysis, accept_regression,
        per_inode_rs,
    } = cfg;

    println!("================================================================");
    println!(" beamfs-bench full - MIL no-NAK validation pipeline");
    println!("================================================================");

    let mut manifest = pipeline::build_initial_manifest()
        .context("manifest init")?;

    // Phase 0.0 -- R21 isolation architecture invariant
    if let Err(e) = pipeline::assert_isolation_r21() {
        return Err(pipeline::fail(&mut manifest, "0.0_isolation_r21", &e));
    }
    pipeline::record(&mut manifest, "0.0_isolation_r21", 0);

    // Phase 0.0bis -- MIL/kernel.org code analysis gate
    let code_analysis_mode = if full_code_analysis {
        code_analysis::AnalysisMode::Full
    } else {
        code_analysis::AnalysisMode::Incremental
    };
    let analysis_run_dir = std::path::PathBuf::from("/tmp/beamfs-bench-current-run");
    if let Err(e) = std::fs::create_dir_all(&analysis_run_dir)
        .map_err(|err| anyhow::anyhow!("create analysis dir: {err}"))
    {
        return Err(pipeline::fail(&mut manifest, "0.0bis_code_analysis", &e));
    }
    if let Err(e) = code_analysis::run(code_analysis_mode, &analysis_run_dir) {
        return Err(pipeline::fail(&mut manifest, "0.0bis_code_analysis", &e));
    }
    pipeline::record(&mut manifest, "0.0bis_code_analysis", 0);

    // Phase 0.1
    if let Err(e) = pipeline::verify_clean_working_trees() {
        return Err(pipeline::fail(&mut manifest, "0.1_clean_trees", &e));
    }
    pipeline::record(&mut manifest, "0.1_clean_trees", 0);

    // Phase 0.2
    let src_manifest = pipeline::verify_lockstep_sources()
        .map_err(|e| pipeline::fail(&mut manifest, "0.2_lockstep", &e))?;
    manifest.source_sha256 = src_manifest;
    pipeline::record(&mut manifest, "0.2_lockstep", 0);

    // Phase 0.3
    if let Err(e) = pipeline::bitbake_image(skip_bitbake) {
        return Err(pipeline::fail(&mut manifest, "0.3_bitbake", &e));
    }
    pipeline::record(&mut manifest, "0.3_bitbake", 0);

    // Phase 0.4
    let (ref_ko, ext2_sha) = pipeline::extract_reference_ko_sha()
        .map_err(|e| pipeline::fail(&mut manifest, "0.4_extract_ref", &e))?;
    manifest.reference_ko_sha256   = ref_ko.clone();
    manifest.canonical_ext2_sha256 = ext2_sha;
    pipeline::record(&mut manifest, "0.4_extract_ref", 0);

    // Phase 0.5
    if let Err(e) = pipeline::redeploy_4_vms() {
        return Err(pipeline::fail(&mut manifest, "0.5_redeploy", &e));
    }
    pipeline::record(&mut manifest, "0.5_redeploy", 0);

    // Phase 0.6 -- reuse lifecycle wait_ssh_ready_parallel
    if let Err(e) = lifecycle::wait_ssh_ready_parallel() {
        return Err(pipeline::fail(&mut manifest, "0.6_ssh_ready", &e));
    }
    pipeline::record(&mut manifest, "0.6_ssh_ready", 0);

    // Phase 0.7
    let in_vm_shas = pipeline::verify_module_identity_in_vm(&ref_ko)
        .map_err(|e| pipeline::fail(&mut manifest, "0.7_identity", &e))?;
    manifest.in_vm_ko_sha256 = in_vm_shas;
    pipeline::record(&mut manifest, "0.7_identity", 0);

    // Phase 1 lifecycle (legacy bring_cluster_up) is fully absorbed by
    // pipeline phases 0.0/0.5/0.6; no separate legacy invocation needed.
    if skip_vm_bootstrap {
        println!("[full] WARNING: --skip-vm-bootstrap given but pipeline already redeployed VMs in Phase 0.5");
    }

    println!();
    println!("[full] Pre-deploying worker on all 4 nodes...");
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
    let deploys = cluster::deploy_worker_all(&bootstrap_nodes)
        .context("worker deploy")?;
    for (host, r) in &deploys {
        match r {
            Ok(()) => println!("  {host} : worker deployed"),
            Err(e) => return Err(anyhow::anyhow!("worker deploy failed on {host}: {e:#}")),
        }
    }

    println!();
    println!("[full] Discovering cluster topology...");
    let nodes = cluster::discover_cluster().context("cluster discovery")?;
    let table = cluster::render_cluster_table(&nodes);
    print!("{table}");

    if !skip_vm_bootstrap {
        bootstrap::bootstrap_all_data(&nodes, per_inode_rs).context("Phase 2 bootstrap failed")?;

        println!();
        println!("[full] Re-discovering topology post-bootstrap...");
        let nodes2 = cluster::discover_cluster().context("cluster re-discovery")?;
        let table2 = cluster::render_cluster_table(&nodes2);
        print!("{table2}");
    } else {
        println!("[full] Phase 2 skipped (--skip-vm-bootstrap)");
    }

    println!();
    println!("[full] Phase 3-7: handing off to analyse --scope=full");
    let cfg = analyse::AnalyseConfig {
        scope: forensics::Scope::Full,
        auto_confirm,
        dry_run: false,
        make_tarball: !no_tarball,
        vm_name: multifs::DEFAULT_VM_NAME.to_string(),
        bpftrace_host: bpftrace,
    };
    let analyse_rc = analyse::run(&cfg).context("analyse phase failed")?;

    if shutdown {
        println!();
        lifecycle::bring_cluster_down().context("shutdown phase failed")?;
    }

    // Phase 8.1
    if let Err(e) = pipeline::verify_dmesg_clean() {
        return Err(pipeline::fail(&mut manifest, "8.1_dmesg", &e));
    }
    pipeline::record(&mut manifest, "8.1_dmesg", 0);

    // Phase 8.2
    manifest.overall_rc  = analyse_rc;
    manifest.finished_at = pipeline::now_iso();
    let _ = pipeline::emit_manifest(&manifest);

    // Phase 8.3 -- regression check vs baseline (R7 canonical pre-push)
    // Skipped if bench was not functionally OK; pointless to compare a
    // crashed run.
    if analyse_rc == 0 {
        let regression_dir = std::path::PathBuf::from("/tmp/beamfs-bench-current-run");
        if let Err(e) = regression_check::run(&regression_dir, accept_regression.clone()) {
            return Err(pipeline::fail(&mut manifest, "8.3_regression_check", &e));
        }
        pipeline::record(&mut manifest, "8.3_regression_check", 0);
        let _ = pipeline::emit_manifest(&manifest);
    }

    println!();
    println!("================================================================");
    println!(" beamfs-bench full complete - exit code {analyse_rc}");
    println!("================================================================");
    Ok(analyse_rc)
}

fn main() {
    let cli = Cli::parse();

    // Session priming : sudo + GPG + ssh-agent caches populated once,
    // refreshed by keep-alive thread for the lifetime of the process.
    // Skipped for Version subcommand which performs no privileged I/O.
    if !matches!(cli.command, Command::Version) {
        if let Err(e) = host_auth::prime_session() {
            eprintln!("beamfs-bench: session priming failed: {e:#}");
            std::process::exit(1);
        }
    }

    let rc = match cli.command {
        Command::Version => cmd_version(),

        Command::Multifs { auto_confirm, dry_run } => {
            match multifs::run(auto_confirm, dry_run) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: multifs failed: {e:#}");
                    1
                }
            }
        }

        Command::Analyse { scope, auto_confirm, dry_run, no_tarball, bpftrace } => {
            let cfg = analyse::AnalyseConfig {
                scope: scope.to_scope(),
                auto_confirm,
                dry_run,
                make_tarball: !no_tarball,
                vm_name: multifs::DEFAULT_VM_NAME.to_string(),
                bpftrace_host: bpftrace,
            };
            match analyse::run(&cfg) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: analyse failed: {e:#}");
                    1
                }
            }
        }

        Command::Full { auto_confirm, no_tarball, shutdown, skip_vm_bootstrap, skip_bitbake, bpftrace, full_code_analysis, accept_regression, per_inode_rs } => {
            let cfg = FullConfig {
                auto_confirm, no_tarball, shutdown, skip_vm_bootstrap,
                skip_bitbake, bpftrace, full_code_analysis, accept_regression,
                per_inode_rs,
            };
            match cmd_full(cfg) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: full failed: {e:#}");
                    1
                }
            }
        }
        Command::Metadata => {
            match metadata::run() {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: metadata failed: {e:#}");
                    1
                }
            }
        }
        Command::Crash => {
            match crash::run() {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: crash failed: {e:#}");
                    1
                }
            }
        }
        Command::Bitrot => {
            match bitrot::run() {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: bitrot failed: {e:#}");
                    1
                }
            }
        }
        Command::Fsck => {
            match fsck::run() {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: fsck failed: {e:#}");
                    1
                }
            }
        }
        Command::Mega => {
            match mega::run() {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: mega failed: {e:#}");
                    1
                }
            }
        }
    };
    std::process::exit(rc);
}
