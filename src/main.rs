//! beamfs-bench - unified bench harness for beamfs resilience testing.
//!
//! Replaces the legacy bash harness (Tir-*.sh, ~1176 lines) with a single
//! Rust binary exposing one subcommand per test scope.
//!
//! ## Subcommands (in this 0.2.0 release)
//!
//! - `version`  : print version + build info
//! - `multifs`  : multi-FS head-to-head bench (2 FS x 3 probs by default)
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
//! - `tindirect`: triple-indirect addressing round-trip (Test F, sparse write)
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

mod bell;
mod analyse;
mod bitrot;
mod bootstrap;
mod bpf;
mod chain;
mod cluster;
mod db;
mod code_analysis;
mod crash;
mod devices;
mod forensics;
mod forensics_host;
mod fsck;
mod lab;
mod lifecycle;
mod mega;
mod metadata;
mod multifs;
mod pipeline;
mod regression_check;
mod host_auth;
mod scrub;
mod ssh;
mod synthesis;
mod tindirect;
mod usb_health;
mod perf;
mod dose;

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

    /// Which chain this run belongs to: qemux86-64 or qemuarm64.
    ///
    /// The two architectures are two validation chains, each sealed
    /// end to end, run together or one without the other. This names
    /// one for a single run; BEAMFS_BENCH_MACHINE does the same for a
    /// whole shell. The build directory and the canonical image path
    /// follow from it, so there is no second value to keep in step.
    #[arg(long, global = true, value_name = "MACHINE")]
    machine: Option<String>,

    /// Stay quiet when the run finishes.
    ///
    /// A campaign runs for the better part of an hour and ends in a
    /// terminal nobody is watching, so it rings until Return is
    /// pressed. Pass this when the run is chained into another, or
    /// driven by a scheduler, or reached over a connection where the
    /// sound would come out of the wrong machine.
    ///
    /// BEAMFS_NO_BELL does the same for a whole shell.
    #[arg(long, global = true)]
    no_bell: bool,

    /// emufi 0.3.2 attack-tuning flags. v0.8.0 expansion.
    /// Every flag here is GLOBAL: accepted on any subcommand, applied
    /// uniformly. Each flag, when present, is exported to the process
    /// environment so `cluster::worker_cmd()` forwards it to worker.sh
    /// which pushes the value to the matching debugfs entry IFF the
    /// entry exists on the target injector (sudo test -e guard).
    /// All flags are CUMULATIVE SIMULTANEOUS: any combination is valid.
    /// Flags without a matching debugfs entry are silently ignored.
    #[command(flatten)]
    attack: EmufiAttackArgs,
}

/// Cumulative attack-tuning options exposed by emufi 0.3.2 debugfs.
/// All optional. None of these conflict with any other; combining them
/// is the supported usage pattern (e.g. `multi_chip` + `codeword_size_bytes`
/// + `sefi_probability` + `burst_symbols` in a single attack).
#[derive(clap::Args, Debug, Default)]
struct EmufiAttackArgs {
    // ---- v0.7.x baseline flags promoted from env-var-only to CLI ----
    /// Number of bits flipped per event (MBU width). emufi entry: `flip_width`.
    #[arg(long, value_name = "U32", global = true)]
    flip_width: Option<u32>,
    /// LET intensity bucket (0=LOW 1=MEDIUM 2=HIGH 3=EXTREME).
    /// emufi entry: `let_class`. Baumann 2005 / JEDEC JEP89 calibrated.
    #[arg(long, value_name = "U8", global = true)]
    let_class: Option<u8>,
    /// Spatial flip pattern: RANDOM | CONSECUTIVE | EXACT. emufi entry: `flip_locality`.
    #[arg(long, value_name = "STR", global = true)]
    flip_locality: Option<String>,
    /// Symbols per burst (RS codeword targeting). emufi entry: `burst_symbols`.
    #[arg(long, value_name = "U8", global = true)]
    burst_symbols: Option<u8>,
    /// On-disk struct selector (1=SUPERBLOCK `2=INODE_TABLE` `3=ROOT_DIR`
    /// `4=INODE_BITMAP` `5=DATA_BLOCK`). emufi entry: `target_struct`.
    #[arg(long, value_name = "U8", global = true)]
    target_struct: Option<u8>,
    /// Block number within the target structure. emufi entry: `target_struct_block_no`.
    #[arg(long, value_name = "U32", global = true)]
    target_struct_block_no: Option<u32>,
    /// SEFI per-event probability (ppm). emufi entry: `sefi_probability`.
    #[arg(long, value_name = "PPM", global = true)]
    sefi_probability: Option<u32>,
    /// SEFI persistence window (ms). emufi entry: `sefi_window_ms`.
    #[arg(long, value_name = "MS", global = true)]
    sefi_window_ms: Option<u32>,
    /// Phase A.5: number of raw direct-I/O reads on block 0 during
    /// attack window (SB-targeted I/O burst). Only effective when
    /// --target-struct=1. Calibration: 200 = probable saturation,
    /// 500 = statistical certainty (RS journal 1535 bytes /
    /// 40-byte sub-blocks). Without this flag, only 1-3 natural
    /// SB reads occur per attack, insufficient to saturate.
    #[arg(long, value_name = "U32", global = true)]
    sb_read_loops: Option<u32>,

    // ---- v0.8.0 additions: rest of the emufi 0.3.2 surface ----
    /// Byte offset within the target struct block. emufi entry: `target_struct_offset`.
    #[arg(long, value_name = "U32", global = true)]
    target_struct_offset: Option<u32>,
    /// Inode-aware FS targeting (FS-level hook required). emufi entry: `target_inode`.
    #[arg(long, value_name = "U64", global = true)]
    target_inode: Option<u64>,
    /// Enable FS-level hook in addition to blk-level. emufi entry: `hook_fs`.
    #[arg(long, global = true)]
    hook_fs: bool,
    /// Multi-segment burst (event spans non-contiguous segments).
    /// emufi entry: `multi_segment`.
    #[arg(long, global = true)]
    multi_segment: bool,
    /// Multi-chip injection realism (event distributed over `chip_count` chips).
    /// emufi entry: `multi_chip`.
    #[arg(long, global = true)]
    multi_chip: bool,
    /// Number of chips when `multi_chip=1`. emufi entry: `chip_count`.
    #[arg(long, value_name = "U8", global = true)]
    chip_count: Option<u8>,
    /// MBU width sampling mode. emufi entry: `width_mode`.
    #[arg(long, value_name = "U8", global = true)]
    width_mode: Option<u8>,
    /// Stride between flips in a burst (intra-burst spacing).
    /// emufi entry: `flip_stride_bits`.
    #[arg(long, value_name = "U8", global = true)]
    flip_stride_bits: Option<u8>,
    /// RS codeword size in bytes (FEC-aware targeting). emufi entry: `codeword_size_bytes`.
    #[arg(long, value_name = "U32", global = true)]
    codeword_size_bytes: Option<u32>,
    /// RS codeword alignment in bytes. emufi entry: `codeword_align_bytes`.
    #[arg(long, value_name = "U32", global = true)]
    codeword_align_bytes: Option<u32>,
    /// Reseed the injector PRNG (write-only command, fresh seed).
    /// emufi entry: reseed.
    #[arg(long, value_name = "U64", global = true)]
    reseed: Option<u64>,
}

impl EmufiAttackArgs {
    /// Export every set flag to the process environment so that
    /// `cluster::worker_cmd()` picks them up and forwards them via SSH.
    /// Boolean flags are exported as "1" when true (and not exported
    /// when false, leaving the kernel default in place).
    fn export_to_env(&self) {
        // Macro-free table-driven export. Each (var_name, formatter)
        // pair maps an Option<T> field to the corresponding env var.
        if let Some(v) = self.flip_width { std::env::set_var("FLIP_WIDTH", v.to_string()); }
        if let Some(v) = self.let_class { std::env::set_var("LET_CLASS", v.to_string()); }
        if let Some(v) = self.flip_locality.as_ref() { std::env::set_var("FLIP_LOCALITY", v); }
        if let Some(v) = self.burst_symbols { std::env::set_var("BURST_SYMBOLS", v.to_string()); }
        if let Some(v) = self.target_struct { std::env::set_var("TARGET_STRUCT", v.to_string()); }
        if let Some(v) = self.target_struct_block_no { std::env::set_var("TARGET_STRUCT_BLOCK_NO", v.to_string()); }
        if let Some(v) = self.sefi_probability { std::env::set_var("SEFI_PROBABILITY", v.to_string()); }
        if let Some(v) = self.sefi_window_ms { std::env::set_var("SEFI_WINDOW_MS", v.to_string()); }
        if let Some(v) = self.sb_read_loops { std::env::set_var("SB_READ_LOOPS", v.to_string()); }
        if let Some(v) = self.target_struct_offset { std::env::set_var("TARGET_STRUCT_OFFSET", v.to_string()); }
        if let Some(v) = self.target_inode { std::env::set_var("TARGET_INODE", v.to_string()); }
        if self.hook_fs { std::env::set_var("HOOK_FS", "1"); }
        if self.multi_segment { std::env::set_var("MULTI_SEGMENT", "1"); }
        if self.multi_chip { std::env::set_var("MULTI_CHIP", "1"); }
        if let Some(v) = self.chip_count { std::env::set_var("CHIP_COUNT", v.to_string()); }
        if let Some(v) = self.width_mode { std::env::set_var("WIDTH_MODE", v.to_string()); }
        if let Some(v) = self.flip_stride_bits { std::env::set_var("FLIP_STRIDE_BITS", v.to_string()); }
        if let Some(v) = self.codeword_size_bytes { std::env::set_var("CODEWORD_SIZE_BYTES", v.to_string()); }
        if let Some(v) = self.codeword_align_bytes { std::env::set_var("CODEWORD_ALIGN_BYTES", v.to_string()); }
        if let Some(v) = self.reseed { std::env::set_var("RESEED", v.to_string()); }
    }
}

#[derive(Subcommand)]
enum DbAction {
    /// Ingest every archived run directory not already recorded.
    Ingest {
        /// Root holding beamfs-bench-multifs-* directories.
        #[arg(long)]
        runs_dir: Option<String>,
    },
    /// Dose-response over usable measurements only.
    DoseResponse,
    /// Exposure actually achieved per filesystem, with validity verdict.
    Exposure,
    /// Why measurements were rejected, and how many.
    Validity,
    /// Drop runs older than N days, keeping their aggregates.
    Purge {
        #[arg(long, default_value = "90")]
        older_than_days: u32,
    },
}

#[derive(Subcommand)]
enum Command {
    /// Print version and build info, then exit.
    Version,

    /// Multi-FS head-to-head bench under `RadFI` live injection.
    /// Targets 2 FS x 3 probabilities by default.
    /// REQUIRES: device validation prompt (or --auto-confirm).
    Multifs {
        /// Skip the [y/N] prompt and proceed (use only in CI / scripted runs).
        #[arg(long)]
        auto_confirm: bool,

        /// Render the device validation table and EXIT WITHOUT prompting.
        /// Useful to verify the mapping before a real run.
        #[arg(long)]
        dry_run: bool,

        /// Fault injector. Only "emufi" is supported since radfi was
        /// "emufi" (MBU-capable successor, ref Zenodo DOI
        /// removed (Zenodo DOI 10.5281/zenodo.20041762).
        #[arg(long, default_value = "emufi")]
        injector: String,
    },

    /// Performance characterisation of every filesystem, in two
    /// regimes.
    ///
    /// `nominal` measures what the on-disk format costs; `correcting`
    /// measures the filesystem while the injector runs, which is what
    /// it costs doing the work it exists for. The gap between them is
    /// what resilience costs, and it is the figure that sizes a
    /// deployment -- a system under radiation keeps serving while
    /// upsets arrive.
    Perf {
        /// Which regimes to measure. Nominal first so a correcting run
        /// cannot leave the injector armed under a clean measurement.
        #[arg(long, default_value = "nominal,correcting")]
        regimes: String,
        /// Injection probability in ppm, correcting regime only.
        #[arg(long, default_value_t = 100_000)]
        prob: u32,
        /// Seconds per fio job.
        #[arg(long, default_value_t = 20)]
        runtime: u32,
        /// Working set per job.
        #[arg(long, default_value = "64M")]
        size: String,
        /// Fault injector. Only "emufi" is supported.
        #[arg(long, default_value = "emufi")]
        injector: String,
    },
    /// multifs + forensic capture (dmesg + `RadFI` + ftrace + perf + cluster).
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

        /// Fault injector. Only "emufi" is supported.
        #[arg(long, default_value = "emufi")]
        injector: String,

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
        /// Fault injector. Only "emufi" is supported.
        #[arg(long, default_value = "emufi")]
        injector: String,
        /// Destroy VMs after bench (default: leave running).
        #[arg(long)]
        shutdown: bool,
        /// Assume cluster already up + /data mounted (skip lifecycle + bootstrap).
        /// Use only for repeated runs on a known-good cluster.
        #[arg(long)]
        skip_vm_bootstrap: bool,
        /// Skip the bitbake image rebuild (use existing canonical .beamfs).
        /// Use when iterating on the pipeline itself; never skip in R19 production.
        #[arg(long)]
        skip_bitbake: bool,
        /// Run Tier 3 code analysis (Frama-C, scan-build, lcov). Heavy.
        #[arg(long)]
        full_code_analysis: bool,
        /// Bypass regression check with explicit reason. Empty rejected.
        #[arg(long)]
        accept_regression: Option<String>,
        /// Format cluster /data with mkfs.beamfs -O `per_inode_rs` (v5
        /// `PER_INODE_RS` feature flag, bit 8 of `s_feat_incompat`).
        /// Func-12 sub-3/sub-4: empirical activation of the decoupled
        /// per-inode RS protection on scheme=2 `UNIVERSAL_INLINE` volume.
        #[arg(long)]
        per_inode_rs: bool,
    },

    /// Test A - metadata-targeted attack (superblock, inode bitmap, journal).
    /// New scope, not in legacy harness.
    Metadata {
        /// Fault injector. Only "emufi" is supported.
        #[arg(long, default_value = "emufi")]
        injector: String,
    },

    /// Test B - crash consistency (virsh destroy mid-write + remount).
    /// New scope, not in legacy harness.
    Crash {
        /// Fault injector. Only "emufi" is supported.
        #[arg(long, default_value = "emufi")]
        injector: String,
    },

    /// Test G - scrubber under dose: does it repair, and does its rate
    /// follow what it finds? Observes without reading the data, so only
    /// the scrubber can act.
    Scrub {
        /// Deployment whose exposure sets the injection size.
        #[arg(long, default_value = "medical-linac-vault")]
        deployment: String,

        /// Sweeps to observe after injection.
        #[arg(long, default_value_t = 12)]
        sweeps: u64,
    },

    /// Test C - bit-rot offline (dd random on offline partition, then read).
    /// New scope, not in legacy harness.
    Bitrot {
        /// Fault injector. Only "emufi" is supported.
        #[arg(long, default_value = "emufi")]
        injector: String,
    },

    /// Test D - fsck recovery post-FS_PANIC.
    /// New scope, not in legacy harness.
    /// Measurement database: retroactive ingest of archived runs, and
    /// queries over the accumulated series.
    Db {
        #[command(subcommand)]
        action: DbAction,
    },

    Fsck {
        /// Fault injector. Only "emufi" is supported.
        #[arg(long, default_value = "emufi")]
        injector: String,
    },

    /// Test F - tindirect: triple-indirect addressing round-trip.
    /// Sparse writes at iblocks crossing dindirect->tindirect frontier,
    /// then sync + `drop_caches` + remount + read-verify byte-identical.
    /// No fault injection; validates addressing math + bounds checks.
    Tindirect {
        /// Fault injector to use (kept for worker.sh module-loading uniformity).
        #[arg(long, default_value = "emufi")]
        injector: String,
    },

    /// Attach a bpftrace script while something happens, on a node or
    /// on the station.
    ///
    /// Every other scope reads state after the fact. This one watches a
    /// sequence -- a pointer installed and read back as zero by another
    /// task -- which is the shape of every defect still open.
    ///
    /// The scripts live in beamfs-xfstests under scripts/ and are found
    /// by name; --list says which ones and what each watches.
    Trace {
        /// Script name, with or without its .bt suffix.
        #[arg(long, default_value = "lostptr")]
        script: String,

        /// host, or a cluster node by name or address.
        #[arg(long, default_value = "compute01")]
        target: String,

        /// How long to keep the probe attached.
        #[arg(long, default_value_t = 60)]
        seconds: u64,

        /// List the scripts found and exit.
        #[arg(long)]
        list: bool,
    },

    /// Test E - mega: pipeline + analyse Full + bitrot + metadata + crash + fsck.
    /// Consolidates everything into ONE tarball under /tmp/ for investigation.
    /// Captures Yocto build logs, kernel config, modinfo, git HEADs, and
    /// post-attack forensics (dmesg, radfi-counters, lsmod, ftrace, rs-journal SB).
    Mega {
        /// Fault injector. Only "emufi" is supported.
        #[arg(long, default_value = "emufi")]
        injector: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScopeArg {
    /// 1 prob (saturation only), no ftrace, no perf, master only forensics.
    Quick,
    /// Default probs, no ftrace, no perf, all 4 nodes dmesg/radfi forensics.
    Standard,
    /// Default probs, ftrace + perf + `cluster_setup/attack/verify` on 4 nodes.
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
    println!("beamfs-bench {BEAMFS_BENCH_VERSION}");
    println!("license GPL-2.0-only");
    println!("status: full + multifs + analyse + bitrot + metadata + crash + fsck implemented");
    0
}

/// Configuration for `cmd_full`. Aggregates the 8 flags exposed by
/// `Command::Full` so the pipeline orchestrator does not run into
/// `clippy::too_many_arguments` and reads naturally for future flags.
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
    injector: String,
}

/// Full bench pipeline: lifecycle (VM up) + bootstrap (/data) + analyse scope=full.
/// R0/R19: exit 0 only when all phases complete cleanly.
fn cmd_full(cfg: FullConfig) -> anyhow::Result<i32> {
    use anyhow::Context;
    let FullConfig {
        auto_confirm, no_tarball, shutdown, skip_vm_bootstrap,
        skip_bitbake, bpftrace, full_code_analysis, accept_regression,
        per_inode_rs, injector,
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

    // Phase 0.0a -- USB pre-flight (host-side block device audit)
    let usb_verdicts = match usb_health::run() {
        Ok(v) => v,
        Err(e) => return Err(pipeline::fail(&mut manifest, "0.0a_usb_health", &e)),
    };
    pipeline::record(&mut manifest, "0.0a_usb_health", 0);

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
    let beamfs_sha = pipeline::canonical_image_sha()
        .map_err(|e| pipeline::fail(&mut manifest, "0.4_extract_ref", &e))?;
    pipeline::record(&mut manifest, "0.4_extract_ref", 0);

    // Phase 0.4bis -- this bench is the second half of a BX campaign
    // or it is not part of one. See chain.rs.
    match pipeline::verify_chain_seal(&beamfs_sha) {
        Ok((verdict, seal)) => {
            manifest.chain_verdict = format!("{verdict:?}");
            manifest.chain_seal = seal;
            pipeline::record(&mut manifest, "0.4bis_chain_seal", 0);
        }
        Err(e) => return Err(pipeline::fail(&mut manifest, "0.4bis_chain_seal", &e)),
    }
    manifest.canonical_beamfs_sha256 = beamfs_sha;

    // Phase 0.5
    match pipeline::redeploy_4_vms() {
        Ok(resolved) => {
            manifest.resolved_vda_paths = resolved;
        }
        Err(e) => return Err(pipeline::fail(&mut manifest, "0.5_redeploy", &e)),
    }
    pipeline::record(&mut manifest, "0.5_redeploy", 0);

    // Phase 0.6 -- reuse lifecycle wait_ssh_ready_parallel
    if let Err(e) = lifecycle::wait_ssh_ready_parallel() {
        return Err(pipeline::fail(&mut manifest, "0.6_ssh_ready", &e));
    }
    pipeline::record(&mut manifest, "0.6_ssh_ready", 0);

    // Phase 0.7
    let stamps = pipeline::verify_kernel_identity_in_vm()
        .map_err(|e| pipeline::fail(&mut manifest, "0.7_identity", &e))?;
    manifest.in_vm_kernel_stamp = stamps;
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

    if skip_vm_bootstrap {
        println!("[full] Phase 2 skipped (--skip-vm-bootstrap)");
    } else {
        bootstrap::bootstrap_all_data(&nodes, per_inode_rs, &injector).context("Phase 2 bootstrap failed")?;

        println!();
        println!("[full] Re-discovering topology post-bootstrap...");
        let nodes2 = cluster::discover_cluster().context("cluster re-discovery")?;
        let table2 = cluster::render_cluster_table(&nodes2);
        print!("{table2}");
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
        injector: injector.clone(),
        usb_verdicts: usb_verdicts.clone(),
    };
    let analyse_rc = analyse::run(&cfg).context("analyse phase failed")?;

    if shutdown {
        println!();
        lifecycle::bring_cluster_down();
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
        if let Err(e) = regression_check::run(&regression_dir, accept_regression.as_deref()) {
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

    // Before anything reads a path: the accessors in lab.rs memoise on
    // first call, so a machine settled later would arrive after the
    // paths it was meant to change.
    if let Some(m) = cli.machine.as_deref() {
        let m = m.trim();
        if m.is_empty() {
            eprintln!("--machine needs a value, for instance qemux86-64 or qemuarm64");
            std::process::exit(2);
        }
        unsafe { std::env::set_var("BEAMFS_BENCH_MACHINE", m) };
    }

    // v0.8.0: cumulative-simultaneous emufi 0.3.2 attack flags.
    // Export to process env BEFORE any subcommand dispatches, so
    // that cluster::worker_cmd's std::env::var(...) picks them up.
    cli.attack.export_to_env();

    // Session priming : sudo + GPG + ssh-agent caches populated once,
    // refreshed by keep-alive thread for the lifetime of the process.
    // Skipped for Version subcommand which performs no privileged I/O.
    if !matches!(cli.command, Command::Version) {
        if let Err(e) = host_auth::prime_session() {
            eprintln!("beamfs-bench: session priming failed: {e:#}");
            std::process::exit(1);
        }
    }

    // Noted before the match consumes it: version returns at once and
    // ringing after it would only be noise.
    let worth_ringing = !matches!(cli.command, Command::Version);

    let rc = match cli.command {
        Command::Version => cmd_version(),

        Command::Perf { regimes, prob, runtime, size, injector } => {
            std::env::set_var("PERF_RUNTIME", runtime.to_string());
            std::env::set_var("PERF_SIZE", &size);

            let usb_verdicts = match usb_health::run() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("beamfs-bench: USB pre-flight failed: {e:#}");
                    std::process::exit(1);
                }
            };
            let fs_mapping = usb_health::build_fs_mapping(&usb_verdicts);
            if fs_mapping.is_empty() {
                eprintln!("beamfs-bench: no healthy USB slots, perf cannot run");
                std::process::exit(1);
            }
            let cfg = perf::PerfConfig {
                fs_list: fs_mapping,
                ssh_user: crate::lab::ssh_user().to_string(),
                master_ip: "192.168.56.11".to_string(),
                ssh_key_path: crate::lab::ssh_key().to_string(),
                injector,
                prob,
                regimes: regimes.split(',').map(|r| r.trim().to_string()).collect(),
            };
            match perf::run(&cfg) {
                Ok(rows) => {
                    let db = db::default_db_path();
                    let cmd = std::env::args().collect::<Vec<_>>().join(" ");
                    match db::init(&db)
                        .and_then(|()| db::open_perf_run(&db, &cmd, env!("CARGO_PKG_VERSION")))
                        .and_then(|id| db::ingest_perf(&db, id, &rows))
                    {
                        Ok(n) => println!("\n  {n} measurements stored in {}", db.display()),
                        Err(e) => eprintln!("\n  {} measurements, ingest failed: {e:#}", rows.len()),
                    }
                    0
                }
                Err(e) => {
                    eprintln!("beamfs-bench: perf failed: {e:#}");
                    1
                }
            }
        }

        Command::Multifs { auto_confirm, dry_run, injector } => {
            // L5 : also probe USB health when Multifs is invoked standalone.
            let usb_verdicts = match usb_health::run() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("beamfs-bench: USB pre-flight failed: {e:#}");
                    std::process::exit(1);
                }
            };
            let fs_mapping = usb_health::build_fs_mapping(&usb_verdicts);
            if fs_mapping.is_empty() {
                eprintln!("beamfs-bench: no healthy USB slots, multifs cannot run");
                std::process::exit(1);
            }
            match multifs::run_with_mapping(auto_confirm, dry_run, &injector, fs_mapping) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: multifs failed: {e:#}");
                    1
                }
            }
        }

        Command::Analyse { scope, auto_confirm, dry_run, no_tarball, bpftrace, injector } => {
            // L5 : Analyse standalone also probes USBs.
            let usb_verdicts = match usb_health::run() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("beamfs-bench: USB pre-flight failed: {e:#}");
                    std::process::exit(1);
                }
            };
            let cfg = analyse::AnalyseConfig {
                scope: scope.to_scope(),
                auto_confirm,
                injector,
                dry_run,
                make_tarball: !no_tarball,
                vm_name: multifs::DEFAULT_VM_NAME.to_string(),
                bpftrace_host: bpftrace,
                usb_verdicts,
            };
            match analyse::run(&cfg) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: analyse failed: {e:#}");
                    1
                }
            }
        }

        Command::Full { auto_confirm, no_tarball, shutdown, skip_vm_bootstrap, skip_bitbake, bpftrace, full_code_analysis, accept_regression, per_inode_rs, injector } => {
            let cfg = FullConfig {
                auto_confirm, no_tarball, shutdown, skip_vm_bootstrap,
                skip_bitbake, bpftrace, full_code_analysis, accept_regression,
                per_inode_rs, injector,
            };
            match cmd_full(cfg) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: full failed: {e:#}");
                    1
                }
            }
        }
        Command::Metadata { injector } => {
            match metadata::run(&injector) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: metadata failed: {e:#}");
                    1
                }
            }
        }
        Command::Crash { injector } => {
            match crash::run(&injector) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: crash failed: {e:#}");
                    1
                }
            }
        }
        Command::Scrub { deployment, sweeps } => {
            match scrub::run_cli(&deployment, sweeps) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: scrub failed: {e:#}");
                    1
                }
            }
        }
        Command::Bitrot { injector } => {
            match bitrot::run(&injector) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: bitrot failed: {e:#}");
                    1
                }
            }
        }
        Command::Db { action } => {
            let rc = match action {
                DbAction::Ingest { runs_dir } => db::cmd_ingest(runs_dir.as_deref()),
                DbAction::DoseResponse => db::cmd_query(db::Query::DoseResponse),
                DbAction::Exposure => db::cmd_query(db::Query::Exposure),
                DbAction::Validity => db::cmd_query(db::Query::Validity),
                DbAction::Purge { older_than_days } => db::cmd_purge(older_than_days),
            };
            match rc {
                Ok(c) => c,
                Err(e) => { eprintln!("beamfs-bench: db: {e:#}"); 1 }
            }
        }
        Command::Fsck { injector } => {
            match fsck::run(&injector) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: fsck failed: {e:#}");
                    1
                }
            }
        }
        Command::Tindirect { injector } => {
            match tindirect::run(&injector) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: tindirect failed: {e:#}");
                    1
                }
            }
        }
        Command::Trace { script, target, seconds, list } => {
            match bpf::run_cli(&script, &target, seconds, list) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: trace failed: {e:#}");
                    1
                }
            }
        }
        Command::Mega { injector } => {
            match mega::run(&injector) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: mega failed: {e:#}");
                    1
                }
            }
        }
    };

    // Ring, except after version, which returns at once and would only
    // be noise. A full pipeline runs for the better part of an hour and
    // ends in a terminal nobody is watching.
    if worth_ringing && !cli.no_bell {
        bell::ring_until_acknowledged();
    }
    std::process::exit(rc);
}
