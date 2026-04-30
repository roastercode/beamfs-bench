//! beamfs-bench — unified bench harness for beamfs resilience testing.
//!
//! Replaces the legacy bash harness (Tir-*.sh, ~1176 lines) with a single
//! Rust binary exposing one subcommand per test scope.
//!
//! ## Subcommands (in this 0.2.0 release)
//!
//! - `version`  : print version + build info
//! - `multifs`  : multi-FS head-to-head bench (5 FS x 3 probs by default)
//!                with mandatory device validation prompt before mkfs.
//! - `analyse`  : multifs + forensic capture (3 scopes: quick/standard/full).
//!                Full scope = ftrace + perf + cluster-wide attack on the
//!                4 nodes (master + 3 computes).
//! - `bench`    : NOT YET IMPLEMENTED (port of Tir.sh / hpc-benchmark-beamfs.sh)
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
mod cluster;
mod devices;
mod forensics;
mod multifs;
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
    },

    /// Cluster I/O performance baseline (M1-M5 metrics, multi-node).
    /// (Port of legacy Tir.sh / hpc-benchmark-beamfs.sh.)
    Bench,

    /// Test A — metadata-targeted attack (superblock, inode bitmap, journal).
    /// New scope, not in legacy harness.
    Metadata,

    /// Test B — crash consistency (virsh destroy mid-write + remount).
    /// New scope, not in legacy harness.
    Crash,

    /// Test C — bit-rot offline (dd random on offline partition, then read).
    /// New scope, not in legacy harness.
    Bitrot,

    /// Test D — fsck recovery post-FS_PANIC.
    /// New scope, not in legacy harness.
    Fsck,
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
    println!("status: multifs + analyse implemented; bench/metadata/crash/bitrot/fsck pending");
    0
}

fn cmd_not_yet_implemented(name: &str) -> i32 {
    eprintln!("beamfs-bench: subcommand `{name}` not yet implemented");
    eprintln!("beamfs-bench: see context/TODO.md (TODO 2) in beamfs-devel for the migration plan");
    2
}

fn main() {
    let cli = Cli::parse();
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

        Command::Analyse { scope, auto_confirm, dry_run, no_tarball } => {
            let cfg = analyse::AnalyseConfig {
                scope: scope.to_scope(),
                auto_confirm,
                dry_run,
                make_tarball: !no_tarball,
                vm_name: multifs::DEFAULT_VM_NAME.to_string(),
            };
            match analyse::run(&cfg) {
                Ok(rc) => rc,
                Err(e) => {
                    eprintln!("beamfs-bench: analyse failed: {e:#}");
                    1
                }
            }
        }

        Command::Bench => cmd_not_yet_implemented("bench"),
        Command::Metadata => cmd_not_yet_implemented("metadata"),
        Command::Crash => cmd_not_yet_implemented("crash"),
        Command::Bitrot => cmd_not_yet_implemented("bitrot"),
        Command::Fsck => cmd_not_yet_implemented("fsck"),
    };
    std::process::exit(rc);
}
