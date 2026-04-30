//! beamfs-bench — unified bench harness for beamfs resilience testing.
//!
//! Replaces the legacy bash harness (Tir-*.sh, ~1176 lines) with a single
//! Rust binary exposing one subcommand per test scope.
//!
//! Naming policy (anti-NAK kernel.org): all output prefixed `beamfs-bench:`,
//! lowercase. Macro identifiers in C (`BEAMFS_*`) keep uppercase per kernel
//! coding style and are not affected by this tool.
//!
//! Status:
//!   - 0.1.0 skeleton: subcommand surface declared.
//!   - 0.2.0 multifs:  port of Tir-multifs.sh, output byte-identical for diff.
//!   - 0.3.x analyse:  forensic wrapper (next).
//!   - 0.4.x bench:    cluster perf bench (later).
//!   - 0.5.x metadata/crash/bitrot/fsck: new test scopes.
//!
//! Author: Aurelien DESBRIERES <aurelien@hackers.camp>
//! License: GPL-2.0-only

use clap::{Parser, Subcommand};

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
    /// Targets 5 FS x 3 probabilities. Output byte-identical to legacy
    /// Tir-multifs.sh for diff-based parity verification against the
    /// reference run Tir-multifs-20260430-141008.
    Multifs,

    /// Forensic wrapper around `multifs`: dmesg + ftrace + perf capture
    /// per attack run, with tarball archive.
    /// (Port of legacy Tir-analyse-multifs.sh.)
    Analyse,

    /// Cluster I/O performance baseline (M1-M5 metrics, multi-node).
    /// (Port of legacy Tir.sh / hpc-benchmark-beamfs.sh.)
    Bench,

    /// Test A — metadata-targeted attack (superblock, inode bitmap, journal).
    /// New scope, not in legacy harness.
    Metadata,

    /// Test B — crash consistency (virsh destroy mid-write + remount).
    /// New scope, not in legacy harness.
    Crash,

    /// Test C — bit-rot offline (dd random on partition not mounted, then read).
    /// New scope, not in legacy harness.
    Bitrot,

    /// Test D — fsck recovery post-FS_PANIC.
    /// New scope, not in legacy harness.
    Fsck,
}

fn cmd_version() -> i32 {
    println!("beamfs-bench {}", BEAMFS_BENCH_VERSION);
    println!("license GPL-2.0-only");
    println!("status: multifs implemented; analyse/bench/metadata/crash/bitrot/fsck pending");
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
        Command::Version  => cmd_version(),
        Command::Multifs  => match multifs::run() {
            Ok(rc) => rc,
            Err(e) => {
                eprintln!("beamfs-bench: multifs failed: {e:#}");
                1
            }
        },
        Command::Analyse  => cmd_not_yet_implemented("analyse"),
        Command::Bench    => cmd_not_yet_implemented("bench"),
        Command::Metadata => cmd_not_yet_implemented("metadata"),
        Command::Crash    => cmd_not_yet_implemented("crash"),
        Command::Bitrot   => cmd_not_yet_implemented("bitrot"),
        Command::Fsck     => cmd_not_yet_implemented("fsck"),
    };
    std::process::exit(rc);
}
