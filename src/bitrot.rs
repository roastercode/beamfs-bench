//! bitrot.rs - Test C: offline bit-rot injection + observation recording.
//!
//! ## Role
//!
//! beamfs-bench is a measurement instrument, not a judgment engine.
//! For each scenario it:
//!
//!   1. Injects a known fault (umount + dd random + remount)
//!   2. Reads files and measures kernel behavior
//!   3. Emits a factual observation record
//!
//! Observations are written verbatim to the run dir for human/script
//! analysis. PASS/FAIL at the bench level only reflects whether the
//! technical phases completed (SSH OK, setup OK, inject OK, verify
//! emitted output). Whether the kernel did the right thing is a
//! separate analysis performed in synthesis.md.
//!
//! ## Scenarios
//!
//!   C1 single-byte injection  : 1 byte at file-3.bin first block
//!   C2 RS-limit injection     : 8 bytes (RS(255,239) correction limit)
//!   C3 over-limit injection   : 9 bytes (>RS limit)
//!   C4 burst injection        : 256 bytes (Family B simulation)
//!
//! Each scenario is independent (fresh setup + inject + verify cycle).

use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::ssh::SshTarget;
use std::fmt::Write;

#[derive(Debug, Clone)]
pub struct BitrotObservation {
    pub scenario: String,
    pub bytes: u32,
    pub raw_setup: String,
    pub raw_inject: String,
    pub raw_verify: String,
    pub phase_ok: bool,
}

/// Build `SshTarget` for compute01 (the FS-test victim node).
/// Master is the orchestrator and is intentionally isolated from
/// `RadFI` transverse contamination per recadrage R-isolation.
pub(crate) fn ssh_target() -> Result<SshTarget> {
    let key = crate::lab::ssh_key().to_string();
    Ok(SshTarget::new(crate::lab::ssh_user(), "192.168.56.11", &key))
}

fn ts_tag() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("c{now}")
}

fn run_scenario(scenario: &str, bytes: u32, injector: &str) -> Result<BitrotObservation> {
    let ssh = ssh_target()?;
    let tag = ts_tag();

    // Phase 1: setup (worker auto-detects target block by scanning disk)
    let setup_cmd = crate::cluster::worker_cmd(injector, &format!("bitrot_setup {tag}"));
    let raw_setup = ssh.exec_lenient(&setup_cmd)
        .with_context(|| format!("bitrot_setup ({scenario})"))?;
    if !raw_setup.contains("SETUP=OK") {
        bail!("setup phase failed for {scenario}: {raw_setup}");
    }

    // Phase 2: inject
    let inject_cmd = crate::cluster::worker_cmd(injector, &format!("bitrot_inject {tag} {bytes}"));
    let raw_inject = ssh.exec_lenient(&inject_cmd)
        .with_context(|| format!("bitrot_inject ({scenario})"))?;
    if !raw_inject.contains("INJECT=OK") {
        bail!("inject phase failed for {scenario}: {raw_inject}");
    }

    // Phase 3: verify (emits observation record)
    let verify_cmd = crate::cluster::worker_cmd(injector, &format!("bitrot_verify {tag}"));
    let raw_verify = ssh.exec_lenient(&verify_cmd)
        .with_context(|| format!("bitrot_verify ({scenario})"))?;
    let phase_ok = raw_verify.contains("BITROT|") && raw_verify.contains("SCHEME=");

    Ok(BitrotObservation {
        scenario: scenario.to_string(),
        bytes,
        raw_setup,
        raw_inject,
        raw_verify,
        phase_ok,
    })
}

pub fn run(injector: &str) -> Result<i32> {
    println!("================================================================");
    println!(" beamfs-bench bitrot - Test C (offline injection)");
    println!(" Mode: measurement instrument (records observations)");
    println!("================================================================");

    let started_inst = Instant::now();
    let started_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let ts_compact = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let run_dir = PathBuf::from(format!(
        "{}/beamfs-bench-bitrot-{ts_compact}", crate::lab::runs_dir()
    ));
    fs::create_dir_all(&run_dir).context("create bitrot run dir")?;
    println!("Run dir: {}", run_dir.display());

    println!();
    println!("[bitrot] Deploying worker.sh on compute01 (FS-test victim node)...");
    let target_node = vec![crate::cluster::ClusterNode {
        ip: "192.168.56.11".to_string(),
        expected_hostname: "beamfs-compute01".to_string(),
        discovered: crate::cluster::NodeState {
            reachable: true,
            ..Default::default()
        },
    }];
    let deploys = crate::cluster::deploy_worker_all(&target_node)
        .context("worker deploy")?;
    for (host, r) in &deploys {
        match r {
            Ok(()) => println!("  {host} : worker deployed"),
            Err(e) => return Err(anyhow!("worker deploy failed on {host}: {e:#}")),
        }
    }

    let scenarios: Vec<(&str, u32)> = vec![
        ("C1_single_byte",  1),
        ("C2_rs_limit",     8),
        ("C3_over_limit",   9),
        ("C4_burst_256",    256),
    ];

    let mut observations = Vec::new();
    for (name, bytes) in &scenarios {
        println!();
        println!("[bitrot] {name} : injecting {bytes} byte(s)");
        match run_scenario(name, *bytes, injector) {
            Ok(o) => {
                println!("  setup    : {}", o.raw_setup.trim());
                println!("  inject   : {}", o.raw_inject.trim());
                println!("  observe  : {}", o.raw_verify.trim());
                observations.push(o);
            }
            Err(e) => {
                eprintln!("  PHASE_ERROR for {name}: {e:#}");
                observations.push(BitrotObservation {
                    scenario: name.to_string(),
                    bytes: *bytes,
                    raw_setup: String::new(),
                    raw_inject: String::new(),
                    raw_verify: format!("PHASE_ERROR: {e:#}"),
                    phase_ok: false,
                });
            }
        }
    }

    let n_phase_ok = observations.iter().filter(|o| o.phase_ok).count();
    let n_phase_fail = observations.len() - n_phase_ok;

    println!();
    println!("================================================================");
    println!(" bitrot phase summary : {n_phase_ok}/{} phases completed cleanly",
             observations.len());
    println!("================================================================");
    println!();
    println!(" Note: bench reports observations only. Kernel behavior analysis");
    println!(" (recovery vs. corruption) is performed post-run in synthesis.md.");
    println!();

    // Persist all-records.txt
    let mut records = String::new();
    for o in &observations {
        writeln!(records, "--- {} (bytes={}) ---", o.scenario, o.bytes).unwrap();
        writeln!(records, "setup    : {}", o.raw_setup.trim()).unwrap();
        writeln!(records, "inject   : {}", o.raw_inject.trim()).unwrap();
        writeln!(records, "observe  : {}", o.raw_verify.trim()).unwrap();
        records.push('\n');
    }
    fs::write(run_dir.join("all-records.txt"), &records)
        .context("write bitrot all-records.txt")?;

    // Persist synthesis.md
    let mut synth = String::new();
    synth.push_str("# bitrot synthesis\n\n");
    writeln!(synth, "- Started (epoch): {started_epoch}").unwrap();
    writeln!(synth, "- Scenarios run  : {}", observations.len()).unwrap();
    writeln!(synth, "- Phases OK      : {n_phase_ok}").unwrap();
    writeln!(synth, "- Phases FAIL    : {n_phase_fail}").unwrap();
    synth.push_str("\nbeamfs-bench is a measurement instrument; this file lists raw observations.\n");
    synth.push_str("Kernel behavior analysis (recovery vs corruption) is performed post-run.\n\n");
    synth.push_str("## Per-scenario\n\n");
    for o in &observations {
        let mark = if o.phase_ok { "OK" } else { "FAIL" };
        writeln!(synth, "- [{mark}] {} (bytes={})", o.scenario, o.bytes).unwrap();
    }
    fs::write(run_dir.join("synthesis.md"), &synth)
        .context("write bitrot synthesis.md")?;

    // Manifest
    let ended_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let duration_secs = started_inst.elapsed().as_secs();
    let mut manifest = String::new();
    manifest.push_str("================================================================\n");
    manifest.push_str(" beamfs-bench bitrot manifest\n");
    manifest.push_str("================================================================\n");
    writeln!(manifest, "Run dir         : {}", run_dir.display()).unwrap();
    writeln!(manifest, "Started (epoch) : {started_epoch}").unwrap();
    writeln!(manifest, "Ended   (epoch) : {ended_epoch}").unwrap();
    writeln!(manifest, "Duration (s)    : {duration_secs}").unwrap();
    writeln!(manifest, "EXPECTED PHASES : {}", observations.len()).unwrap();
    writeln!(manifest, "EXECUTED PHASES : {}", observations.len()).unwrap();
    writeln!(manifest, "PASSED          : {n_phase_ok}").unwrap();
    writeln!(manifest, "FAILED          : {n_phase_fail}").unwrap();
    manifest.push_str("\n================================================================\n");
    manifest.push_str(" PHASE-BY-PHASE\n");
    manifest.push_str("================================================================\n");
    for o in &observations {
        let tag = if o.phase_ok { "[OK]  " } else { "[FAIL]" };
        let summary = o.raw_verify.trim().chars().take(140).collect::<String>();
        writeln!(manifest, "{tag} {} (bytes={}) : {summary}", o.scenario, o.bytes).unwrap();
    }
    manifest.push_str("\n================================================================\n");
    manifest.push_str(" ARTIFACTS IN RUN DIR\n");
    manifest.push_str("================================================================\n");
    if let Ok(rd) = fs::read_dir(&run_dir) {
        for entry in rd.flatten() {
            if let Ok(meta) = entry.metadata() {
                writeln!(manifest, "{:<40} : {} bytes",
                    entry.file_name().to_string_lossy(), meta.len()).unwrap();
            }
        }
    }
    let manifest_path = run_dir.join("manifest.txt");
    fs::write(&manifest_path, &manifest)
        .context("write bitrot manifest.txt")?;

    println!();
    println!(" Synthesis : {}/synthesis.md", run_dir.display());
    println!(" Records   : {}/all-records.txt", run_dir.display());
    println!(" Manifest  : {}/manifest.txt", run_dir.display());

    if n_phase_fail > 0 {
        for o in &observations {
            if !o.phase_ok {
                eprintln!("  PHASE_FAIL {} (bytes={})", o.scenario, o.bytes);
            }
        }
        return Err(anyhow!("{n_phase_fail} bitrot phase(s) failed technically"));
    }

    Ok(0)
}
