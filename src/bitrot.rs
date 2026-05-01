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
use std::time::SystemTime;

use crate::cluster::REMOTE_WORKER_PATH;
use crate::ssh::SshTarget;

#[derive(Debug, Clone)]
pub struct BitrotObservation {
    pub scenario: String,
    pub bytes: u32,
    pub raw_setup: String,
    pub raw_inject: String,
    pub raw_verify: String,
    pub phase_ok: bool,
}

/// Build SshTarget for compute01 (the FS-test victim node).
/// Master is the orchestrator and is intentionally isolated from
/// RadFI transverse contamination per recadrage R-isolation.
pub(crate) fn ssh_target() -> Result<SshTarget> {
    let key = std::env::var("HOME")
        .map(|h| format!("{h}/.ssh/hpclab_admin"))
        .context("HOME not set")?;
    Ok(SshTarget::new("hpcadmin", "192.168.56.11", &key))
}

fn ts_tag() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("c{now}")
}

fn run_scenario(scenario: &str, bytes: u32) -> Result<BitrotObservation> {
    let ssh = ssh_target()?;
    let tag = ts_tag();

    // Phase 1: setup (worker auto-detects target block by scanning disk)
    let setup_cmd = format!("{REMOTE_WORKER_PATH} bitrot_setup {tag}");
    let raw_setup = ssh.exec_lenient(&setup_cmd)
        .with_context(|| format!("bitrot_setup ({scenario})"))?;
    if !raw_setup.contains("SETUP=OK") {
        bail!("setup phase failed for {scenario}: {raw_setup}");
    }

    // Phase 2: inject
    let inject_cmd = format!("{REMOTE_WORKER_PATH} bitrot_inject {tag} {bytes}");
    let raw_inject = ssh.exec_lenient(&inject_cmd)
        .with_context(|| format!("bitrot_inject ({scenario})"))?;
    if !raw_inject.contains("INJECT=OK") {
        bail!("inject phase failed for {scenario}: {raw_inject}");
    }

    // Phase 3: verify (emits observation record)
    let verify_cmd = format!("{REMOTE_WORKER_PATH} bitrot_verify {tag}");
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

pub fn run() -> Result<i32> {
    println!("================================================================");
    println!(" beamfs-bench bitrot - Test C (offline injection)");
    println!(" Mode: measurement instrument (records observations)");
    println!("================================================================");

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
        match run_scenario(name, *bytes) {
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
