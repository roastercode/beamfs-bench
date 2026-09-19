//! tindirect.rs - Test F: triple-indirect addressing round-trip.
//!
//! Validates the kernel-side triple-indirect block-mapping paths
//! added in beamfs commit a192bb5 ('feat(fs): activate tindirect +
//! dindirect on iomap path'). The test creates a sparse beamfs
//! volume image on tmpfs, writes 16 KiB slices at carefully chosen
//! iblocks that exercise the dindirect->tindirect frontier and
//! several tindirect L2 slots, then sync + `drop_caches` + remount,
//! and re-reads the same slices to verify byte-for-byte identity.
//!
//! No fault injection. Validates the addressing math + bounds checks
//! under nominal conditions; the RS recovery path is exercised by
//! `multifs`, `cluster` and `bitrot` scopes.
//!
//! ## Scenarios
//!
//!   `T0_dindirect_max`    : iblock 262 667 (last dindirect, ~956 MiB-eq)
//!   `T1_tindirect_entry`  : iblock 262 668 (first tindirect)
//!   `T2_tindirect_l2_jmp` : iblock 524 812 (262 668 + 512^2, `l2_slot=1`)
//!   `T3_tindirect_deep`   : iblock 549 247 (mid-volume, l1=0, l2=559,
//!                          well into tindirect address space)
//!
//! Each scenario: write 16 KiB slice (4 disk blocks) at the iblock,
//! sync, sha256, `drop_caches`, umount, mount, sha256 again, compare.
//! All iblocks between direct[0] and the tested iblock remain HOLE
//! (sparse writes via `dd seek=...`). This is the whole point: tests
//! the addressing without paying terabytes of writes.
//!
//! ## Volume sizing
//!
//! mkfs.beamfs requires the on-disk volume to contain enough blocks
//! to *address* the highest tested iblock, but sparse data writes
//! only consume a handful of physical blocks. We size the volume at
//! 4 GiB on tmpfs (sparse-allocated loop file): enough physical
//! address space for iblock 549 247 (~2 GiB-eq) with margin, but
//! tmpfs pages only allocate on actual writes.
//!
//! ## Target node
//!
//! compute01 (FS-test victim per R21).

use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::ssh::SshTarget;
use std::fmt::Write;

#[derive(Debug, Clone)]
pub struct TindirectObservation {
    pub scenario: String,
    pub iblock: u64,
    pub raw_setup: String,
    pub raw_test: String,
    pub raw_cleanup: String,
    pub phase_ok: bool,
}

fn ssh_target() -> Result<SshTarget> {
    let key = crate::lab::ssh_key().to_string();
    Ok(SshTarget::new(crate::lab::ssh_user(), "192.168.56.11", &key))
}

fn ts_tag() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("t{now}")
}

fn run_scenario(scenario: &str, iblock: u64, injector: &str) -> Result<TindirectObservation> {
    let ssh = ssh_target()?;
    let tag = ts_tag();

    let setup_cmd = crate::cluster::worker_cmd(
        injector,
        &format!("tindirect_setup {tag}"),
    );
    let raw_setup = ssh.exec_lenient(&setup_cmd)
        .with_context(|| format!("tindirect_setup ({scenario})"))?;
    if !raw_setup.contains("SETUP=OK") {
        bail!("setup phase failed for {scenario}: {raw_setup}");
    }

    let test_cmd = crate::cluster::worker_cmd(
        injector,
        &format!("tindirect_test {tag} {iblock}"),
    );
    let raw_test = ssh.exec_lenient(&test_cmd)
        .with_context(|| format!("tindirect_test ({scenario}, iblock={iblock})"))?;

    let cleanup_cmd = crate::cluster::worker_cmd(
        injector,
        &format!("tindirect_cleanup {tag}"),
    );
    let raw_cleanup = ssh.exec_lenient(&cleanup_cmd)
        .with_context(|| format!("tindirect_cleanup ({scenario})"))?;

    let phase_ok = raw_setup.contains("SETUP=OK")
        && raw_test.contains("VERDICT=MATCH")
        && raw_cleanup.contains("CLEANUP=OK");

    Ok(TindirectObservation {
        scenario: scenario.to_string(),
        iblock,
        raw_setup,
        raw_test,
        raw_cleanup,
        phase_ok,
    })
}

pub fn run(injector: &str) -> Result<i32> {
    println!("================================================================");
    println!(" beamfs-bench tindirect - Test F (triple-indirect round-trip)");
    println!(" Mode: addressing validation (sparse writes, no fault injection)");
    println!("================================================================");

    let started_inst = Instant::now();
    let started_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let ts_compact = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let run_dir = PathBuf::from(format!(
        "{}/beamfs-bench-tindirect-{ts_compact}", crate::lab::runs_dir()
    ));
    fs::create_dir_all(&run_dir).context("create tindirect run dir")?;
    println!("Run dir: {}", run_dir.display());

    println!();
    println!("[tindirect] Deploying worker.sh on compute01 (FS-test victim node)...");
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

    // Scenarios:
    //   BEAMFS_INDIRECT_PTRS = 512
    //   BEAMFS_MAX_IBLOCK_INDIRECT  = 12 + 512                  = 524
    //   BEAMFS_MAX_IBLOCK_DINDIRECT = 524 + 512*512              = 262 668
    //   BEAMFS_MAX_IBLOCK_TINDIRECT = 262 668 + 512*512*512      = 134 480 396
    //
    // T0: last dindirect iblock = MAX_IBLOCK_DINDIRECT - 1 = 262 667
    // T1: first tindirect       = MAX_IBLOCK_DINDIRECT     = 262 668
    // T2: l2_jump               = T1 + 512*512 = 262 668 + 262 144 = 524 812
    // T3: deep tindirect        = T1 + 286 579 = 549 247
    //                             (l1=0, l2 = 286579/512 = 559, l3 = 286579 % 512 = 371)
    let scenarios: Vec<(&str, u64)> = vec![
        ("T0_dindirect_max",    262_667),
        ("T1_tindirect_entry",  262_668),
        ("T2_tindirect_l2_jmp", 524_812),
        ("T3_tindirect_deep",   549_247),
    ];

    let mut observations = Vec::new();
    for (name, iblock) in &scenarios {
        println!();
        println!("[tindirect] {name} : testing iblock {iblock}");
        match run_scenario(name, *iblock, injector) {
            Ok(o) => {
                println!("  setup    : {}", o.raw_setup.trim());
                println!("  test     : {}", o.raw_test.trim());
                println!("  cleanup  : {}", o.raw_cleanup.trim());
                observations.push(o);
            }
            Err(e) => {
                eprintln!("  PHASE_ERROR for {name}: {e:#}");
                observations.push(TindirectObservation {
                    scenario: name.to_string(),
                    iblock: *iblock,
                    raw_setup: String::new(),
                    raw_test: format!("PHASE_ERROR: {e:#}"),
                    raw_cleanup: String::new(),
                    phase_ok: false,
                });
            }
        }
    }

    let n_phase_ok = observations.iter().filter(|o| o.phase_ok).count();
    let n_phase_fail = observations.len() - n_phase_ok;

    println!();
    println!("================================================================");
    println!(" tindirect phase summary : {n_phase_ok}/{} phases MATCH",
             observations.len());
    println!("================================================================");

    let mut records = String::new();
    for o in &observations {
        writeln!(records, "--- {} (iblock={}) ---", o.scenario, o.iblock).unwrap();
        writeln!(records, "setup    : {}", o.raw_setup.trim()).unwrap();
        writeln!(records, "test     : {}", o.raw_test.trim()).unwrap();
        writeln!(records, "cleanup  : {}", o.raw_cleanup.trim()).unwrap();
        records.push('\n');
    }
    fs::write(run_dir.join("all-records.txt"), &records)
        .context("write tindirect all-records.txt")?;

    let mut synth = String::new();
    synth.push_str("# tindirect synthesis\n\n");
    writeln!(synth, "- Started (epoch) : {started_epoch}").unwrap();
    writeln!(synth, "- Scenarios run   : {}", observations.len()).unwrap();
    writeln!(synth, "- Phases MATCH    : {n_phase_ok}").unwrap();
    writeln!(synth, "- Phases FAIL     : {n_phase_fail}").unwrap();
    synth.push_str("\nbeamfs-bench is a measurement instrument; this file lists raw observations.\n");
    synth.push_str("MATCH = sha256(write_slice) == sha256(read_slice after drop_caches + remount).\n\n");
    synth.push_str("## Per-scenario\n\n");
    for o in &observations {
        let mark = if o.phase_ok { "MATCH" } else { "FAIL" };
        writeln!(synth, "- [{mark}] {} (iblock={})", o.scenario, o.iblock).unwrap();
    }
    fs::write(run_dir.join("synthesis.md"), &synth)
        .context("write tindirect synthesis.md")?;

    let ended_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let duration_secs = started_inst.elapsed().as_secs();
    let mut manifest = String::new();
    manifest.push_str("================================================================\n");
    manifest.push_str(" beamfs-bench tindirect manifest\n");
    manifest.push_str("================================================================\n");
    writeln!(manifest, "Run dir         : {}", run_dir.display()).unwrap();
    writeln!(manifest, "Started (epoch) : {started_epoch}").unwrap();
    writeln!(manifest, "Ended   (epoch) : {ended_epoch}").unwrap();
    writeln!(manifest, "Duration (s)    : {duration_secs}").unwrap();
    writeln!(manifest, "EXPECTED PHASES : {}", observations.len()).unwrap();
    writeln!(manifest, "EXECUTED PHASES : {}", observations.len()).unwrap();
    writeln!(manifest, "MATCH           : {n_phase_ok}").unwrap();
    writeln!(manifest, "FAIL            : {n_phase_fail}").unwrap();
    manifest.push_str("\n================================================================\n");
    manifest.push_str(" PHASE-BY-PHASE\n");
    manifest.push_str("================================================================\n");
    for o in &observations {
        let tag = if o.phase_ok { "[MATCH]" } else { "[FAIL] " };
        let summary = o.raw_test.trim().chars().take(140).collect::<String>();
        writeln!(manifest, "{tag} {} (iblock={}) : {summary}",
                                   o.scenario, o.iblock).unwrap();
    }
    fs::write(run_dir.join("manifest.txt"), &manifest)
        .context("write tindirect manifest.txt")?;

    println!();
    println!("Run dir : {}", run_dir.display());
    println!("Manifest: {}", run_dir.join("manifest.txt").display());

    if n_phase_fail == 0 { Ok(0) } else { Ok(1) }
}
