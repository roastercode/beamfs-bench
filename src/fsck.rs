//! fsck.rs - Test D: offline filesystem check post-crash.
//!
//! ## Role
//!
//! Runs fsck.<fs> on each victim filesystem and emits the result as
//! a factual observation.
//!
//! For beamfs: fsck.beamfs is not yet implemented (planned Phase 1.5
//! mainline-prep). The bench emits an explicit NOT_IMPLEMENTED record
//! rather than skip silently.
//!
//! For squashfs: read-only filesystem, no fsck applicable; SKIP.
//!
//! For ext4/ext3: runs fsck.ext{3,4} -f -y, captures rc + first 20
//! lines of output.
//!
//! For btrfs: runs btrfs check, captures rc + first 20 lines.
//!
//! ## Format
//!
//!   FSCK|HOST=...|FS=...|FSCK_RC=N|FSCK_SUMMARY=<first 20 lines, semicolon-joined>
//!   FSCK|HOST=...|FS=beamfs|CHECK=NOT_IMPLEMENTED|reason=fsck_beamfs_pending_phase_1_5
//!   FSCK|HOST=...|FS=squashfs|CHECK=SKIP|reason=read_only_filesystem_no_fsck
//!
//! Topology: compute01 (R-isolation).

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::bitrot::ssh_target;
use crate::cluster::{ClusterNode, NodeState, REMOTE_WORKER_PATH};

#[derive(Debug, Clone)]
pub struct FsckObservation {
    pub fs: String,
    pub vd: String,
    pub raw_check: String,
    pub phase_ok: bool,
}

const FS_TARGETS: &[(&str, &str)] = &[
    ("ext4",     "vdc"),
    ("ext3",     "vdd"),
    ("btrfs",    "vde"),
    ("squashfs", "vdf"),
    ("beamfs",   "vdg"),
];

fn ts_tag() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("fsck{now}")
}

fn run_scenario(fs: &str, vd: &str) -> Result<FsckObservation> {
    let tag = ts_tag();
    let ssh = ssh_target()?;
    let cmd = format!("{REMOTE_WORKER_PATH} fsck_check {tag} {fs} {vd}");
    let raw_check = ssh.exec_lenient(&cmd)
        .with_context(|| format!("fsck_check ({fs})"))?;
    let phase_ok = raw_check.contains("CHECK=OK")
        || raw_check.contains("CHECK=SKIP")
        || raw_check.contains("CHECK=NOT_IMPLEMENTED");

    Ok(FsckObservation {
        fs: fs.to_string(),
        vd: vd.to_string(),
        raw_check,
        phase_ok,
    })
}

fn write_synthesis(run_dir: &PathBuf, observations: &[FsckObservation]) -> Result<()> {
    let synth_path = run_dir.join("synthesis.md");
    let mut s = String::new();
    s.push_str("# beamfs-bench fsck synthesis\n\n");
    s.push_str("Test D: offline filesystem check (fsck.<fs>).\n");
    s.push_str("Mode: measurement instrument (factual observations only).\n\n");
    s.push_str("## Topology\n\n");
    s.push_str("- compute01 holds the 5 USB FS victims\n");
    s.push_str("- master is orchestrator (R-isolation)\n");
    s.push_str("- squashfs: SKIP (read-only, no fsck)\n");
    s.push_str("- beamfs: NOT_IMPLEMENTED (fsck.beamfs is Phase 1.5 mainline-prep)\n\n");
    s.push_str("## Observation matrix (5 FS x 1 scenario = 5 records)\n\n");
    s.push_str("| FS | VD | Phase | Raw check (truncated) |\n");
    s.push_str("|----|-----|-------|----------------------|\n");
    for o in observations {
        let phase = if o.phase_ok { "OK" } else { "FAIL" };
        let v: String = o.raw_check.lines().next().unwrap_or("").chars().take(150).collect();
        s.push_str(&format!("| {} | {} | {} | `{}` |\n", o.fs, o.vd, phase, v));
    }
    s.push_str("\n## Notes for analysis\n\n");
    s.push_str("- fsck_rc=0 generally means clean; rc=1 means errors corrected;\n");
    s.push_str("  rc>=4 means manual intervention required (per fsck conventions).\n");
    s.push_str("- For beamfs: NOT_IMPLEMENTED is a deliberate signal; once Phase 1.5\n");
    s.push_str("  delivers fsck.beamfs, this row will produce real fsck observations.\n");
    fs::write(&synth_path, s).context("write synthesis.md")?;

    let records_path = run_dir.join("all-records.txt");
    let mut r = String::new();
    for o in observations {
        r.push_str(&format!("--- {} / {} ---\n", o.fs, o.vd));
        r.push_str(&format!("check : {}\n\n", o.raw_check.trim()));
    }
    fs::write(&records_path, r).context("write all-records.txt")?;
    Ok(())
}

pub fn run() -> Result<i32> {
    println!("================================================================");
    println!(" beamfs-bench fsck - Test D (offline FS check)");
    println!(" Mode: measurement instrument (factual observations only)");
    println!(" Topology: compute01 (5 USB victims), master isolated");
    println!("================================================================");

    let now = chrono::Local::now();
    let stamp = now.format("%Y%m%d-%H%M%S").to_string();
    let started_inst = Instant::now();
    let started_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let run_dir = PathBuf::from(format!(
        "/home/aurelien/git/yocto-beamfs/Documentation/runs/beamfs-bench-fsck-{stamp}"
    ));
    fs::create_dir_all(&run_dir).context("create run dir")?;
    println!("Run dir: {}", run_dir.display());
    println!();

    println!("[fsck] Deploying worker on compute01...");
    let target = vec![ClusterNode {
        ip: "192.168.56.11".to_string(),
        expected_hostname: "beamfs-compute01".to_string(),
        discovered: NodeState {
            reachable: true,
            ..Default::default()
        },
    }];
    let deploys = crate::cluster::deploy_worker_all(&target).context("worker deploy")?;
    for (host, r) in &deploys {
        match r {
            Ok(()) => println!("  {host} : worker deployed"),
            Err(e) => return Err(anyhow!("worker deploy failed on {host}: {e:#}")),
        }
    }

    let mut observations = Vec::new();
    for (fs_name, vd) in FS_TARGETS {
        println!();
        println!("=== FS: {fs_name} on /dev/{vd} ===");
        match run_scenario(fs_name, vd) {
            Ok(o) => {
                let mark = if o.phase_ok { "OK" } else { "FAIL" };
                println!("  [phase {mark}] check: {}", o.raw_check.trim());
                observations.push(o);
            }
            Err(e) => {
                eprintln!("  PHASE_ERROR for {fs_name}: {e:#}");
                observations.push(FsckObservation {
                    fs: fs_name.to_string(),
                    vd: vd.to_string(),
                    raw_check: format!("PHASE_ERROR: {e:#}"),
                    phase_ok: false,
                });
            }
        }
    }

    write_synthesis(&run_dir, &observations).context("write synthesis")?;

    let n_ok = observations.iter().filter(|o| o.phase_ok).count();
    let n_fail = observations.len() - n_ok;

    // Manifest + tarball
    let ended_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let duration_secs = started_inst.elapsed().as_secs();
    let mut manifest = String::new();
    manifest.push_str("================================================================\n");
    manifest.push_str(" beamfs-bench fsck manifest\n");
    manifest.push_str("================================================================\n");
    manifest.push_str(&format!("Run dir         : {}\n", run_dir.display()));
    manifest.push_str(&format!("Started (epoch) : {started_epoch}\n"));
    manifest.push_str(&format!("Ended   (epoch) : {ended_epoch}\n"));
    manifest.push_str(&format!("Duration (s)    : {duration_secs}\n"));
    manifest.push_str(&format!("EXPECTED PHASES : {}\n", observations.len()));
    manifest.push_str(&format!("EXECUTED PHASES : {}\n", observations.len()));
    manifest.push_str(&format!("PASSED          : {n_ok}\n"));
    manifest.push_str(&format!("FAILED          : {n_fail}\n"));
    manifest.push_str("\n================================================================\n");
    manifest.push_str(" PHASE-BY-PHASE\n");
    manifest.push_str("================================================================\n");
    for o in &observations {
        let tag = if o.phase_ok { "[OK]  " } else { "[FAIL]" };
        let summary = o.raw_check.trim().chars().take(140).collect::<String>();
        manifest.push_str(&format!("{tag} {} : {summary}\n", o.fs));
    }
    manifest.push_str("\n================================================================\n");
    manifest.push_str(" ARTIFACTS IN RUN DIR\n");
    manifest.push_str("================================================================\n");
    if let Ok(rd) = fs::read_dir(&run_dir) {
        for entry in rd.flatten() {
            if let Ok(meta) = entry.metadata() {
                manifest.push_str(&format!("{:<40} : {} bytes\n",
                    entry.file_name().to_string_lossy(), meta.len()));
            }
        }
    }
    let manifest_path = run_dir.join("manifest.txt");
    fs::write(&manifest_path, &manifest)
        .context("write fsck manifest.txt")?;

    println!();
    println!("================================================================");
    println!(" fsck phase summary : {n_ok}/{} phases completed cleanly",
             observations.len());
    println!("================================================================");
    println!();
    println!(" Synthesis : {}/synthesis.md", run_dir.display());
    println!(" Records   : {}/all-records.txt", run_dir.display());
    println!();

    if n_fail > 0 {
        return Err(anyhow!("{n_fail} fsck phase(s) failed technically"));
    }
    Ok(0)
}
