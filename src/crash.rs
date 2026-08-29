//! crash.rs - Test B: power-loss mid-write recovery.
//!
//! ## Role
//!
//! Tests filesystem recovery after a brutal power loss while a write
//! is in flight. Simulates the standard fsdevel "crash recovery" test:
//!
//!   1. Setup FS, populate stable baseline files, capture `hash_pre`
//!   2. Start a background dd writer (urandom -> file)
//!   3. virsh destroy compute01 (kill QEMU process, no graceful shutdown)
//!   4. virsh start compute01, wait SSH
//!   5. Redeploy worker (lost on destroy)
//!   6. Try remount, parse dmesg journal-replay events, emit observation
//!
//! ## Methodology
//!
//! Measurement instrument, no judgment. For each FS, one observation:
//!
//!   `CRASH|HOST=...|FS=...|SCHEME=N|MOUNT_RC=0/N|MOUNTED=0/1`
//!        |`STABLE_FILES_OK=K|HASH_STABLE`=<sha>
//!        |`CRASH_FILE_PRESENT=0/1`
//!        |`DMESG_JOURNAL_REPLAY=N|DMESG_EIO=N`
//!        |`DMESG_FSCK_NEEDED=N|DMESG_PANIC=N`
//!
//! Topology (R-isolation): compute01 holds the 5 USB victims.
//! squashfs is RO, automatically skipped.

use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::bitrot::ssh_target;
use crate::cluster::{ClusterNode, NodeState};
use crate::lifecycle::{ssh_probe, virsh_sudo_lenient};
use std::fmt::Write;

#[derive(Debug, Clone)]
pub struct CrashObservation {
    pub fs: String,
    pub vd: String,
    pub raw_setup: String,
    pub raw_writer: String,
    pub raw_verify: String,
    pub phase_ok: bool,
}

const FS_TARGETS: &[(&str, &str)] = &[
    ("ext4",     "vdc"),
    ("ext3",     "vdd"),
    ("btrfs",    "vde"),
    ("squashfs", "vdf"),
    ("beamfs",   "vdg"),
];

const COMPUTE01_VM: &str = "beamfs-compute01";
const COMPUTE01_IP: &str = "192.168.56.11";

fn ts_tag() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("crash{now}")
}

fn deploy_worker_to_compute01() -> Result<()> {
    let target = vec![ClusterNode {
        ip: COMPUTE01_IP.to_string(),
        expected_hostname: COMPUTE01_VM.to_string(),
        discovered: NodeState {
            reachable: true,
            ..Default::default()
        },
    }];
    let deploys = crate::cluster::deploy_worker_all(&target).context("worker deploy")?;
    for (host, r) in &deploys {
        match r {
            Ok(()) => println!("  {host} : worker (re)deployed"),
            Err(e) => return Err(anyhow!("worker deploy failed on {host}: {e:#}")),
        }
    }
    Ok(())
}

fn wait_ssh_compute01(timeout_secs: u64) -> Result<()> {
    let key = std::env::var("HOME")
        .map(|h| format!("{h}/.ssh/hpclab_admin"))
        .context("HOME not set")?;
    let start = std::time::Instant::now();
    loop {
        if ssh_probe(COMPUTE01_IP, &key) {
            return Ok(());
        }
        if start.elapsed().as_secs() > timeout_secs {
            bail!("compute01 SSH did not become ready within {timeout_secs}s");
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn run_scenario(fs: &str, vd: &str, injector: &str) -> Result<CrashObservation> {
    let tag = ts_tag();
    let ssh = ssh_target()?;

    // Phase 1: setup
    println!("  [phase 1/4] setup");
    let setup_cmd = crate::cluster::worker_cmd(injector, &format!("crash_setup {tag} {fs} {vd}"));
    let raw_setup = ssh.exec_lenient(&setup_cmd)
        .with_context(|| format!("crash_setup ({fs})"))?;
    if raw_setup.contains("SETUP=SKIP") {
        // squashfs RO case
        return Ok(CrashObservation {
            fs: fs.to_string(),
            vd: vd.to_string(),
            raw_setup,
            raw_writer: "WRITER=SKIP|reason=ro_fs".to_string(),
            raw_verify: "VERIFY=SKIP|reason=ro_fs".to_string(),
            phase_ok: true,
        });
    }
    if !raw_setup.contains("SETUP=OK") {
        bail!("setup failed for {fs}: {raw_setup}");
    }

    // Phase 2: start background writer
    println!("  [phase 2/4] start writer (background dd)");
    let writer_cmd = crate::cluster::worker_cmd(injector, &format!("crash_start_writer {tag} {fs} {vd}"));
    let raw_writer = ssh.exec_lenient(&writer_cmd)
        .with_context(|| format!("crash_start_writer ({fs})"))?;
    if !raw_writer.contains("WRITER=STARTED") {
        bail!("writer failed for {fs}: {raw_writer}");
    }

    // Wait briefly so dd has bytes in flight
    thread::sleep(Duration::from_millis(500));

    // Phase 3: virsh destroy compute01 (brutal power-off)
    println!("  [phase 3/4] virsh destroy {COMPUTE01_VM} (simulating power loss)");
    let (rc, _, stderr) = virsh_sudo_lenient(&["destroy", COMPUTE01_VM]);
    if rc != 0 && !stderr.contains("not running") {
        bail!("virsh destroy failed: rc={rc} stderr={stderr}");
    }
    thread::sleep(Duration::from_secs(1));

    // Phase 3b: virsh start
    println!("  [phase 3/4] virsh start {COMPUTE01_VM}");
    let (rc, _, stderr) = virsh_sudo_lenient(&["start", COMPUTE01_VM]);
    if rc != 0 {
        bail!("virsh start failed: rc={rc} stderr={stderr}");
    }

    // Wait SSH ready
    wait_ssh_compute01(120).context("wait SSH after restart")?;
    println!("  compute01 SSH ready");

    // Redeploy worker (was on tmpfs, lost)
    deploy_worker_to_compute01().context("redeploy worker post-crash")?;

    // Phase 4: verify
    println!("  [phase 4/4] verify (mount + read + dmesg parse)");
    let ssh = ssh_target()?;
    let verify_cmd = crate::cluster::worker_cmd(injector, &format!("crash_verify {tag} {fs} {vd}"));
    let raw_verify = ssh.exec_lenient(&verify_cmd)
        .with_context(|| format!("crash_verify ({fs})"))?;
    let phase_ok = raw_verify.contains("VERIFY=OK") || raw_verify.contains("VERIFY=SKIP");

    Ok(CrashObservation {
        fs: fs.to_string(),
        vd: vd.to_string(),
        raw_setup,
        raw_writer,
        raw_verify,
        phase_ok,
    })
}

fn write_synthesis(run_dir: &Path, observations: &[CrashObservation]) -> Result<()> {
    let synth_path = run_dir.join("synthesis.md");
    let mut s = String::new();
    s.push_str("# beamfs-bench crash synthesis\n\n");
    s.push_str("Test B: power-loss mid-write (virsh destroy compute01).\n");
    s.push_str("Mode: measurement instrument (factual observations only).\n\n");
    s.push_str("## Topology\n\n");
    s.push_str("- compute01 holds the 5 USB FS victims\n");
    s.push_str("- master is orchestrator (R-isolation)\n");
    s.push_str("- squashfs is read-only, automatically skipped\n\n");
    s.push_str("## Observation matrix (5 FS x 1 scenario = 5 records)\n\n");
    s.push_str("| FS | VD | Phase | Raw verify (truncated) |\n");
    s.push_str("|----|-----|-------|------------------------|\n");
    for o in observations {
        let phase = if o.phase_ok { "OK" } else { "FAIL" };
        let v: String = o.raw_verify.lines().next().unwrap_or("").chars().take(150).collect();
        writeln!(s, "| {} | {} | {} | `{}` |", o.fs, o.vd, phase, v).unwrap();
    }
    s.push_str("\n## Notes for analysis\n\n");
    s.push_str("- Verdict interpretation (clean recovery / journal replay / data loss / corruption)\n");
    s.push_str("  belongs to the analyst, not the bench.\n");
    s.push_str("- DMESG_JOURNAL_REPLAY is keyword-matched (recovery/journal/replay/orphan inode);\n");
    s.push_str("  presence does not mean success, only that a replay event was logged.\n");
    s.push_str("- HASH_STABLE compared against HASH_PRE indicates whether stable baseline\n");
    s.push_str("  files survived crash (independent of crash-write.bin which was in-flight).\n");
    s.push_str("- For beamfs: scheme=N from dmesg shows active protection level.\n");
    fs::write(&synth_path, s).context("write synthesis.md")?;

    let records_path = run_dir.join("all-records.txt");
    let mut r = String::new();
    for o in observations {
        writeln!(r, "--- {} / {} ---", o.fs, o.vd).unwrap();
        writeln!(r, "setup  : {}", o.raw_setup.trim()).unwrap();
        writeln!(r, "writer : {}", o.raw_writer.trim()).unwrap();
        writeln!(r, "verify : {}", o.raw_verify.trim()).unwrap();
        r.push('\n');
    }
    fs::write(&records_path, r).context("write all-records.txt")?;
    Ok(())
}

pub fn run(injector: &str) -> Result<i32> {
    println!("================================================================");
    println!(" beamfs-bench crash - Test B (power-loss mid-write recovery)");
    println!(" Mode: measurement instrument (factual observations only)");
    println!(" Topology: compute01 (5 USB victims), master isolated");
    println!("================================================================");

    let now = chrono::Local::now();
    let stamp = now.format("%Y%m%d-%H%M%S").to_string();
    let started_inst = Instant::now();
    let started_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let run_dir = PathBuf::from(format!(
        "/home/aurelien/git/yocto-beamfs/Documentation/runs/beamfs-bench-crash-{stamp}"
    ));
    fs::create_dir_all(&run_dir).context("create run dir")?;
    println!("Run dir: {}", run_dir.display());
    println!();

    println!("[crash] Initial worker deploy on compute01...");
    deploy_worker_to_compute01().context("initial worker deploy")?;

    let mut observations = Vec::new();
    for (fs_name, vd) in FS_TARGETS {
        println!();
        println!("=== FS: {fs_name} on /dev/{vd} ===");
        match run_scenario(fs_name, vd, injector) {
            Ok(o) => {
                let mark = if o.phase_ok { "OK" } else { "FAIL" };
                println!("  [phase {mark}] verify: {}", o.raw_verify.trim());
                observations.push(o);
            }
            Err(e) => {
                eprintln!("  PHASE_ERROR for {fs_name}: {e:#}");
                observations.push(CrashObservation {
                    fs: fs_name.to_string(),
                    vd: vd.to_string(),
                    raw_setup: String::new(),
                    raw_writer: String::new(),
                    raw_verify: format!("PHASE_ERROR: {e:#}"),
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
        .map_or(0, |d| d.as_secs());
    let duration_secs = started_inst.elapsed().as_secs();
    let mut manifest = String::new();
    manifest.push_str("================================================================\n");
    manifest.push_str(" beamfs-bench crash manifest\n");
    manifest.push_str("================================================================\n");
    writeln!(manifest, "Run dir         : {}", run_dir.display()).unwrap();
    writeln!(manifest, "Started (epoch) : {started_epoch}").unwrap();
    writeln!(manifest, "Ended   (epoch) : {ended_epoch}").unwrap();
    writeln!(manifest, "Duration (s)    : {duration_secs}").unwrap();
    writeln!(manifest, "EXPECTED PHASES : {}", observations.len()).unwrap();
    writeln!(manifest, "EXECUTED PHASES : {}", observations.len()).unwrap();
    writeln!(manifest, "PASSED          : {n_ok}").unwrap();
    writeln!(manifest, "FAILED          : {n_fail}").unwrap();
    manifest.push_str("\n================================================================\n");
    manifest.push_str(" PHASE-BY-PHASE\n");
    manifest.push_str("================================================================\n");
    for o in &observations {
        let tag = if o.phase_ok { "[OK]  " } else { "[FAIL]" };
        let summary = o.raw_verify.trim().chars().take(140).collect::<String>();
        writeln!(manifest, "{tag} {} : {summary}", o.fs).unwrap();
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
        .context("write crash manifest.txt")?;

    println!();
    println!("================================================================");
    println!(" crash phase summary : {n_ok}/{} phases completed cleanly",
             observations.len());
    println!("================================================================");
    println!();
    println!(" Synthesis : {}/synthesis.md", run_dir.display());
    println!(" Records   : {}/all-records.txt", run_dir.display());
    println!();

    if n_fail > 0 {
        for o in &observations {
            if !o.phase_ok {
                eprintln!("  PHASE_FAIL {}", o.fs);
            }
        }
        return Err(anyhow!("{n_fail} crash phase(s) failed technically"));
    }

    Ok(0)
}
