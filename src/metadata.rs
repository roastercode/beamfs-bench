//! metadata.rs - Test A: RadFI deterministic injection on metadata blocks.
//!
//! ## Role
//!
//! Tests filesystem resilience to electromagnetic perturbations on
//! metadata blocks (superblock, bitmap, inode table) via RadFI
//! deterministic targeting (target_block + probability=1M).
//!
//! Per the EMR threat model (Family A stochastic SEU + Family B
//! adversarial bursts, see beamfs paper v2 + RadFI paper v1), this
//! exercises the kernel transit path: bytes in DRAM are flipped
//! while in flight through submit_bio_noacct/submit_bh, simulating
//! single-event upsets observable at the byte level.
//!
//! Cluster topology (R-isolation enforced):
//!   compute01 holds the 5 USB FS-test victims (vdc..vdg)
//!   master is the orchestrator, never a target
//!
//! ## Methodology (per fsdevel rigour standards)
//!
//! beamfs-bench is a measurement instrument, not a judgment engine.
//! For each (FS, scenario) pair, it emits a factual observation
//! record:
//!
//!   METADATA|HOST=...|FS=...|SCENARIO=...|TARGET_BLOCK=N
//!           |SCHEME=N|MOUNTED=0/1|READ_OK=K
//!           |DMESG_RS_CORRECTED=N|DMESG_UNCORRECTABLE=N
//!           |DMESG_EIO=N|DMESG_PANIC=N
//!           |RS_JOURNAL_NEW_ENTRIES=N
//!           |HASH_PRE=<sha256>|HASH_POST=<sha256>
//!
//! Interpretation (e.g. "ext4 panicked on superblock corruption,
//! beamfs recovered via RS FEC") is the role of post-run synthesis,
//! not the bench. PASS/FAIL at bench level reflects only that
//! technical phases completed.
//!
//! ## Scenarios (4 per FS, 5 FS = 20 observations)
//!
//!   A1 superblock      : target_block=0, prob=1M (Family A SEU)
//!   A2 bitmap-adjacent : target_block=1, prob=1M
//!   A3 inode-adjacent  : target_block=2, prob=1M
//!   A4 saturation      : target_block=0, prob=1M, repeated up to 3x
//!                        Probes Theorem v2.2 saturation observability.
//!                        - On non-FEC FSes (ext4/btrfs/squashfs),
//!                          iter=1 typically corrupts the SB enough
//!                          that subsequent iterations cannot remount;
//!                          the bench emits INJECT=SKIP|saturation_reached
//!                          as a factual observation (not an error).
//!                        - On beamfs (FEC-protected), all 3 iters
//!                          should succeed up to RS correction limit.

use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::bitrot::ssh_target;
use crate::cluster::{ClusterNode, NodeState, REMOTE_WORKER_PATH};

#[derive(Debug, Clone)]
pub struct MetadataObservation {
    pub fs: String,
    pub vd: String,
    pub scenario: String,
    pub target_block: u32,
    pub probability: u32,
    pub raw_setup: String,
    pub raw_inject: String,
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

const SCENARIOS: &[(&str, u32, u32)] = &[
    // (name, target_block, probability)
    ("A1_superblock",      0, 1_000_000),
    ("A2_bitmap_adjacent", 1, 1_000_000),
    ("A3_inode_adjacent",  2, 1_000_000),
    ("A4_saturation_x3",   0, 1_000_000),  // repeated 3x in inject phase
];

fn ts_tag() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("m{now}")
}

fn run_scenario(fs: &str, vd: &str, scenario: &str, block: u32, prob: u32) -> Result<MetadataObservation> {
    let ssh = ssh_target()?;
    let tag = ts_tag();

    // Phase 1: setup
    let setup_cmd = format!("{REMOTE_WORKER_PATH} metadata_setup {tag} {fs} {vd}");
    let raw_setup = ssh.exec_lenient(&setup_cmd)
        .with_context(|| format!("metadata_setup ({fs}, {scenario})"))?;
    if !raw_setup.contains("SETUP=OK") {
        bail!("setup phase failed for {fs}/{scenario}: {raw_setup}");
    }

    // Phase 2: inject (saturation = 3 sequential injects)
    let n_iter = if scenario.starts_with("A4_saturation") { 3 } else { 1 };
    let mut raw_inject_all = String::new();
    for i in 0..n_iter {
        let cmd = format!("{REMOTE_WORKER_PATH} metadata_inject {tag} {fs} {vd} {block} {prob}");
        let r = ssh.exec_lenient(&cmd)
            .with_context(|| format!("metadata_inject ({fs}, {scenario}, iter={})", i + 1))?;
        if !r.contains("INJECT=OK") && !r.contains("INJECT=SKIP") {
            bail!("inject phase failed for {fs}/{scenario} iter={}: {r}", i + 1);
        }
        if i > 0 {
            raw_inject_all.push('\n');
        }
        raw_inject_all.push_str(&r);
    }

    // Phase 3: verify
    let verify_cmd = format!("{REMOTE_WORKER_PATH} metadata_verify {tag} {fs} {vd}");
    let raw_verify = ssh.exec_lenient(&verify_cmd)
        .with_context(|| format!("metadata_verify ({fs}, {scenario})"))?;
    let phase_ok = raw_verify.contains("VERIFY=OK") && raw_verify.contains("scheme=");

    Ok(MetadataObservation {
        fs: fs.to_string(),
        vd: vd.to_string(),
        scenario: scenario.to_string(),
        target_block: block,
        probability: prob,
        raw_setup,
        raw_inject: raw_inject_all,
        raw_verify,
        phase_ok,
    })
}

fn write_synthesis(run_dir: &PathBuf, observations: &[MetadataObservation]) -> Result<()> {
    let synth_path = run_dir.join("synthesis.md");
    let mut s = String::new();

    s.push_str("# beamfs-bench metadata synthesis\n\n");
    s.push_str("Test A: RadFI deterministic injection on metadata blocks.\n");
    s.push_str("Mode: measurement instrument (factual observations only).\n\n");

    s.push_str("## Topology\n\n");
    s.push_str("- compute01 (192.168.56.11) holds the 5 USB FS-test victims\n");
    s.push_str("- master is orchestrator (R-isolation enforced)\n\n");

    s.push_str("## Observation matrix (5 FS x 4 scenarios = 20 records)\n\n");
    s.push_str("| FS | VD | Scenario | Block | Prob | Phase | Raw verify |\n");
    s.push_str("|----|----|----------|-------|------|-------|------------|\n");
    for o in observations {
        let phase = if o.phase_ok { "OK" } else { "FAIL" };
        let verify_short: String = o.raw_verify.lines().next().unwrap_or("").chars().take(120).collect();
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | `{}` |\n",
            o.fs, o.vd, o.scenario, o.target_block, o.probability, phase, verify_short
        ));
    }
    s.push_str("\n");

    s.push_str("## Notes for analysis\n\n");
    s.push_str("- Verdict interpretation (recovered/corrupted/panicked) is the\n");
    s.push_str("  role of the analyst, not the bench. Parse fields below.\n");
    s.push_str("- beamfs scheme=5 (INODE_UNIVERSAL) protects metadata only;\n");
    s.push_str("  data block protection is Stage 4 future work. See\n");
    s.push_str("  Documentation/roadmap.md.\n");
    s.push_str("- DMESG_RS_CORRECTED counts kernel-logged FEC events.\n");
    s.push_str("- RS_JOURNAL_NEW_ENTRIES is parsed from beamfs superblock.\n\n");

    fs::write(&synth_path, s).context("write synthesis.md")?;

    let records_path = run_dir.join("all-records.txt");
    let mut r = String::new();
    for o in observations {
        r.push_str(&format!("--- {} / {} / {} ---\n", o.fs, o.vd, o.scenario));
        r.push_str(&format!("setup  : {}\n", o.raw_setup.trim()));
        r.push_str(&format!("inject : {}\n", o.raw_inject.trim()));
        r.push_str(&format!("verify : {}\n", o.raw_verify.trim()));
        r.push('\n');
    }
    fs::write(&records_path, r).context("write all-records.txt")?;

    Ok(())
}

pub fn run() -> Result<i32> {
    println!("================================================================");
    println!(" beamfs-bench metadata - Test A (RadFI deterministic on metadata)");
    println!(" Mode: measurement instrument (factual observations only)");
    println!(" Topology: compute01 (5 USB victims), master isolated");
    println!("================================================================");

    // Run dir setup
    let now = chrono::Local::now();
    let stamp = now.format("%Y%m%d-%H%M%S").to_string();
    let started_inst = Instant::now();
    let started_epoch = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let run_dir = PathBuf::from(format!(
        "/home/aurelien/git/yocto-beamfs/Documentation/runs/beamfs-bench-metadata-{stamp}"
    ));
    fs::create_dir_all(&run_dir).context("create run dir")?;
    println!("Run dir: {}", run_dir.display());

    println!();
    println!("[metadata] Deploying worker.sh on compute01...");
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
        for (scn_name, block, prob) in SCENARIOS {
            println!();
            println!("[metadata] {fs_name} / {scn_name} : target_block={block} prob={prob}");
            match run_scenario(fs_name, vd, scn_name, *block, *prob) {
                Ok(o) => {
                    let mark = if o.phase_ok { "OK" } else { "FAIL" };
                    println!("  [phase {mark}] verify: {}", o.raw_verify.trim());
                    observations.push(o);
                }
                Err(e) => {
                    eprintln!("  PHASE_ERROR for {fs_name}/{scn_name}: {e:#}");
                    observations.push(MetadataObservation {
                        fs: fs_name.to_string(),
                        vd: vd.to_string(),
                        scenario: scn_name.to_string(),
                        target_block: *block,
                        probability: *prob,
                        raw_setup: String::new(),
                        raw_inject: String::new(),
                        raw_verify: format!("PHASE_ERROR: {e:#}"),
                        phase_ok: false,
                    });
                }
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
    manifest.push_str(" beamfs-bench metadata manifest\n");
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
        let summary = o.raw_verify.trim().chars().take(140).collect::<String>();
        manifest.push_str(&format!("{tag} {}/{} : {summary}\n", o.fs, o.scenario));
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
        .context("write metadata manifest.txt")?;


    println!();
    println!("================================================================");
    println!(" metadata phase summary : {n_ok}/{} phases completed cleanly",
             observations.len());
    println!("================================================================");
    println!();
    println!(" Synthesis : {}/synthesis.md", run_dir.display());
    println!(" Records   : {}/all-records.txt", run_dir.display());
    println!();
    println!(" Note: bench reports observations only. Kernel behavior analysis");
    println!(" (recovered/corrupted/panicked) is performed post-run.");
    println!();

    if n_fail > 0 {
        for o in &observations {
            if !o.phase_ok {
                eprintln!("  PHASE_FAIL {}/{}", o.fs, o.scenario);
            }
        }
        return Err(anyhow!("{n_fail} metadata phase(s) failed technically"));
    }

    Ok(0)
}
