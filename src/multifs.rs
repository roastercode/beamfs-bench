//! multifs.rs — port of Tir-multifs.sh (5 FS x 3 probabilities).
//!
//! Orchestration phases (mirror bash exactly):
//!   1. Deploy worker.sh on master VM via scp.
//!   2. Setup phase: format + populate 5 partitions.
//!   3. Attack/verify phases: 15 (FS, prob) tuples.
//!   4. Synthesis report (synthesis.md + synthesis.json).
//!   5. Print summary, exit.
//!
//! Output format byte-identical to legacy run for diff-based parity
//! verification against Tir-multifs-20260430-141008/.

use anyhow::{Context, Result};
use chrono::Local;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::ssh::SshTarget;
use crate::synthesis;

/// Embedded worker bash script. Same content as Tir-multifs.sh inline
/// `cat > $WORKER << 'WORK_EOF' ... WORK_EOF` block, extracted to a
/// dedicated file under src/worker.sh and shipped via include_str!.
const WORKER_SH: &str = include_str!("worker.sh");

/// FS list in deterministic order (matches Tir-multifs.sh line 53).
const FS_LIST: &[(&str, &str)] = &[
    ("ext4",     "vdc"),
    ("ext3",     "vdd"),
    ("btrfs",    "vde"),
    ("squashfs", "vdf"),
    ("beamfs",   "vdg"),
];

/// Probabilities (matches Tir-multifs.sh line 54).
const PROBS: &[u32] = &[1000, 100000, 1000000];

const SSH_USER: &str = "hpcadmin";
const MASTER_IP: &str = "192.168.56.10";
const REMOTE_WORKER_PATH: &str = "/tmp/beamfs-bench-worker.sh";

pub fn run() -> Result<i32> {
    let ts = Local::now();
    let ts_compact = ts.format("%Y%m%d-%H%M%S").to_string();
    let ts_human = ts.format("%Y-%m-%d %H:%M:%S").to_string();

    // Resolve repo root: this binary is normally invoked from the repo,
    // but to keep parity with bash we anchor to the parent of bin/ if
    // the binary is in target/release/, otherwise the current working dir.
    let repo_root = locate_repo_root()
        .context("could not locate yocto-beamfs repo root")?;
    let run_dir = repo_root
        .join("Documentation/runs")
        .join(format!("Tir-multifs-{ts_compact}"));
    let per_fs_dir = run_dir.join("per-fs");
    fs::create_dir_all(&per_fs_dir)
        .with_context(|| format!("create_dir_all {:?}", per_fs_dir))?;

    // SSH target
    let key_path = std::env::var("HOME")
        .map(|h| format!("{h}/.ssh/hpclab_admin"))
        .context("HOME not set")?;
    let ssh = SshTarget::new(SSH_USER, MASTER_IP, &key_path);

    // Banner (color codes match bash)
    println!("================================================================");
    println!(" beamfs-bench multifs -- {ts_human}");
    println!("================================================================");
    println!("Run dir: {}", run_dir.display());
    println!("FS list: {}", fs_list_display());
    println!("Probs:   {}", probs_display());
    println!();

    // ----------------------------------------------------------------
    // Phase 1: deploy worker on master
    // ----------------------------------------------------------------
    blue("[1/5] Setup VMs: load modules + format 5 partitions + create test layout");

    let local_worker = std::env::temp_dir().join(format!("beamfs-bench-worker-{}.sh", std::process::id()));
    fs::write(&local_worker, WORKER_SH)
        .with_context(|| format!("write local worker {:?}", local_worker))?;
    ssh.scp_to(local_worker.to_str().unwrap(), REMOTE_WORKER_PATH)
        .context("scp worker to master")?;
    ssh.exec(&format!("chmod +x {REMOTE_WORKER_PATH}"))
        .context("chmod +x worker on master")?;
    let _ = fs::remove_file(&local_worker);

    // ----------------------------------------------------------------
    // Phase 2: setup all FS
    // ----------------------------------------------------------------
    blue("[2/5] Format + populate 5 partitions with 3 dirs x 3 files (3KB each)");
    for &(fs_name, vd) in FS_LIST {
        let cmd = format!("{REMOTE_WORKER_PATH} setup {fs_name} {vd} 0");
        let out = ssh.exec_lenient(&cmd)
            .with_context(|| format!("setup {fs_name} on {vd}"))?;
        println!("  {fs_name} ({vd}): {out}");

        let fs_dir = per_fs_dir.join(fs_name);
        fs::create_dir_all(&fs_dir)
            .with_context(|| format!("create_dir_all {:?}", fs_dir))?;
        write_text(&fs_dir.join("setup.txt"), &format!("{out}\n"))?;
    }

    // ----------------------------------------------------------------
    // Phase 3: per-FS, per-prob attacks
    // ----------------------------------------------------------------
    blue("[3/5] RadFI attacks: 5 FS x 3 probs = 15 runs");
    let all_records_path = run_dir.join("all-records.txt");
    // Reproduce bash: `echo "" > all-records.txt` -> file starts with one blank line.
    let mut all_records = fs::File::create(&all_records_path)
        .with_context(|| format!("create {:?}", all_records_path))?;
    writeln!(all_records).context("write blank line to all-records.txt")?;

    for &(fs_name, vd) in FS_LIST {
        let fs_dir = per_fs_dir.join(fs_name);
        let attacks_path = fs_dir.join("attacks.txt");
        let verifies_path = fs_dir.join("verifies.txt");
        let mut attacks_f = fs::File::create(&attacks_path)
            .with_context(|| format!("create {:?}", attacks_path))?;
        let mut verifies_f = fs::File::create(&verifies_path)
            .with_context(|| format!("create {:?}", verifies_path))?;

        for &prob in PROBS {
            let attack_cmd = format!("{REMOTE_WORKER_PATH} attack {fs_name} {vd} {prob}");
            let attack_out = ssh.exec_lenient(&attack_cmd)
                .with_context(|| format!("attack {fs_name} prob={prob}"))?;

            let verify_cmd = format!("{REMOTE_WORKER_PATH} verify {fs_name} {vd} 0");
            let verify_out = ssh.exec_lenient(&verify_cmd)
                .with_context(|| format!("verify {fs_name} prob={prob}"))?;

            println!("  {fs_name} prob={prob}: {attack_out}");
            println!("                {verify_out}");

            // all-records.txt: ATTACK| then VERIFY|fs=...|prob=...|...
            writeln!(all_records, "ATTACK|{attack_out}")?;
            writeln!(all_records, "VERIFY|fs={fs_name}|prob={prob}|{verify_out}")?;

            // per-fs attacks.txt and verifies.txt
            writeln!(attacks_f, "{attack_out}")?;
            writeln!(verifies_f, "{verify_out}")?;
        }
    }
    drop(all_records);

    // ----------------------------------------------------------------
    // Phase 4: synthesis report
    // ----------------------------------------------------------------
    blue("[4/5] Synthesis report");
    synthesis::write_synthesis_md(
        &run_dir,
        &ts_human,
        FS_LIST,
        PROBS,
        &per_fs_dir,
    ).context("write synthesis.md")?;
    synthesis::write_synthesis_json(
        &run_dir,
        &ts_human,
        &all_records_path,
    ).context("write synthesis.json")?;

    // Print synthesis.md to stdout (mirror bash `cat "$RUN_DIR/synthesis.md"`)
    let synth_md = fs::read_to_string(run_dir.join("synthesis.md"))
        .context("read back synthesis.md")?;
    print!("{synth_md}");

    // ----------------------------------------------------------------
    // Phase 5: exit
    // ----------------------------------------------------------------
    blue("[5/5] beamfs-bench multifs complete");
    println!();
    println!("Synthesis: {}", run_dir.join("synthesis.md").display());
    println!("JSON:      {}", run_dir.join("synthesis.json").display());
    println!("Records:   {}", run_dir.join("all-records.txt").display());

    Ok(0)
}

fn fs_list_display() -> String {
    FS_LIST.iter()
        .map(|(fs, vd)| format!("{fs}:{vd}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn probs_display() -> String {
    PROBS.iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn blue(msg: &str) {
    // Match bash blue() helper: \e[34m...\e[0m
    println!("\x1b[34m{msg}\x1b[0m");
}

fn write_text(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content)
        .with_context(|| format!("write {:?}", path))
}

/// Locate the yocto-beamfs repo root: walk up from the binary's location
/// (or CWD) until we find Documentation/ + bin/ + beamfs-bench/.
fn locate_repo_root() -> Result<PathBuf> {
    // Try CWD first (typical case: invoked from repo root or anywhere within)
    let cwd = std::env::current_dir().context("getcwd")?;
    if let Some(root) = walk_up_for_repo(&cwd) {
        return Ok(root);
    }

    // Fallback: walk up from the binary location
    if let Ok(exe) = std::env::current_exe() {
        if let Some(root) = walk_up_for_repo(&exe) {
            return Ok(root);
        }
    }

    Err(anyhow::anyhow!(
        "could not locate yocto-beamfs repo root (looked for Documentation/ + bin/ from {} and exe path)",
        cwd.display()
    ))
}

fn walk_up_for_repo(start: &Path) -> Option<PathBuf> {
    let mut cur = start.to_path_buf();
    if cur.is_file() {
        cur.pop();
    }
    loop {
        if cur.join("Documentation").is_dir()
            && cur.join("bin").is_dir()
            && cur.join("beamfs-bench").is_dir()
        {
            return Some(cur);
        }
        if !cur.pop() {
            return None;
        }
    }
}
