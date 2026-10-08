//! multifs.rs - port of Tir-multifs.sh (2 FS x 3 probabilities).
//!
//! ## Public API
//!
//!   - `MultifsConfig`: parameterizes a multifs run (FS list, probs, `run_dir` prefix,
//!     security flags: `auto_confirm/dry_run/vm_name`)
//!   - `MultifsResult`: returned to callers (analyse.rs) for follow-up forensic capture
//!   - `run()`: convenience entry for `Cli::Multifs` (uses default config)
//!   - `run_with_config()`: full API, used by analyse.rs
//!
//! ## Security pipeline (anti-NAK / R12 of context-recadrage)
//!
//!   1. Resolve authoritative (vd -> usb-by-id) mapping via `virsh dumpxml`
//!      on the host. THIS HAPPENS BEFORE ANY DESTRUCTIVE ACTION.
//!   2. Render the validation table to the user.
//!   3. Prompt [y/N] (default = N = abort), unless --auto-confirm is set.
//!   4. Persist the validated mapping in run_dir/devices-validated.txt as
//!      audit trail.
//!   5. ONLY THEN: deploy worker on master, run setup/attack/verify.
//!
//! Output format (synthesis.md, synthesis.json, all-records.txt, per-fs/...) is
//! byte-identical to legacy Tir-multifs.sh for diff-based parity verification
//! against reference run beamfs-bench-analyse-20260430-141008/.

use anyhow::{Context, Result};
use chrono::Local;
use std::fs;
use std::collections::HashMap;

/// S3.1: parsed payload from the SETUP record echo emitted by
/// `worker.sh::setup` case. Captures the file-precise injection range
/// computed via filefrag during setup, to be propagated to attack
/// phase as env vars (`TARGET_BLOCK_RANGE_START` / _END).
#[derive(Debug, Clone, Default)]
struct SetupParse {
    target_block_range_start: u64,
    target_block_range_end: u64,
    /// v0.12.3: "yes" if a cold read of the target emitted bios on the
    /// filesystem's own device, "no" if it was served entirely from cache
    /// (erofs, vfat), "unknown" if the probe could not run.
    reachable: String,
    /// Per-extent "start:end,start:end" sector intervals covering the whole
    /// target file. Needed by the attack phase to count how many flips
    /// landed inside the file, which the single interval above cannot do:
    /// a fragmented file spans several disjoint extents and the interval
    /// spans everything between the first and the last, most of which
    /// belongs to other files.
    target_ranges: String,
}

/// Parse a key=value| pipe-delimited setup record into `SetupParse`.
/// Unknown keys are ignored. Missing range keys default to 0/0
/// (= range filter inactive, broadcast fallback preserved).
fn parse_setup_record(out: &str) -> SetupParse {
    let mut parsed = SetupParse::default();
    for tok in out.trim().split('|') {
        if let Some((k, v)) = tok.split_once('=') {
            match k {
                "TARGET_BLOCK_RANGE_START" => {
                    parsed.target_block_range_start = v.trim().parse().unwrap_or(0);
                }
                "TARGET_BLOCK_RANGE_END" => {
                    parsed.target_block_range_end = v.trim().parse().unwrap_or(0);
                }
                "REACHABLE" => {
                    parsed.reachable = v.trim().to_string();
                }
                "TARGET_RANGES" => {
                    parsed.target_ranges = v.trim().to_string();
                }
                _ => {}
            }
        }
    }
    parsed
}
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::devices::{self, ProposedMapping};
use crate::ssh::SshTarget;
use crate::synthesis;

const WORKER_SH: &str = include_str!("worker.sh");

/// Public accessor for the embedded worker.sh content.
/// Used by `cluster.rs` to deploy the same worker on compute nodes
/// without duplicating the `include_str!` macro invocation.
pub fn worker_sh() -> &'static str {
    WORKER_SH
}

/// Default probabilities (matches Tir-multifs.sh line 54).
pub const DEFAULT_PROBS: &[u32] = &[1_000, 100_000, 1_000_000];

/// v3 campaign : read `BEAMFS_BENCH_PROBS` env var and parse as comma-separated
/// list of u32 ppm values. Fallback to `DEFAULT_PROBS` if env var is unset or
/// invalid. Used by `MultifsConfig::default()` and `run_with_mapping()` callers.
/// Format : "100,1000,10000,100000,500000,1000000" (no spaces).
pub fn resolve_probs() -> Vec<u32> {
    match std::env::var("BEAMFS_BENCH_PROBS") {
        Ok(env_val) if !env_val.trim().is_empty() => {
            let parsed: Result<Vec<u32>, _> = env_val
                .split(',')
                .map(|s| s.trim().parse::<u32>())
                .collect();
            match parsed {
                Ok(v) if !v.is_empty() => v,
                _ => {
                    eprintln!(
                        "[multifs] WARN : BEAMFS_BENCH_PROBS=\"{env_val}\" failed to parse ; falling back to DEFAULT_PROBS"
                    );
                    DEFAULT_PROBS.to_vec()
                }
            }
        }
        _ => DEFAULT_PROBS.to_vec(),
    }
}

pub const MULTIFS_TARGET_IP: &str = "192.168.56.11";  // compute01 holds the 5 USB sticks (isolation per recadrage R-isolation)
pub const REMOTE_WORKER_PATH: &str = "/tmp/beamfs-bench-worker.sh";
pub const DEFAULT_VM_NAME: &str = "beamfs-compute01";

/// Configuration for a multifs run.
#[derive(Clone, Debug)]
pub struct MultifsConfig {
    /// libvirt domain name to query for the (vd -> by-id) mapping.
    pub vm_name: String,
    /// FS slot definitions: (`fs_name`, `guest_dev`). Matched against `virsh dumpxml`.
    pub fs_list: Vec<(String, String)>,
    /// Probabilities (in ppm) to sweep.
    pub probs: Vec<u32>,
    /// Run directory prefix under Documentation/runs/.
    pub run_dir_prefix: String,
    /// SSH user on master VM.
    pub ssh_user: String,
    /// Master VM IP.
    pub master_ip: String,
    /// Path to SSH private key.
    pub ssh_key_path: String,
    /// If true, skip the prompt and proceed (for CI / scripted use).
    pub auto_confirm: bool,
    /// If true, render the validation table and EXIT WITHOUT PROMPTING.
    pub dry_run: bool,
    /// If true, skip the worker deploy (used by analyse.rs which deploys once).
    pub skip_worker_deploy: bool,
    /// If true, suppress trailing print/cat of synthesis.md to stdout.
    pub suppress_synthesis_print: bool,
    /// If Some, skip the discover/validate prompt entirely and use these
    /// pre-validated mappings (used by analyse.rs which validates once).
    pub pre_validated_mappings: Option<Vec<ProposedMapping>>,
    /// Fault injector to use: "radfi" (legacy SEU baseline) or "emufi"
    /// (MBU-capable successor). Propagated to worker.sh via INJECTOR env.
    /// Default: "radfi".
    pub injector: String,
}

impl Default for MultifsConfig {
    fn default() -> Self {
        let key_path = crate::lab::ssh_key().to_string();
        Self {
            vm_name: DEFAULT_VM_NAME.to_string(),
            // L5 : fs_list is now built at runtime by usb_health::build_fs_mapping
            // from the actual healthy USB count. Default is empty ; callers
            // (cmd_full, Cli::Multifs) populate it after Phase 0.0a probing.
            fs_list: Vec::new(),
            probs: resolve_probs(),
            injector: "emufi".to_string(),
            run_dir_prefix: "beamfs-bench-multifs".to_string(),
            ssh_user: crate::lab::ssh_user().to_string(),
            master_ip: MULTIFS_TARGET_IP.to_string(),
            ssh_key_path: key_path,
            auto_confirm: false,
            dry_run: false,
            skip_worker_deploy: false,
            suppress_synthesis_print: false,
            pre_validated_mappings: None,
        }
    }
}

impl MultifsConfig {
    /// Quick mode: single probability (1000000 ppm = saturation).
    /// Currently unused inside the binary (analyse.rs builds its own `MultifsConfig`
    /// inline) but kept as a documented public API for external callers / tests.
    #[allow(dead_code)]
    pub fn quick() -> Self {
        Self {
            probs: vec![1_000_000],
            ..Self::default()
        }
    }
}

/// Result of a multifs run. Returned to analyse.rs for forensic capture.
/// Note: the non-`run_dir` fields are part of the public API contract for
/// downstream callers (logging, audit trails, future test scopes), even if
/// the current analyse.rs implementation only happens to consume `run_dir`.
#[derive(Debug)]
#[allow(dead_code)]
pub struct MultifsResult {
    pub run_dir: PathBuf,
    pub ts_compact: String,
    pub ts_human: String,
    pub validated_mappings: Vec<ProposedMapping>,
}

/// Convenience entry for `Cli::Multifs`. Uses default config.
/// L5 deprecation note : prefer `run_with_mapping()` which accepts a runtime
/// `fs_list`. This function is kept for callers that want the legacy behaviour
/// (empty `fs_list` -> error from analyse). Currently unused by `Cli::Multifs`
/// since L5 ; kept public for back-compat with external callers.
#[allow(dead_code)]
pub fn run(auto_confirm: bool, dry_run: bool, injector: &str) -> Result<i32> {
    let cfg = MultifsConfig {
        auto_confirm,
        dry_run,
        injector: injector.to_string(),
        ..MultifsConfig::default()
    };
    let _result = run_with_config(&cfg)?;
    Ok(0)
}

/// L5 entry for `Cli::Multifs` : accepts a runtime `fs_list` mapping built
/// from `usb_health::build_fs_mapping()`. This replaces the legacy `run()`
/// for the default invocation path (`cmd_full` -> analyse uses
/// `run_with_config` directly, not this function).
pub fn run_with_mapping(
    auto_confirm: bool,
    dry_run: bool,
    injector: &str,
    fs_list: Vec<(String, String)>,
) -> Result<i32> {
    let cfg = MultifsConfig {
        auto_confirm,
        dry_run,
        injector: injector.to_string(),
        fs_list,
        ..MultifsConfig::default()
    };
    let _result = run_with_config(&cfg)?;
    Ok(0)
}

/// Where the physics simulator lives.
///
/// A sibling checkout of this repository, which is where it is on the
/// station and where anybody reproducing a campaign would put it.
/// BEAMFS_BENCH_RADSIM names it elsewhere.
fn radsim_path() -> String {
    if let Ok(v) = std::env::var("BEAMFS_BENCH_RADSIM") {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/aurelien".to_string());
    format!("{home}/git/emufi/userspace/emufi-physics/target/release/emufi-radsim")
}

/// Where the node expects the campaign blob.
const CAMPAIGN_REMOTE: &str = "/tmp/emufi-campaign.bin";

/// Generate a physics campaign over the target file's extents and push
/// it to the node.
///
/// Event count, incident energy and seed come from the environment
/// (PHYSICS_EVENTS, PHYSICS_ENERGY_MEV, PHYSICS_SEED) so a campaign can
/// be varied without rebuilding.
///
/// Returns the number of events generated.
fn generate_campaign(ranges: &str, ssh: &SshTarget) -> Result<usize> {
    // DEPLOYMENT, when set, derives the count from flux, cross-section
    // and exposure time rather than taking it as given. A campaign
    // then reads as "six months in a linac vault" instead of "64
    // flips", which is the difference between a number an integrator
    // can act on and one that only compares runs of this harness.
    //
    // PHYSICS_EVENTS still wins when DEPLOYMENT is absent: an operator
    // who wants exactly 64 asks for 64.
    let exposure = crate::dose::Exposure::from_env();
    let n = if let Some(e) = exposure {
        let c = e.event_count();
        println!("[multifs] exposure: {}", e.manifest_line(0.0));
        if e.deployment.is_estimated() {
            println!(
                "[multifs] WARN : the flux factor for {} is an estimate, not a site survey",
                e.deployment.as_str()
            );
        }
        usize::try_from(c).unwrap_or(usize::MAX)
    } else {
        std::env::var("PHYSICS_EVENTS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(64)
    };
    let energy = std::env::var("PHYSICS_ENERGY_MEV").unwrap_or_else(|_| "14.0".into());
    let seed = std::env::var("PHYSICS_SEED").unwrap_or_else(|_| "3735928559".into());

    let local = "/tmp/emufi-campaign.bin";
    let out = std::process::Command::new(radsim_path())
        .args([
            "--seed", &seed,
            "campaign",
            "--ranges", ranges,
            "--n", &n.to_string(),
            "--energy-mev", &energy,
        ])
        .output()
        .with_context(|| format!("spawn {}", radsim_path()))?;
    if !out.status.success() {
        anyhow::bail!(
            "emufi-radsim failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    std::fs::write(local, &out.stdout)
        .with_context(|| format!("write {local}"))?;

    ssh.scp_to(local, CAMPAIGN_REMOTE)
        .with_context(|| format!("push campaign to {CAMPAIGN_REMOTE}"))?;

    Ok(out.stdout.len() / 16)
}

pub fn run_with_config(cfg: &MultifsConfig) -> Result<MultifsResult> {
    let ts = Local::now();
    let ts_compact = ts.format("%Y%m%d-%H%M%S").to_string();
    let ts_human = ts.format("%Y-%m-%d %H:%M:%S").to_string();

    let repo_root = locate_repo_root()
        .context("could not locate yocto-beamfs repo root")?;

    // ----------------------------------------------------------------
    // Step 0: device validation (pre-flight, before any RUN_DIR creation)
    // If caller already validated (pre_validated_mappings is Some), skip.
    // Otherwise, call discover_and_validate which prompts the user.
    // dry_run aborts here without creating any directories.
    // ----------------------------------------------------------------
    let validated: Vec<ProposedMapping> = if let Some(m) = &cfg.pre_validated_mappings {
        eprintln!("beamfs-bench: using pre-validated mappings from caller ({} entries)", m.len());
        m.clone()
    } else {
        let fs_list_refs: Vec<(&str, &str)> = cfg.fs_list.iter()
            .map(|(f, v)| (f.as_str(), v.as_str()))
            .collect();
        devices::discover_and_validate(
            &cfg.vm_name,
            &fs_list_refs,
            cfg.auto_confirm,
            cfg.dry_run,
        )?
    };

    // From here on, RUN_DIR is created and destructive actions begin.
    let run_dir = repo_root
        .join("Documentation/runs")
        .join(format!("{}-{}", cfg.run_dir_prefix, ts_compact));
    let per_fs_dir = run_dir.join("per-fs");
    fs::create_dir_all(&per_fs_dir)
        .with_context(|| format!("create_dir_all {}", per_fs_dir.display()))?;

    // Persist the validated mapping as audit trail.
    persist_validated_mapping(&run_dir, &cfg.vm_name, &validated)?;

    let ssh = SshTarget::new(&cfg.ssh_user, &cfg.master_ip, &cfg.ssh_key_path);

    println!("================================================================");
    println!(" beamfs-bench multifs -- {ts_human}");
    println!("================================================================");
    println!("Run dir: {}", run_dir.display());
    println!("FS list: {}", validated_display(&validated));
    println!("Probs:   {}", probs_display(&cfg.probs));
    println!();

    // ----------------------------------------------------------------
    // Phase 1: deploy worker (skipped if caller already did it)
    // ----------------------------------------------------------------
    if cfg.skip_worker_deploy {
        blue("[1/5] Worker deployment skipped (caller-managed)");
    } else {
        blue("[1/5] Setup VMs: load modules + format 5 partitions + create test layout");
        deploy_worker(&ssh).context("deploy worker on master")?;
    }

    // ----------------------------------------------------------------
    // Phase 2: setup all FS
    // ----------------------------------------------------------------
    blue("[2/5] Format + populate 5 partitions with 3 dirs x 3 files (3KB each)");
    // S3.1: collect per-FS file-precise injection range from SETUP records.
    let mut setup_parsed: HashMap<String, SetupParse> = HashMap::new();
    for m in &validated {
        let cmd = crate::cluster::worker_cmd(&cfg.injector, &format!("setup {} {}", m.fs_name, m.disk.guest_dev));
        let out = ssh.exec_lenient(&cmd)
            .with_context(|| format!("setup {} on {}", m.fs_name, m.disk.guest_dev))?;
        println!("  {} ({}): {out}", m.fs_name, m.disk.guest_dev);

        let fs_dir = per_fs_dir.join(&m.fs_name);
        fs::create_dir_all(&fs_dir)
            .with_context(|| format!("create_dir_all {}", fs_dir.display()))?;
        write_text(&fs_dir.join("setup.txt"), &format!("{out}\n"))?;
        // S3.1: parse and store the range for later propagation.
        setup_parsed.insert(m.fs_name.clone(), parse_setup_record(&out));
    }

    // ----------------------------------------------------------------
    // Phase 3: per-FS, per-prob attacks
    // ----------------------------------------------------------------
    let n_runs = validated.len() * cfg.probs.len();
    blue(&format!("[3/5] {} attacks: {} FS x {} probs = {} runs",
                  cfg.injector, validated.len(), cfg.probs.len(), n_runs));

    let all_records_path = run_dir.join("all-records.txt");
    let mut all_records = fs::File::create(&all_records_path)
        .with_context(|| format!("create {}", all_records_path.display()))?;
    writeln!(all_records).context("write blank line to all-records.txt")?;

    for m in &validated {
        let fs_dir = per_fs_dir.join(&m.fs_name);
        let attacks_path = fs_dir.join("attacks.txt");
        let verifies_path = fs_dir.join("verifies.txt");
        let mut attacks_f = fs::File::create(&attacks_path)
            .with_context(|| format!("create {}", attacks_path.display()))?;
        let mut verifies_f = fs::File::create(&verifies_path)
            .with_context(|| format!("create {}", verifies_path.display()))?;

        // S3.1: set TARGET_BLOCK_RANGE_* env vars from per-FS SETUP parse.
        let setup_p = setup_parsed.get(&m.fs_name).cloned().unwrap_or_default();
        let range_active = setup_p.target_block_range_end > setup_p.target_block_range_start;
        if range_active {
            std::env::set_var("TARGET_BLOCK_RANGE_START", setup_p.target_block_range_start.to_string());
            std::env::set_var("TARGET_BLOCK_RANGE_END",   setup_p.target_block_range_end.to_string());
        } else {
            std::env::remove_var("TARGET_BLOCK_RANGE_START");
            std::env::remove_var("TARGET_BLOCK_RANGE_END");
        }
        // TARGET_RANGES was forwarded by worker_cmd but never set on this
        // path, so the attack phase saw it empty and reported
        // FLIPS_ON_TARGET=na for every filesystem. It carries the whole
        // extent list, which is what tells apart "the filesystem protected
        // the file" from "nothing hit the file" -- the distinction the
        // cross-filesystem comparison rests on.
        if setup_p.target_ranges.is_empty() {
            std::env::remove_var("TARGET_RANGES");
        } else {
            std::env::set_var("TARGET_RANGES", &setup_p.target_ranges);
        }

        // PHYSICS_DRIVEN: generate the campaign here, where the target
        // file's extents are known, and push it to the node. The
        // generator is x86_64 and the nodes are aarch64, but a campaign
        // is a list of absolute byte offsets on the device under test --
        // where it was computed does not enter into it, and determinism
        // comes from the seed.
        //
        // A generation failure is not fatal: the worker falls back to
        // probabilistic placement when the blob is absent.
        if std::env::var("PHYSICS_DRIVEN").as_deref() == Ok("1")
            && !setup_p.target_ranges.is_empty()
        {
            match generate_campaign(&setup_p.target_ranges, &ssh) {
                Ok(n) => println!("  {} : campaign of {n} events pushed", m.fs_name),
                Err(e) => eprintln!("  {} : campaign generation failed: {e:#}", m.fs_name),
            }
        }

        for &prob in &cfg.probs {
            let attack_cmd = crate::cluster::worker_cmd(&cfg.injector,
                &format!("attack {} {} {prob}", m.fs_name, m.disk.guest_dev));
            let attack_out = ssh.exec_lenient(&attack_cmd)
                .with_context(|| format!("attack {} prob={prob}", m.fs_name))?;

            let verify_cmd = crate::cluster::worker_cmd(&cfg.injector,
                &format!("verify {} {}", m.fs_name, m.disk.guest_dev));
            let verify_out = ssh.exec_lenient(&verify_cmd)
                .with_context(|| format!("verify {} prob={prob}", m.fs_name))?;

            println!("  {} prob={prob}: {attack_out}", m.fs_name);
            println!("                {verify_out}");

            writeln!(all_records, "ATTACK|{attack_out}")?;
            writeln!(all_records, "VERIFY|fs={}|prob={prob}|{verify_out}", m.fs_name)?;

            writeln!(attacks_f, "{attack_out}")?;
            writeln!(verifies_f, "{verify_out}")?;
        }
    }
    drop(all_records);
    clear_target_env();

    // ----------------------------------------------------------------
    // Phase 4: synthesis report
    // ----------------------------------------------------------------
    blue("[4/5] Synthesis report");
    let fs_list_refs: Vec<(&str, &str)> = validated.iter()
        .map(|m| (m.fs_name.as_str(), m.disk.guest_dev.as_str()))
        .collect();
    let probs_owned: Vec<u32> = cfg.probs.clone();
    synthesis::write_synthesis_md(
        &run_dir,
        &ts_human,
        &fs_list_refs,
        &probs_owned,
        &per_fs_dir,
    ).context("write synthesis.md")?;
    synthesis::write_synthesis_json(
        &run_dir,
        &ts_human,
        &all_records_path,
    ).context("write synthesis.json")?;

    if !cfg.suppress_synthesis_print {
        let synth_md = fs::read_to_string(run_dir.join("synthesis.md"))
            .context("read back synthesis.md")?;
        print!("{synth_md}");
    }

    // ----------------------------------------------------------------
    // Phase 5: exit
    // ----------------------------------------------------------------
    blue("[5/5] beamfs-bench multifs complete");
    println!();
    println!("Synthesis: {}", run_dir.join("synthesis.md").display());
    println!("JSON:      {}", run_dir.join("synthesis.json").display());
    println!("Records:   {}", run_dir.join("all-records.txt").display());

    // Ingest into the measurement database. A failure here must not fail
    // the run: the records on disk remain the source of truth and can be
    // ingested later with `beamfs-bench db ingest`.
    {
        let db_path = crate::db::default_db_path();
        match crate::db::init(&db_path)
            .and_then(|()| crate::db::ingest_run_dir(&db_path, &run_dir, None))
        {
            Ok(id) => println!("DB:        run #{id} -> {}", db_path.display()),
            Err(e) => eprintln!("[multifs] WARN : database ingest skipped: {e:#}"),
        }
    }

    Ok(MultifsResult {
        run_dir,
        ts_compact,
        ts_human,
        validated_mappings: validated,
    })
}

/// Persist the validated (vd, by-id) mapping into `<run_dir>/devices-validated.txt`
/// for later audit/repro. Mirror format that humans + diff tools both like.
fn persist_validated_mapping(
    run_dir: &Path,
    vm_name: &str,
    validated: &[ProposedMapping],
) -> Result<()> {
    let path = run_dir.join("devices-validated.txt");
    let mut f = fs::File::create(&path)
        .with_context(|| format!("create {}", path.display()))?;
    writeln!(f, "# beamfs-bench device validation audit")?;
    writeln!(f, "# vm        : {vm_name}")?;
    writeln!(f, "# generated : {}", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(f, "# format    : <fs>|<guest_dev>|<host_resolved>|<host_size>|<host_byid>")?;
    writeln!(f)?;
    for m in validated {
        let resolved = m.disk.host_resolved.as_ref().map_or_else(|| "?".to_string(), |p| p.display().to_string());
        let size = m.disk.host_size.as_deref().unwrap_or("?");
        writeln!(f, "{}|{}|{}|{}|{}",
                 m.fs_name,
                 m.disk.guest_dev,
                 resolved,
                 size,
                 m.disk.host_byid_path)?;
    }
    Ok(())
}

/// Deploy the embedded worker.sh to a target via SSH.
pub fn deploy_worker(ssh: &SshTarget) -> Result<()> {
    let local_worker = std::env::temp_dir()
        .join(format!("beamfs-bench-worker-{}.sh", std::process::id()));
    fs::write(&local_worker, WORKER_SH)
        .with_context(|| format!("write local worker {}", local_worker.display()))?;
    ssh.scp_to(local_worker.to_str().unwrap(), REMOTE_WORKER_PATH)
        .context("scp worker to target")?;
    ssh.exec(&format!("chmod +x {REMOTE_WORKER_PATH}"))
        .context("chmod +x worker on target")?;
    let _ = fs::remove_file(&local_worker);
    Ok(())
}

fn validated_display(validated: &[ProposedMapping]) -> String {
    validated.iter()
        .map(|m| format!("{}:{}", m.fs_name, m.disk.guest_dev))
        .collect::<Vec<_>>()
        .join(" ")
}

fn probs_display(probs: &[u32]) -> String {
    probs.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join(" ")
}

fn blue(msg: &str) {
    println!("\x1b[34m{msg}\x1b[0m");
}

fn write_text(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).with_context(|| format!("write {}", path.display()))
}

/// Remove every targeting variable the per-filesystem loop sets.
///
/// Until 0.14.7 this removed `TARGET_BLOCK_RANGE_START` and `_END` and
/// left `TARGET_RANGES` behind. On 2026-10-05 it still held btrfs's
/// extents (28672:29184, a USB stick on compute01) when the cluster
/// phase ran; `worker_cmd` forwarded it to the four nodes, emufi gives
/// the list precedence over the interval, and every read of /data was
/// rejected by the filter: `call_count` 0 and `skipped_filter` 12863 on
/// the master, twelve cluster cells `NOT_EXERCISED`.
pub(crate) fn clear_target_env() {
    for var in ["TARGET_BLOCK_RANGE_START", "TARGET_BLOCK_RANGE_END", "TARGET_RANGES"] {
        std::env::remove_var(var);
    }
}

pub fn locate_repo_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("getcwd")?;
    if let Some(root) = walk_up_for_repo(&cwd) {
        return Ok(root);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(root) = walk_up_for_repo(&exe) {
            return Ok(root);
        }
    }
    Err(anyhow::anyhow!("could not locate yocto-beamfs repo root from {} or exe path", cwd.display()))
}

fn walk_up_for_repo(start: &Path) -> Option<PathBuf> {
    let mut cur = start.to_path_buf();
    if cur.is_file() { cur.pop(); }
    loop {
        if cur.join("Documentation").is_dir()
            && cur.join("bin").is_dir()
            && cur.join("beamfs-bench").is_dir()
        {
            return Some(cur);
        }
        if !cur.pop() { return None; }
    }
}

#[cfg(test)]
mod tests_phase_a5 {
    use super::*;

    /// Phase A.5: verify worker.sh embeds the `SB_READ_LOOPS` guard for
    /// SB-targeted I/O burst (RS saturation campaign).
    #[test]
    fn worker_sh_contains_sb_read_loops_guard() {
        let w = worker_sh();
        assert!(
            w.contains("SB_READ_LOOPS"),
            "worker.sh must reference SB_READ_LOOPS env var"
        );
        assert!(
            w.contains("iflag=direct"),
            "worker.sh must use iflag=direct for cache bypass on SB reads"
        );
        assert!(
            w.contains("A.5 SB burst"),
            "worker.sh must include the A.5 INFO marker for run logs"
        );
    }
}

#[cfg(test)]
mod tests_cluster_targeting {
    use super::*;

    /// worker.sh's `fiemap_ranges`, run by bash on a `filefrag -v -b4096`
    /// listing.
    fn fiemap_ranges(listing: &str) -> String {
        let w = worker_sh();
        let start = w
            .find("fiemap_ranges() {")
            .expect("worker.sh defines fiemap_ranges");
        let len = w[start..]
            .find("\n}\n")
            .expect("fiemap_ranges is closed");
        let script = format!(
            "{}\n}}\nprintf '%s\\n' \"$LISTING\" | fiemap_ranges",
            &w[start..start + len]
        );
        let out = std::process::Command::new("bash")
            .args(["-c", &script])
            .env("LISTING", listing)
            .output()
            .expect("bash runs");
        assert!(out.status.success(), "fiemap_ranges failed: {out:?}");
        String::from_utf8(out.stdout).expect("utf-8")
    }

    /// The `cluster_attack` branch of worker.sh, up to its `;;`.
    fn cluster_attack_section() -> &'static str {
        let w = worker_sh();
        let start = w
            .find("\ncluster_attack)")
            .expect("worker.sh has a cluster_attack action");
        let len = w[start..]
            .find("\n    ;;\n")
            .expect("cluster_attack ends with ;;");
        &w[start..start + len]
    }

    #[test]
    fn fiemap_ranges_gives_each_extent_in_sectors() {
        // Two extents of a fragmented file, as ext3 laid one out in the
        // 2026-08-28 campaign: 16 blocks at 3277377, 48 at 18160.
        let ext3 = "\
Filesystem type is: ef53
File size of /mnt/f is 262144 (64 blocks of 4096 bytes)
 ext:     logical_offset:        physical_offset: length:   expected: flags:
   0:        0..      15:    3277377..   3277392:     16:
   1:       16..      63:      18160..     18207:     48:    3277393: last,eof
/mnt/f: 2 extents found
";
        assert_eq!(fiemap_ranges(ext3), "26219016:26219144,145280:145664");

        // beamfs reports one extent per block: the form the multifs
        // records carry, 2052992:2053000,2053000:2053008,...
        let beamfs = "\
 ext:     logical_offset:        physical_offset: length:   expected: flags:
   0:        0..       0:     256624..    256624:      1:
   1:        1..       1:     256625..    256625:      1:
";
        assert_eq!(fiemap_ranges(beamfs), "2052992:2053000,2053000:2053008");

        // No extent, no list: the caller must not mistake it for one.
        assert_eq!(fiemap_ranges("/data/x: No such file or directory\n"), "");
    }

    #[test]
    fn cluster_attack_targets_its_own_extents_not_the_environment() {
        let a = cluster_attack_section();
        assert!(
            !a.contains("${TARGET_RANGES}"),
            "cluster_attack must not pose the TARGET_RANGES forwarded from the \
             host: that is the multifs loop's last filesystem, not this node's file"
        );
        assert!(
            a.contains("fiemap_ranges"),
            "cluster_attack must compute the list from this node's own file"
        );
        assert!(
            a.contains("reason=target_extents_unavailable"),
            "without a list, the attack must not run under the module's previous one"
        );
    }

    #[test]
    fn cluster_attack_reports_the_ranges_it_posed() {
        let a = cluster_attack_section();
        let line = a
            .lines()
            .find(|l| l.contains("echo \"CLUSTER|HOST=$(hostname)|PROB="))
            .expect("cluster_attack emits its CLUSTER record");
        assert!(
            line.contains("|TARGET_RANGES=$CL_TARGET_RANGES"),
            "the record must say which sectors the injector was told to hit"
        );
    }

    #[test]
    fn the_multifs_loop_leaves_no_target_behind() {
        for var in ["TARGET_BLOCK_RANGE_START", "TARGET_BLOCK_RANGE_END", "TARGET_RANGES"] {
            std::env::set_var(var, "28672");
        }
        clear_target_env();
        for var in ["TARGET_BLOCK_RANGE_START", "TARGET_BLOCK_RANGE_END", "TARGET_RANGES"] {
            assert!(std::env::var(var).is_err(), "{var} survived the multifs loop");
        }
    }
}
