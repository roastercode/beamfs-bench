//! mega.rs - Test E: consolidated single-tarball mega run.
//!
//! Pipeline phases 0.0..0.7 (with build log capture), analyse Full,
//! bitrot, metadata, crash, fsck, plus extended forensics (Yocto build
//! logs, kernel config, modinfo, git HEADs) all consolidated under one
//! run dir, then a single tarball:
//!
//! ```text
//! /tmp/beamfs-bench-mega-YYYYMMDD-HHMMSS.tar.gz
//! ```
//!
//! All sub-scope run dirs are detected post-creation and moved into the
//! mega run dir (sub-scopes are unmodified, they keep their own logic).

use anyhow::{anyhow, Context, Result};
use chrono::Local;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::analyse;
use crate::bitrot;
use crate::cluster;
use crate::crash;
use crate::forensics::{self, Scope};
use crate::fsck;
use crate::lifecycle;
use crate::metadata;
use crate::multifs;
use crate::pipeline;

const RUNS_DIR: &str = "/home/aurelien/git/yocto-beamfs/Documentation/runs";

fn list_run_dirs_with_prefix(prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(RUNS_DIR) {
        for entry in rd.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(prefix) {
                    out.push(name.to_string());
                }
            }
        }
    }
    out.sort();
    out
}

fn detect_new_run_dir(prefix: &str, before: &[String]) -> Option<String> {
    let after = list_run_dirs_with_prefix(prefix);
    after.into_iter().find(|d| !before.contains(d))
}

fn relocate_run_dir(prefix: &str, before: &[String], mega_dir: &Path, sub_name: &str) {
    match detect_new_run_dir(prefix, before) {
        Some(new_basename) => {
            let src = Path::new(RUNS_DIR).join(&new_basename);
            let dst = mega_dir.join(sub_name);
            match fs::rename(&src, &dst) {
                Ok(_) => println!("[mega]  relocated {sub_name}: {} -> {}",
                                  new_basename, dst.display()),
                Err(e) => eprintln!("[mega]  WARN: rename {} -> {}: {e:#}",
                                    src.display(), dst.display()),
            }
        }
        None => eprintln!("[mega]  WARNING: no new {prefix}* dir found"),
    }
}

#[derive(Debug, Default)]
struct PhaseResult {
    name: String,
    rc: i32,
    duration_secs: u64,
    note: String,
}

fn capture_env(env_dir: &Path) -> Result<()> {
    fs::create_dir_all(env_dir).context("create env dir")?;

    let uname = Command::new("uname").arg("-a").output().context("uname")?;
    fs::write(env_dir.join("uname.txt"), uname.stdout)?;

    fs::write(env_dir.join("bench-version.txt"),
        format!("beamfs-bench {}\n", env!("CARGO_PKG_VERSION")))?;

    for (name, repo) in [
        ("beamfs",       "/home/aurelien/git/beamfs"),
        ("yocto-beamfs", "/home/aurelien/git/yocto-beamfs"),
        ("beamfs-bench", "/home/aurelien/git/beamfs-bench"),
    ] {
        let head = Command::new("git").args(["-C", repo, "log", "-1", "--format=%H %s"])
            .output().with_context(|| format!("git log {repo}"))?;
        let status = Command::new("git").args(["-C", repo, "status", "-s"])
            .output().with_context(|| format!("git status {repo}"))?;
        let mut s = String::new();
        s.push_str(&format!("# repo: {repo}\n"));
        s.push_str(&format!("HEAD: {}", String::from_utf8_lossy(&head.stdout)));
        s.push_str("status -s:\n");
        s.push_str(&String::from_utf8_lossy(&status.stdout));
        fs::write(env_dir.join(format!("git-{name}.txt")), s)?;
    }

    let env_dump = Command::new("env").output().context("env")?;
    fs::write(env_dir.join("host-env.txt"), env_dump.stdout)?;
    Ok(())
}

fn capture_yocto_build_logs(build_dir: &Path) -> Result<()> {
    fs::create_dir_all(build_dir).context("create build dir")?;
    let yocto_temp = [
        ("beamfs-module",
         "/home/aurelien/yocto/poky/build-qemu-arm64/tmp/work/qemuarm64-poky-linux/beamfs-module/0.1.0/temp"),
        ("hpc-arm64-research-beamfs",
         "/home/aurelien/yocto/poky/build-qemu-arm64/tmp/work/qemuarm64-poky-linux/hpc-arm64-research-beamfs/1.0/temp"),
    ];
    for (recipe, src_temp) in &yocto_temp {
        let dst = build_dir.join(format!("yocto-{recipe}-temp"));
        let _ = fs::create_dir_all(&dst);
        let cmd = format!("cp -L {src_temp}/log.do_* {src_temp}/run.do_* {src_temp}/task_order {} 2>/dev/null || true",
                          dst.display());
        let _ = Command::new("bash").arg("-c").arg(&cmd).status();
    }
    Ok(())
}

fn capture_kernel_artifacts(build_dir: &Path) -> Result<()> {
    fs::create_dir_all(build_dir).context("create build dir")?;
    let cfg_cmd = "ssh -i /home/aurelien/.ssh/hpclab_admin -o StrictHostKeyChecking=no \
                   -o ConnectTimeout=5 hpcadmin@192.168.56.11 \
                   'sudo cat /proc/config.gz' 2>/dev/null";
    if let Ok(out) = Command::new("bash").arg("-c").arg(cfg_cmd).output() {
        if out.status.success() && !out.stdout.is_empty() {
            let _ = fs::write(build_dir.join("proc-config.gz"), &out.stdout);
        }
    }
    let mod_cmd = "ssh -i /home/aurelien/.ssh/hpclab_admin -o StrictHostKeyChecking=no \
                   -o ConnectTimeout=5 hpcadmin@192.168.56.11 \
                   'sudo modinfo beamfs; echo ---; sudo modinfo radfi'";
    if let Ok(out) = Command::new("bash").arg("-c").arg(mod_cmd).output() {
        let _ = fs::write(build_dir.join("modinfo.txt"), out.stdout);
    }
    Ok(())
}

fn write_global_manifest(
    mega_dir: &Path,
    started_ts: chrono::DateTime<chrono::Local>,
    started_inst: Instant,
    phases: &[PhaseResult],
) -> Result<PathBuf> {
    let ended = Local::now();
    let duration = started_inst.elapsed().as_secs();
    let mut s = String::new();
    s.push_str("================================================================\n");
    s.push_str(" beamfs-bench mega manifest (consolidated investigation run)\n");
    s.push_str("================================================================\n");
    s.push_str(&format!("Run dir         : {}\n", mega_dir.display()));
    s.push_str(&format!("Started         : {}\n", started_ts.format("%Y-%m-%d %H:%M:%S %Z")));
    s.push_str(&format!("Ended           : {}\n", ended.format("%Y-%m-%d %H:%M:%S %Z")));
    s.push_str(&format!("Duration (s)    : {duration}\n"));
    s.push_str(&format!("Total phases    : {}\n", phases.len()));
    let n_ok = phases.iter().filter(|p| p.rc == 0).count();
    let n_fail = phases.len() - n_ok;
    s.push_str(&format!("PASSED          : {n_ok}\n"));
    s.push_str(&format!("FAILED          : {n_fail}\n"));
    s.push_str("\n================================================================\n");
    s.push_str(" PHASE-BY-PHASE\n");
    s.push_str("================================================================\n");
    for p in phases {
        let tag = if p.rc == 0 { "[OK]  " } else { "[FAIL]" };
        s.push_str(&format!("{tag} {:<28} ({:>5} s) : rc={} {}\n",
            p.name, p.duration_secs, p.rc, p.note));
    }
    s.push_str("\n================================================================\n");
    s.push_str(" ARTIFACTS IN MEGA DIR (depth-3 listing)\n");
    s.push_str("================================================================\n");
    fn list_recursive(dir: &Path, prefix: &str, out: &mut String, depth: usize) {
        if depth > 3 { return; }
        if let Ok(rd) = fs::read_dir(dir) {
            let mut entries: Vec<_> = rd.flatten().collect();
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                let name = entry.file_name().to_string_lossy().into_owned();
                let path = entry.path();
                if path.is_dir() {
                    out.push_str(&format!("{prefix}{name}/\n"));
                    let new_prefix = format!("{prefix}  ");
                    list_recursive(&path, &new_prefix, out, depth + 1);
                } else if let Ok(meta) = entry.metadata() {
                    out.push_str(&format!("{prefix}{:<40} : {} bytes\n", name, meta.len()));
                }
            }
        }
    }
    list_recursive(mega_dir, "", &mut s, 0);
    let path = mega_dir.join("manifest.txt");
    fs::write(&path, &s).context("write mega manifest.txt")?;
    Ok(path)
}

fn make_mega_tarball(mega_dir: &Path) -> Result<PathBuf> {
    let basename = mega_dir.file_name()
        .ok_or_else(|| anyhow!("mega_dir has no basename"))?
        .to_string_lossy()
        .to_string();
    // basename is already "beamfs-bench-mega-<TS>", just append .tar.gz
    let archive_name = format!("{basename}.tar.gz");
    let archive = PathBuf::from("/tmp").join(&archive_name);
    let parent = mega_dir.parent()
        .ok_or_else(|| anyhow!("mega_dir has no parent"))?;
    let status = Command::new("tar")
        .arg("-czf").arg(&archive)
        .arg("-C").arg(parent)
        .arg(&basename)
        .status()
        .context("spawn tar")?;
    if !status.success() {
        return Err(anyhow!("tar failed (exit {:?})", status.code()));
    }
    Ok(archive)
}

pub fn run(injector: &str) -> Result<i32> {
    println!("================================================================");
    println!(" beamfs-bench mega - consolidated investigation run");
    println!(" Mode: full pipeline + 4 sub-scopes + extended forensics");
    println!("================================================================");

    let started_ts = Local::now();
    let started_inst = Instant::now();
    let ts_compact = started_ts.format("%Y%m%d-%H%M%S").to_string();
    let mega_basename = format!("beamfs-bench-mega-{ts_compact}");
    let mega_dir = Path::new(RUNS_DIR).join(&mega_basename);
    fs::create_dir_all(&mega_dir).context("create mega run dir")?;
    println!("[mega] Run dir: {}", mega_dir.display());

    let build_dir = mega_dir.join("build");
    let env_dir = mega_dir.join("env");
    fs::create_dir_all(&build_dir)?;
    fs::create_dir_all(&env_dir)?;

    let mut phases: Vec<PhaseResult> = Vec::new();

    // Phase 00: env capture
    let _t0 = Instant::now();
    let rc = match capture_env(&env_dir) {
        Ok(_) => 0,
        Err(e) => { eprintln!("[mega] capture_env: {e:#}"); 1 }
    };
    phases.push(PhaseResult {
        name: "00_capture_env".into(), rc,
        duration_secs: _t0.elapsed().as_secs(),
        note: "uname + bench version + git HEADs".into(),
    });

    // Phase 01: pipeline R19
    let _t0 = Instant::now();
    println!();
    println!("[mega] === Phase 01: pipeline R19 validation chain ===");
    let pipeline_result: Result<()> = (|| {
        let mut manifest = pipeline::build_initial_manifest()?;
        pipeline::assert_isolation_r21()?;
        pipeline::record(&mut manifest, "0.0_isolation_r21", 0);
        pipeline::verify_clean_working_trees()?;
        pipeline::record(&mut manifest, "0.1_clean_trees", 0);
        let src = pipeline::verify_lockstep_sources()?;
        manifest.source_sha256 = src;
        pipeline::record(&mut manifest, "0.2_lockstep", 0);
        pipeline::bitbake_image_to(false, Some(&build_dir))?;
        pipeline::record(&mut manifest, "0.3_bitbake", 0);
        let (ref_ko, ext2_sha) = pipeline::extract_reference_ko_sha()?;
        manifest.reference_ko_sha256 = ref_ko.clone();
        manifest.canonical_ext2_sha256 = ext2_sha;
        pipeline::record(&mut manifest, "0.4_extract_ref", 0);
        pipeline::redeploy_4_vms()?;
        pipeline::record(&mut manifest, "0.5_redeploy", 0);
        lifecycle::wait_ssh_ready_parallel()?;
        pipeline::record(&mut manifest, "0.6_ssh_ready", 0);
        let in_vm_shas = pipeline::verify_module_identity_in_vm(&ref_ko)?;
        manifest.in_vm_ko_sha256 = in_vm_shas;
        pipeline::record(&mut manifest, "0.7_identity", 0);
        let bootstrap_nodes: Vec<cluster::ClusterNode> = cluster::CLUSTER_NODES.iter()
            .map(|(ip, hostname)| cluster::ClusterNode {
                ip: ip.to_string(),
                expected_hostname: hostname.to_string(),
                discovered: cluster::NodeState { reachable: true, ..Default::default() },
            }).collect();
        cluster::deploy_worker_all(&bootstrap_nodes)?;
        if let Ok(mp) = pipeline::emit_manifest(&manifest) {
            let _ = fs::copy(&mp, mega_dir.join("pipeline-manifest.json"));
        }
        Ok(())
    })();
    let pipeline_rc = if pipeline_result.is_ok() { 0 } else { 1 };
    phases.push(PhaseResult {
        name: "01_pipeline_R19".into(), rc: pipeline_rc,
        duration_secs: _t0.elapsed().as_secs(),
        note: match &pipeline_result {
            Ok(_) => "phases 0.0..0.7 PASS".into(),
            Err(e) => format!("FAIL: {e:#}"),
        },
    });
    if let Err(e) = pipeline_result {
        eprintln!("[mega] pipeline failed; capturing build logs + tarball before abort");
        let _ = capture_yocto_build_logs(&build_dir);
        let _ = capture_kernel_artifacts(&build_dir);
        let _ = write_global_manifest(&mega_dir, started_ts, started_inst, &phases);
        let _ = make_mega_tarball(&mega_dir);
        return Err(e);
    }

    // Phase 02: analyse Full
    let before = list_run_dirs_with_prefix("beamfs-bench-analyse-full-");
    let _t0 = Instant::now();
    println!();
    println!("[mega] === Phase 02: analyse scope=Full ===");
    let cfg = analyse::AnalyseConfig {
        scope: Scope::Full,
        auto_confirm: true, dry_run: false, make_tarball: false,
        vm_name: multifs::DEFAULT_VM_NAME.to_string(),
        bpftrace_host: false,
        injector: injector.to_string(),
    };
    let rc = match analyse::run(&cfg) {
        Ok(r) => r,
        Err(e) => { eprintln!("[mega] analyse: {e:#}"); 1 }
    };
    phases.push(PhaseResult {
        name: "02_analyse_full".into(), rc,
        duration_secs: _t0.elapsed().as_secs(),
        note: "multifs + cluster + 4-node forensics".into(),
    });
    relocate_run_dir("beamfs-bench-analyse-full-", &before, &mega_dir, "analyse");

    // Phase 03: bitrot
    let before = list_run_dirs_with_prefix("beamfs-bench-bitrot-");
    let _t0 = Instant::now();
    println!();
    println!("[mega] === Phase 03: bitrot ===");
    let rc = match bitrot::run(injector) {
        Ok(r) => r,
        Err(e) => { eprintln!("[mega] bitrot: {e:#}"); 1 }
    };
    phases.push(PhaseResult {
        name: "03_bitrot".into(), rc,
        duration_secs: _t0.elapsed().as_secs(),
        note: "offline bit-rot 4 scenarios".into(),
    });
    relocate_run_dir("beamfs-bench-bitrot-", &before, &mega_dir, "bitrot");

    // Phase 04: metadata
    let before = list_run_dirs_with_prefix("beamfs-bench-metadata-");
    let _t0 = Instant::now();
    println!();
    println!("[mega] === Phase 04: metadata ===");
    let rc = match metadata::run(injector) {
        Ok(r) => r,
        Err(e) => { eprintln!("[mega] metadata: {e:#}"); 1 }
    };
    phases.push(PhaseResult {
        name: "04_metadata".into(), rc,
        duration_secs: _t0.elapsed().as_secs(),
        note: "RadFI metadata 5 FS x 4 phases".into(),
    });
    relocate_run_dir("beamfs-bench-metadata-", &before, &mega_dir, "metadata");

    // Phase 05: crash
    let before = list_run_dirs_with_prefix("beamfs-bench-crash-");
    let _t0 = Instant::now();
    println!();
    println!("[mega] === Phase 05: crash ===");
    let rc = match crash::run(injector) {
        Ok(r) => r,
        Err(e) => { eprintln!("[mega] crash: {e:#}"); 1 }
    };
    phases.push(PhaseResult {
        name: "05_crash".into(), rc,
        duration_secs: _t0.elapsed().as_secs(),
        note: "power-loss mid-write 5 FS".into(),
    });
    relocate_run_dir("beamfs-bench-crash-", &before, &mega_dir, "crash");

    // Phase 06: fsck
    let before = list_run_dirs_with_prefix("beamfs-bench-fsck-");
    let _t0 = Instant::now();
    println!();
    println!("[mega] === Phase 06: fsck ===");
    let rc = match fsck::run(injector) {
        Ok(r) => r,
        Err(e) => { eprintln!("[mega] fsck: {e:#}"); 1 }
    };
    phases.push(PhaseResult {
        name: "06_fsck".into(), rc,
        duration_secs: _t0.elapsed().as_secs(),
        note: "offline FS check 5 FS".into(),
    });
    relocate_run_dir("beamfs-bench-fsck-", &before, &mega_dir, "fsck");

    // Phase 07: Yocto build logs
    let _t0 = Instant::now();
    let rc = match capture_yocto_build_logs(&build_dir) { Ok(_) => 0, Err(_) => 1 };
    phases.push(PhaseResult {
        name: "07_yocto_build_logs".into(), rc,
        duration_secs: _t0.elapsed().as_secs(),
        note: "log.do_* + run.do_* + task_order".into(),
    });

    // Phase 08: kernel artifacts
    let _t0 = Instant::now();
    let rc = match capture_kernel_artifacts(&build_dir) { Ok(_) => 0, Err(_) => 1 };
    phases.push(PhaseResult {
        name: "08_kernel_artifacts".into(), rc,
        duration_secs: _t0.elapsed().as_secs(),
        note: "/proc/config.gz + modinfo".into(),
    });

    // Phase 09: post-attack forensics
    let _t0 = Instant::now();
    let rc = (|| -> Result<i32> {
        let nodes: Vec<cluster::ClusterNode> = cluster::CLUSTER_NODES.iter()
            .map(|(ip, hostname)| cluster::ClusterNode {
                ip: ip.to_string(),
                expected_hostname: hostname.to_string(),
                discovered: cluster::NodeState {
                    reachable: true,
                    hostname: Some(hostname.to_string()),
                    ..Default::default()
                },
            }).collect();
        forensics::post_capture_all(&nodes, &mega_dir, Scope::Full)?;
        Ok(0)
    })().unwrap_or(1);
    phases.push(PhaseResult {
        name: "09_post_forensics".into(), rc,
        duration_secs: _t0.elapsed().as_secs(),
        note: "dmesg + radfi-counters + lsmod + ftrace + rs-journal".into(),
    });

    // Global manifest
    let _ = write_global_manifest(&mega_dir, started_ts, started_inst, &phases);

    // Single tarball
    match make_mega_tarball(&mega_dir) {
        Ok(t) => {
            println!();
            println!("================================================================");
            println!(" mega run complete");
            println!("================================================================");
            println!(" Run dir : {}", mega_dir.display());
            println!(" Tarball : {}", t.display());
            let mp = mega_dir.join("manifest.txt");
            if let Ok(mut s) = fs::read_to_string(&mp) {
                s.push_str(&format!("\nTARBALL : {}\n", t.display()));
                let _ = fs::write(&mp, s);
            }
        }
        Err(e) => eprintln!("[mega] tarball FAIL: {e:#}"),
    }

    let n_fail = phases.iter().filter(|p| p.rc != 0).count();
    if n_fail > 0 {
        return Err(anyhow!("{n_fail} of {} mega phase(s) failed", phases.len()));
    }
    Ok(0)
}
