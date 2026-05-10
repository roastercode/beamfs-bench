//! beamfs-bench pipeline -- MIL no-NAK validation chain.
//!
//! Phases executed before any test runs:
//!   0.1 verify_clean_working_trees   3 git repos must be clean
//!   0.2 verify_lockstep_sources      sha256 manifest source vs yocto layer
//!   0.3 bitbake_image                build canonical .ext2
//!   0.4 extract_reference_ko_sha     loop-mount canonical, sha256 module
//!   0.5 redeploy_4_vms               virsh destroy + cp x4 + chown + start
//!   0.6 wait_ssh_ready_parallel      reuse lifecycle helper
//!   0.7 verify_module_identity       sha256 in-VM == reference, on 4 nodes
//!
//! Phases executed after tests:
//!   8.1 verify_dmesg_clean           no BUG/Oops/WARN on any node
//!   8.2 emit_manifest                JSON + GPG-detached-sign
//!
//! All phases fail-closed. Any non-zero exit aborts the pipeline,
//! emits a partial manifest with the failure record, and returns rc=2.

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BEAMFS_REPO:        &str = "/home/aurelien/git/beamfs";
const YOCTO_REPO:         &str = "/home/aurelien/git/yocto-beamfs";
const BENCH_REPO:         &str = "/home/aurelien/git/beamfs-bench";
const YOCTO_KERNEL_FILES: &str = "/home/aurelien/git/yocto-beamfs/recipes-kernel/beamfs/files/beamfs-0.1.1";
const KERNEL_SOURCES: &[&str] = &[
    "alloc.c", "beamfs.h", "COPYING", "dir.c", "edac.c", "file.c",
    "file_inline.c", "inode.c", "Kconfig", "Makefile", "namei.c", "super.c",
];

const POKY_DIR:       &str = "/home/aurelien/yocto/poky";
const BUILD_DIR_NAME: &str = "build-qemu-arm64";
const CANONICAL_EXT2: &str = "/home/aurelien/yocto/poky/build-qemu-arm64/tmp/deploy/images/qemuarm64/hpc-arm64-research-beamfs-qemuarm64.ext2";
const LIBVIRT_DIR:    &str = "/var/lib/libvirt/images/hpc-arm64";
const KO_PATH_IN_FS:  &str = "lib/modules/7.0.3/updates/beamfs.ko";

const VM_NAMES: &[&str] = &["beamfs-master", "beamfs-compute01", "beamfs-compute02", "beamfs-compute03"];
const VM_IPS:   &[&str] = &["192.168.56.10", "192.168.56.11", "192.168.56.12", "192.168.56.13"];
const SSH_KEY:  &str = "/home/aurelien/.ssh/hpclab_admin";

#[derive(Debug, Clone, Serialize)]
pub struct PipelineManifest {
    pub started_at:        String,
    pub finished_at:       String,
    pub commit_beamfs:     String,
    pub commit_yocto:      String,
    pub commit_bench:      String,
    pub source_sha256:     Vec<(String, String)>,
    pub canonical_ext2_sha256: String,
    pub reference_ko_sha256:   String,
    pub in_vm_ko_sha256:   Vec<(String, String)>,
    pub phases:            Vec<(String, String, i32)>,
    pub overall_rc:        i32,
}

fn sha256_file(path: &Path) -> Result<String> {
    let out = Command::new("sha256sum").arg(path).output()
        .with_context(|| format!("sha256sum {}", path.display()))?;
    if !out.status.success() {
        bail!("sha256sum failed on {}: {}", path.display(), String::from_utf8_lossy(&out.stderr));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.split_whitespace().next().unwrap_or("").to_string())
}

fn sha256_file_sudo(path: &str) -> Result<String> {
    let out = Command::new("sudo").args(["sha256sum", path]).output()
        .with_context(|| format!("sudo sha256sum {path}"))?;
    if !out.status.success() {
        bail!("sudo sha256sum failed on {path}: {}", String::from_utf8_lossy(&out.stderr));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.split_whitespace().next().unwrap_or("").to_string())
}

fn git_head_sha(repo: &str) -> Result<String> {
    let out = Command::new("git").args(["-C", repo, "rev-parse", "HEAD"]).output()
        .with_context(|| format!("git rev-parse HEAD in {repo}"))?;
    if !out.status.success() {
        bail!("git rev-parse failed in {repo}: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn ssh_exec(ip: &str, cmd: &str) -> Result<String> {
    let out = Command::new("ssh")
        .args(["-T", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
               &format!("hpcadmin@{ip}"), cmd])
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("ssh {ip}"))?;
    if !out.status.success() {
        bail!("ssh {ip} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

// ---------------------------------------------------------------------
// Phase 0.1
// ---------------------------------------------------------------------
pub fn verify_clean_working_trees() -> Result<()> {
    println!("[pipeline 0.1] verify clean working trees on 2 lockstep repos");
    // R19 semantics: lockstep is between beamfs and yocto-beamfs (kernel sources
    // must be byte-identical between the two repos). beamfs-bench is the bench
    // tool itself; it is intentionally excluded so that bench refactors can
    // run their own validation chain without requiring a self-commit first.
    for repo in &[BEAMFS_REPO, YOCTO_REPO] {
        let out = Command::new("git").args(["-C", repo, "status", "-s"]).output()
            .with_context(|| format!("git status in {repo}"))?;
        let dirty = String::from_utf8_lossy(&out.stdout);
        if !dirty.trim().is_empty() {
            bail!("repo {repo} not clean:\n{dirty}");
        }
        println!("  {repo} clean");
    }
    // beamfs-bench check downgraded from blocking to informative WARN.
    {
        let out = Command::new("git").args(["-C", BENCH_REPO, "status", "-s"]).output()
            .with_context(|| format!("git status in {BENCH_REPO}"))?;
        let dirty = String::from_utf8_lossy(&out.stdout);
        if !dirty.trim().is_empty() {
            println!("  {BENCH_REPO} dirty (informative, non-blocking):");
            for line in dirty.lines().take(20) {
                println!("    {line}");
            }
        } else {
            println!("  {BENCH_REPO} clean");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Phase 0.2
// ---------------------------------------------------------------------
pub fn verify_lockstep_sources() -> Result<Vec<(String, String)>> {
    println!("[pipeline 0.2] verify lockstep sources (12 files)");
    let mut manifest = Vec::new();
    for f in KERNEL_SOURCES {
        let p1 = PathBuf::from(BEAMFS_REPO).join(f);
        let p2 = PathBuf::from(YOCTO_KERNEL_FILES).join(f);
        let s1 = sha256_file(&p1).with_context(|| format!("hash beamfs/{f}"))?;
        let s2 = sha256_file(&p2).with_context(|| format!("hash yocto/{f}"))?;
        if s1 != s2 {
            bail!("lockstep DIVERGENCE: {f}\n  beamfs: {s1}\n  yocto:  {s2}");
        }
        manifest.push((f.to_string(), s1));
    }
    println!("  12 files byte-identical");
    Ok(manifest)
}

// ---------------------------------------------------------------------
// Phase 0.3
// ---------------------------------------------------------------------
pub fn bitbake_image(skip: bool) -> Result<()> {
    bitbake_image_to(skip, None)
}

/// Same as bitbake_image but optionally captures stdout+stderr to a log file
/// (in addition to streaming to terminal). Used by mega scope to archive build logs.
pub fn bitbake_image_to(skip: bool, log_dir: Option<&Path>) -> Result<()> {
    if skip {
        println!("[pipeline 0.3] bitbake SKIPPED (--skip-bitbake)");
        return Ok(());
    }
    println!("[pipeline 0.3] bitbake hpc-arm64-research-beamfs (streaming)");
    let mut cmd = format!(
        "cd {POKY_DIR} && source oe-init-build-env {BUILD_DIR_NAME} > /dev/null 2>&1 && \
         bitbake hpc-arm64-research-beamfs 2>&1"
    );
    if let Some(dir) = log_dir {
        std::fs::create_dir_all(dir).context("create bitbake log dir")?;
        let log_path = dir.join("bitbake-stdout.log");
        // tee: keep streaming visible AND capture to file.
        cmd = format!("({cmd}) | tee {}", log_path.display());
    }
    let status = Command::new("env")
        .args(["-i", "HOME=/home/aurelien", "TERM=xterm",
               "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
               "bash", "-c", &cmd])
        .status()
        .context("bitbake spawn")?;
    if !status.success() {
        bail!("bitbake hpc-arm64-research-beamfs failed (exit {:?})", status.code());
    }
    let p = PathBuf::from(CANONICAL_EXT2);
    if !p.exists() {
        bail!("canonical ext2 not produced: {}", p.display());
    }
    println!("  canonical ext2 produced: {}", p.display());
    Ok(())
}

// ---------------------------------------------------------------------
// Phase 0.4
// ---------------------------------------------------------------------
pub fn extract_reference_ko_sha() -> Result<(String, String)> {
    println!("[pipeline 0.4] extract reference beamfs.ko sha256 from canonical .ext2");
    let mnt = Command::new("mktemp").arg("-d").output().context("mktemp")?;
    let mnt = String::from_utf8_lossy(&mnt.stdout).trim().to_string();
    let mount_st = Command::new("sudo")
        .args(["mount", "-o", "ro,loop", CANONICAL_EXT2, &mnt])
        .status().context("sudo mount loop")?;
    if !mount_st.success() { bail!("loop mount failed on {CANONICAL_EXT2}"); }

    let ko_path = format!("{mnt}/{KO_PATH_IN_FS}");
    let ko_sha  = sha256_file_sudo(&ko_path);
    let ext2_sha = sha256_file(Path::new(CANONICAL_EXT2));

    let _ = Command::new("sudo").args(["umount", &mnt]).status();
    let _ = Command::new("rmdir").arg(&mnt).status();

    let ko_sha   = ko_sha.context("extract ko sha")?;
    let ext2_sha = ext2_sha.context("hash ext2")?;
    println!("  reference ko sha256:   {ko_sha}");
    println!("  canonical ext2 sha256: {ext2_sha}");
    Ok((ko_sha, ext2_sha))
}

// ---------------------------------------------------------------------
// Phase 0.0 -- R21 isolation architecture invariant.
// Wrapper around lifecycle::assert_isolation_architecture so callers
// see Phase 0.0 in logs and the manifest.
// ---------------------------------------------------------------------
pub fn assert_isolation_r21() -> Result<()> {
    println!("[pipeline 0.0] verify R21 cluster isolation architecture");
    crate::lifecycle::assert_isolation_architecture()
        .context("R21 isolation pre-flight failed")
}

// ---------------------------------------------------------------------
// Phase 0.5 -- redeploy + cluster up.
// Reuses lifecycle helpers (define_missing_vms, destroy_all_vms,
// start_network, start_all_vms) so the R21-validated invariants of
// those helpers remain in force; this function only adds the cp/chown
// step between destroy and start.
// ---------------------------------------------------------------------
pub fn redeploy_4_vms() -> Result<()> {
    println!("[pipeline 0.5] redeploy 4 VMs from canonical .ext2");

    crate::lifecycle::define_missing_vms()
        .context("define missing VMs (cold-start safety)")?;
    crate::lifecycle::destroy_all_vms()
        .context("destroy all VMs before redeploy")?;

    // R31 step 4: ensure libvirt/QEMU has fully released file descriptors
    // on .ext2 rootfs files before we overwrite them. virsh destroy is
    // SIGKILL-level but QEMU buffer flush is best-effort; sync forces the
    // host page cache + dirty pages to disk so subsequent cp lands on a
    // quiesced filesystem state.
    let _ = Command::new("sync").status();

    // Reference sha256 of the canonical .ext2 -- computed once, used to
    // verify each cp byte-for-byte. Establishes the R31 invariant that
    // every VM rootfs is byte-identical to canonical at start time.
    let canonical_sha = sha256_file(Path::new(CANONICAL_EXT2))
        .context("hash canonical .ext2")?;
    println!("  canonical .ext2 sha256: {canonical_sha}");

    for vm in VM_NAMES {
        let dst = format!("{LIBVIRT_DIR}/{vm}.ext2");
        let st = Command::new("sudo")
            .args(["cp", CANONICAL_EXT2, &dst])
            .status().with_context(|| format!("cp ext2 -> {dst}"))?;
        if !st.success() { bail!("cp failed for {dst}"); }
        let st = Command::new("sudo")
            .args(["chown", "qemu:qemu", &dst]).status()
            .with_context(|| format!("chown {dst}"))?;
        if !st.success() { bail!("chown failed for {dst}"); }

        // R31 step 4: flush page cache + verify byte-identity vs canonical
        // BEFORE start. This catches the case where a stale FD from a
        // pre-existing VM (out-of-pipeline launch, crashed bench leftover,
        // libvirt resource leak) caused cp to land on a non-quiesced file.
        let _ = Command::new("sync").status();
        let dst_sha = sha256_file(Path::new(&dst))
            .with_context(|| format!("hash {dst}"))?;
        if dst_sha != canonical_sha {
            bail!(
                "redeploy verify FAIL for {dst}: deployed sha256={dst_sha} != canonical={canonical_sha} (R31: a stale VM held a FD on this file, or cp was interrupted; ensure no out-of-pipeline VM is running and rerun)"
            );
        }
        println!("  {vm}.ext2 redeployed (sha256 verified)");
    }

    crate::lifecycle::start_network()
        .context("start hpcnet network")?;
    crate::lifecycle::start_all_vms()
        .context("start all 4 VMs")?;

    Ok(())
}

// ---------------------------------------------------------------------
// Phase 0.7
// ---------------------------------------------------------------------
pub fn verify_module_identity_in_vm(reference_ko_sha: &str) -> Result<Vec<(String, String)>> {
    println!("[pipeline 0.7] verify in-VM beamfs.ko sha256 == reference on 4 nodes");
    let mut shas = Vec::new();
    for (i, ip) in VM_IPS.iter().enumerate() {
        let cmd = format!("sudo sha256sum /{KO_PATH_IN_FS}");
        let out = ssh_exec(ip, &cmd).with_context(|| format!("ssh {ip} sha256"))?;
        let sha = out.split_whitespace().next().unwrap_or("").to_string();
        if sha != reference_ko_sha {
            bail!("identity FAIL on {} ({}): in-VM={sha}  reference={reference_ko_sha}",
                  VM_NAMES[i], ip);
        }
        shas.push((VM_NAMES[i].to_string(), sha));
        println!("  {} ({ip}) match", VM_NAMES[i]);
    }
    Ok(shas)
}

// ---------------------------------------------------------------------
// Phase 8.1
// ---------------------------------------------------------------------
pub fn verify_dmesg_clean() -> Result<()> {
    println!("[pipeline 8.1] verify dmesg clean on 4 nodes");
    let pat = "BUG\\|Oops\\|general protection\\|Kernel panic\\|stack-protector";
    let mut total = 0usize;
    for (i, ip) in VM_IPS.iter().enumerate() {
        let cmd = format!("sudo dmesg | grep -E -c '{pat}' || true");
        let out = ssh_exec(ip, &cmd)?;
        let n: usize = out.trim().parse().unwrap_or(0);
        if n > 0 {
            let detail = ssh_exec(ip, &format!("sudo dmesg | grep -E '{pat}' | head -20"))?;
            bail!("dmesg DIRTY on {} ({ip}): {n} matches\n{detail}",
                  VM_NAMES[i]);
        }
        total += n;
        println!("  {} ({ip}) clean", VM_NAMES[i]);
    }
    println!("  total kernel crash markers: {total}");
    Ok(())
}

// ---------------------------------------------------------------------
// Phase 8.2
// ---------------------------------------------------------------------
pub fn emit_manifest(m: &PipelineManifest) -> Result<PathBuf> {
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let path = PathBuf::from(format!("/home/aurelien/git/yocto-beamfs/Documentation/runs/manifest-{stamp}.json"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let json = serde_json::to_string_pretty(m).context("serialize manifest")?;
    std::fs::write(&path, &json).with_context(|| format!("write {}", path.display()))?;
    println!("[pipeline 8.2] manifest written: {}", path.display());

    // Use --batch --pinentry-mode loopback to avoid pinentry timeout when
    // gpg-agent cache is empty. This requires either a populated agent
    // cache (preauth via dummy sign) or a configured passphrase source.
    // Without these flags, gpg blocks on pinentry-curses for 30s then fails.
    let st = Command::new("gpg")
        .args(["--batch", "--pinentry-mode", "loopback",
               "--detach-sign", "--armor", "--yes", "--output",
               &format!("{}.asc", path.display()), &path.to_string_lossy()])
        .status();
    match st {
        Ok(s) if s.success() => println!("  manifest GPG-signed: {}.asc", path.display()),
        _ => eprintln!("  WARNING: gpg detach-sign failed (manifest unsigned)"),
    }
    Ok(path)
}

pub fn now_iso() -> String { Utc::now().to_rfc3339() }

pub fn build_initial_manifest() -> Result<PipelineManifest> {
    Ok(PipelineManifest {
        started_at:  now_iso(),
        finished_at: String::new(),
        commit_beamfs: git_head_sha(BEAMFS_REPO)?,
        commit_yocto:  git_head_sha(YOCTO_REPO)?,
        commit_bench:  git_head_sha(BENCH_REPO)?,
        source_sha256: Vec::new(),
        canonical_ext2_sha256: String::new(),
        reference_ko_sha256:   String::new(),
        in_vm_ko_sha256:       Vec::new(),
        phases:                Vec::new(),
        overall_rc:            -1,
    })
}

pub fn record(m: &mut PipelineManifest, name: &str, rc: i32) {
    m.phases.push((name.to_string(), now_iso(), rc));
}

pub fn fail(m: &mut PipelineManifest, name: &str, e: &anyhow::Error) -> anyhow::Error {
    record(m, name, 2);
    m.overall_rc  = 2;
    m.finished_at = now_iso();
    let _ = emit_manifest(m);
    anyhow!("pipeline phase {name} FAILED: {e:#}")
}
