//! `forensics_host.rs` - host-side forensic capture for beamfs-bench.
//!
//! Companion to `forensics.rs` (which captures inside the 4 cluster VMs).
//! This module captures host-side state (`spartian-1`) into
//! `<run_dir>/host/` so the resulting tarball produced by `analyse::make_tarball`
//! contains both the VM and host forensics in one archive (Voie A: inject
//! before tar, no consolidation step needed).
//!
//! ## What is captured (always, all scopes)
//!
//!   - dmesg.log              : host kernel ring buffer (post-bootstrap)
//!   - uname.log              : host kernel + arch + distro info
//!   - virsh-list.log         : libvirt VM state (running/shut off/etc.)
//!   - virsh-dumpxml-<vm>.xml : libvirt persistent XML for each beamfs-* VM
//!   - lsblk.log              : host block device tree
//!   - lsusb.log              : host USB tree (the 5 sticks passed to compute01)
//!   - canonical-ko.log       : sha256 + path of the deployed beamfs.ko
//!   - system.log             : free, uptime, /proc/cmdline
//!
//! ## What is captured (opt-in, --bpftrace flag)
//!
//!   - bpftrace.log           : passive bpftrace probes during the run
//!     (`block_rq_complete` + `sched_switch` counts)
//!
//! ## Why a separate module
//!
//! `forensics.rs` is VM-side: every function takes a list of `ClusterNode`
//! and `SSHes` into the guest. Adding host-side captures there would
//! conflate two responsibilities and break the existing single-purpose
//! contract documented at the top of `forensics.rs`. Keeping host-side
//! in `forensics_host.rs` makes the orchestration in `analyse.rs` an
//! explicit two-step parallel: VM forensics + host forensics.
//!
//! ## bpftrace VM-side (out of scope for this module)
//!
//! bpftrace is not currently in the Yocto image
//! `hpc-arm64-research-beamfs.bb` (R23). VM-side bpftrace would require
//! adding it to `IMAGE_INSTALL` and rebuilding. Tracked as a follow-up.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::forensics::Scope;
use std::fmt::Write;
use std::io::Write as IoWrite;

const VM_NAMES: &[&str] = &[
    "beamfs-master",
    "beamfs-compute01",
    "beamfs-compute02",
    "beamfs-compute03",
];

const BPFTRACE_PID_FILE: &str = "/tmp/beamfs-bench-bpftrace.pid";
const BPFTRACE_LOG_FILE: &str = "/tmp/beamfs-bench-bpftrace.log";

/// Run a shell command on the host, return stdout (lossy UTF-8).
/// Stderr is captured but not returned ; if the command fails the
/// caller still gets whatever stdout was produced (best-effort).
fn run_host(cmd: &str) -> Result<String> {
    let output = Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .output()
        .with_context(|| format!("spawn bash -c {cmd}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Write a file under `<run_dir>/host/<name>` with content from `cmd`.
/// Logs and continues on failure (host capture is best-effort by design).
fn capture_to(host_dir: &Path, name: &str, cmd: &str) {
    match run_host(cmd) {
        Ok(out) => {
            let path = host_dir.join(name);
            if let Err(e) = fs::write(&path, out) {
                eprintln!("  host capture: write {} failed: {e:#}", path.display());
            }
        }
        Err(e) => eprintln!("  host capture: {name} ({cmd}) failed: {e:#}"),
    }
}

/// Pre-capture: create `<run_dir>/host/`, write static host snapshot,
/// optionally start bpftrace in background.
///
/// Called from `analyse.rs` immediately after `forensics::pre_capture_all`.
pub fn pre_capture_host(
    run_dir: &Path,
    _scope: Scope,
    bpftrace_enabled: bool,
) -> Result<()> {
    let host_dir = run_dir.join("host");
    fs::create_dir_all(&host_dir)
        .with_context(|| format!("create_dir_all {}", host_dir.display()))?;

    println!("[pre]    Host-side capture (static snapshot)...");

    capture_to(&host_dir, "uname.log", "uname -a 2>&1; echo; cat /etc/os-release 2>/dev/null");
    capture_to(&host_dir, "system.log", "free -h 2>&1; echo; uptime 2>&1; echo; cat /proc/cmdline 2>&1");
    capture_to(&host_dir, "lsblk.log", "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL 2>&1");
    capture_to(&host_dir, "lsusb.log", "lsusb 2>&1");
    capture_to(&host_dir, "virsh-list.log", "virsh -c qemu:///system list --all 2>&1");

    for vm in VM_NAMES {
        let cmd = format!("virsh -c qemu:///system dumpxml {vm} 2>&1");
        capture_to(&host_dir, &format!("virsh-dumpxml-{vm}.xml"), &cmd);
    }

    capture_to(
        &host_dir,
        "canonical-ko.log",
        r#"
set -e
IMG=~/yocto/poky/build-qemu-arm64/tmp/deploy/images/qemuarm64/hpc-arm64-research-beamfs-qemuarm64.beamfs
echo "image: $IMG"
if [ -e "$IMG" ]; then
    echo "image-target: $(readlink -f "$IMG")"
    sha256sum "$(readlink -f "$IMG")" 2>&1
else
    echo "image: missing"
fi
"#,
    );

    if bpftrace_enabled {
        start_bpftrace_host()?;
    }

    // ---- 0.1 enrichments (R31 audit trail) ----
    capture_git_provenance(&host_dir);
    capture_bitbake_provenance(&host_dir);
    capture_vm_rootfs_format(&host_dir);
    capture_identity_per_node(&host_dir);
    capture_vm_runtime_state(&host_dir);
    capture_vm_modinfo(&host_dir);
    // -------------------------------------------

    Ok(())
}

/// Post-capture: append final dmesg + virsh state, stop bpftrace if running.
///
/// Called from `analyse.rs` immediately after `forensics::post_capture_all`.
pub fn post_capture_host(
    run_dir: &Path,
    _scope: Scope,
    bpftrace_enabled: bool,
) -> Result<()> {
    let host_dir = run_dir.join("host");
    if !host_dir.exists() {
        // pre_capture_host wasn't called or failed silently ; nothing to append.
        return Ok(());
    }

    println!("[post]   Host-side capture (post-run state)...");

    capture_to(&host_dir, "dmesg.log", "dmesg --ctime --no-pager 2>&1 | tail -500");
    capture_to(&host_dir, "virsh-list-final.log", "virsh -c qemu:///system list --all 2>&1");

    if bpftrace_enabled {
        stop_bpftrace_host(&host_dir);
    }

    Ok(())
}

/// Start bpftrace in background as root via `sudo -n` (NOPASSWD required).
/// If sudo prompts for a password, we fail fast and skip bpftrace
/// (best-effort : the rest of the run proceeds without bpftrace data).
fn start_bpftrace_host() -> Result<()> {
    // Probe sudo non-interactively first ; if it would prompt, skip.
    let probe = Command::new("sudo")
        .arg("-n")
        .arg("bpftrace")
        .arg("-V")
        .output();
    match probe {
        Ok(out) if out.status.success() => {}
        Ok(_) | Err(_) => {
            eprintln!(
                "[pre]    bpftrace skipped: `sudo -n bpftrace` requires                  NOPASSWD entry. Add bpftrace to /etc/sudoers.d/beamfs-bench                  if you want host bpftrace probes during the run."
            );
            return Ok(());
        }
    }

    // Probe : block layer request completion + sched_switch counts.
    // Kept intentionally light : 2 probes, count-only, no per-PID detail,
    // so the overhead during the run is negligible.
    let probe_script = r#"
BEGIN { printf("bpftrace: started %s\n", strftime("%Y-%m-%d %H:%M:%S", nsecs)); }
tracepoint:block:block_rq_complete { @block_rq_complete = count(); }
tracepoint:sched:sched_switch { @sched_switch = count(); }
END { printf("bpftrace: ended %s\n", strftime("%Y-%m-%d %H:%M:%S", nsecs)); }
"#;
    // Persist probe script to a tmp file so the launching shell stays simple.
    let script_path = "/tmp/beamfs-bench-bpftrace.bt";
    if let Err(e) = fs::write(script_path, probe_script) {
        eprintln!("[pre]    bpftrace skipped: failed to write probe script: {e:#}");
        return Ok(());
    }

    // Launch bpftrace detached, capturing PID into a sidecar file
    // (same pattern as forensics::start_perf_master).
    let launch = format!(
        "sudo -n nohup bpftrace {script_path} </dev/null          >{BPFTRACE_LOG_FILE} 2>&1 & echo $! > {BPFTRACE_PID_FILE}"
    );
    let status = Command::new("bash")
        .arg("-c")
        .arg(&launch)
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("[pre]    bpftrace started (host) ; pid file {BPFTRACE_PID_FILE}");
        }
        Ok(s) => {
            eprintln!("[pre]    bpftrace launch returned non-zero: {s:?}");
        }
        Err(e) => {
            eprintln!("[pre]    bpftrace launch failed: {e:#}");
        }
    }
    Ok(())
}

/// Stop bpftrace via SIGINT to its PID, wait for the log to be flushed,
/// then copy `/tmp/beamfs-bench-bpftrace.log` into `<run_dir>/host/`.
fn stop_bpftrace_host(host_dir: &Path) {
    // Read PID from sidecar file ; if missing, nothing to stop.
    let pid = if let Ok(s) = fs::read_to_string(BPFTRACE_PID_FILE) { s.trim().to_string() } else {
        eprintln!("[post]   bpftrace stop skipped: no PID file (was bpftrace started?)");
        return;
    };
    if pid.is_empty() {
        eprintln!("[post]   bpftrace stop skipped: empty PID file");
        return;
    }

    // SIGINT to bpftrace ; the END probe will fire and the log will close.
    let _ = Command::new("sudo")
        .arg("-n")
        .arg("kill")
        .arg("-INT")
        .arg(&pid)
        .status();

    // Bounded wait for log to be flushed (bpftrace writes END synchronously
    // but we still give it a short window to finalize aggregations).
    for _ in 0..20 {
        // Check process disappears or log shows END marker.
        let still_alive = Command::new("sudo")
            .arg("-n")
            .arg("kill")
            .arg("-0")
            .arg(&pid)
            .status()
            .is_ok_and(|s| s.success());
        if !still_alive {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Copy log into run_dir/host/.
    let dst = host_dir.join("bpftrace.log");
    let copy = Command::new("sudo")
        .arg("-n")
        .arg("cp")
        .arg(BPFTRACE_LOG_FILE)
        .arg(&dst)
        .status();
    match copy {
        Ok(s) if s.success() => {
            // chown back to user so the tarball is readable.
            let user = std::env::var("USER").unwrap_or_else(|_| "aurelien".to_string());
            let _ = Command::new("sudo")
                .arg("-n")
                .arg("chown")
                .arg(format!("{user}:{user}"))
                .arg(&dst)
                .status();
            println!("[post]   bpftrace log captured -> {}", dst.display());
        }
        Ok(s) => eprintln!("[post]   bpftrace log copy returned {s:?}"),
        Err(e) => eprintln!("[post]   bpftrace log copy failed: {e:#}"),
    }

    // Cleanup transient files (best-effort).
    let _ = fs::remove_file(BPFTRACE_PID_FILE);
    let _ = Command::new("sudo")
        .arg("-n")
        .arg("rm")
        .arg("-f")
        .arg(BPFTRACE_LOG_FILE)
        .arg("/tmp/beamfs-bench-bpftrace.bt")
        .status();
}


// =====================================================================
// 0.1 enrichments -- forensic capture extensions for R31 audit trail.
// =====================================================================
//
// Each helper is best-effort: failures are logged but do not abort the
// pre_capture_host flow. The contract matches `capture_to`: write
// whatever stdout we got, even on partial failure.
// =====================================================================

const REPOS: &[(&str, &str)] = &[
    ("beamfs",       "/home/aurelien/git/beamfs"),
    ("yocto-beamfs", "/home/aurelien/git/yocto-beamfs"),
    ("beamfs-bench", "/home/aurelien/git/beamfs-bench"),
    ("radfi",        "/home/aurelien/git/radfi"),
];

const VM_IPS: &[(&str, &str)] = &[
    ("beamfs-master",    "192.168.56.10"),
    ("beamfs-compute01", "192.168.56.11"),
    ("beamfs-compute02", "192.168.56.12"),
    ("beamfs-compute03", "192.168.56.13"),
];

const SSH_KEY: &str = "/home/aurelien/.ssh/hpclab_admin";
const SSH_USER: &str = "hpcadmin";

fn ssh_capture(ip: &str, remote_cmd: &str) -> String {
    // Bug A fix: drop stale host key entry (R13: known_hosts desynchronisation
    // after VM rebuild is a known recurring failure mode).
    let _ = Command::new("ssh-keygen")
        .args(["-R", ip])
        .output();

    // Bug B fix: encode the remote command in base64 so we never have to
    // quote-escape multi-line shell scripts through Rust's Debug format.
    // The remote side decodes and pipes to bash -s.
    let b64: String = {
        match Command::new("base64")
            .arg("-w0")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
        {
            Ok(mut c) => {
                if let Some(mut stdin) = c.stdin.take() {
                    let _ = stdin.write_all(remote_cmd.as_bytes());
                }
                match c.wait_with_output() {
                    Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
                    Err(_) => return String::from("ssh capture failed: base64 wait error"),
                }
            }
            Err(e) => return format!("ssh capture failed: base64 spawn: {e:#}"),
        }
    };

    let cmd = format!(
        "ssh -i {SSH_KEY} -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/home/aurelien/.ssh/known_hosts -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR {SSH_USER}@{ip} 'echo {b64} | base64 -d | bash -s' 2>&1"
    );
    run_host(&cmd).unwrap_or_else(|e| format!("ssh capture failed: {e:#}"))
}

/// Capture per-repo HEAD signature, status, branch, and remote URLs.
/// One file per repo: `git-{label}.txt`.
fn capture_git_provenance(host_dir: &Path) {
    println!("[pre]    Host capture: git provenance (4 repos)");
    for (label, path) in REPOS {
        let cmd = format!(
            r#"
echo "=== git rev-parse HEAD ==="
git --no-pager -C {path} rev-parse HEAD 2>&1
echo
echo "=== git log -1 --show-signature ==="
git --no-pager -C {path} log -1 --show-signature 2>&1
echo
echo "=== git status --short ==="
git --no-pager -C {path} status --short 2>&1
echo
echo "=== git branch --show-current ==="
git --no-pager -C {path} branch --show-current 2>&1
echo
echo "=== git remote -v ==="
git --no-pager -C {path} remote -v 2>&1
"#
        );
        capture_to(host_dir, &format!("git-{label}.txt"), &cmd);
    }
}

/// Capture bitbake recipe provenance for beamfs-module: `SRC_URI`, SRCREV,
/// FILESPATH, S=. Confirms which source tree produced the .ko.
fn capture_bitbake_provenance(host_dir: &Path) {
    println!("[pre]    Host capture: bitbake provenance");
    let cmd = r#"
cd ~/yocto/poky 2>/dev/null &&   source oe-init-build-env build-qemu-arm64 >/dev/null 2>&1 &&   bitbake -e beamfs-module 2>/dev/null |     grep -E '^(SRC_URI|SRCREV|FILESPATH|S|WORKDIR)=' | head -20
echo
echo "=== bitbake-layers show-recipes beamfs-module ==="
cd ~/yocto/poky 2>/dev/null &&   source oe-init-build-env build-qemu-arm64 >/dev/null 2>&1 &&   bitbake-layers show-recipes beamfs-module 2>&1 | head -20
"#;
    capture_to(host_dir, "bitbake-provenance.log", cmd);
}

/// Capture qemu-img info + sha256 for each VM rootfs .beamfs.
/// Proves R31 step 4 (redeploy completeness) was respected.
///
/// Each VM's vda backing path is resolved dynamically via
/// `crate::pipeline::resolve_vda_source` (parses live libvirt XML).
/// This protects against a silent drift of the <VM>.beamfs naming
/// convention (cf. Bug B 2026-05-15): if a future XML edit reroutes
/// vda elsewhere, this capture follows the actual backing file
/// instead of recording a stale path.
fn capture_vm_rootfs_format(host_dir: &Path) {
    println!("[pre]    Host capture: VM rootfs format + sha256");

    let mut out = String::new();

    // Canonical .beamfs (yocto deploy/images).
    let canonical_link = "/home/aurelien/yocto/poky/build-qemu-arm64/tmp/deploy/images/qemuarm64/hpc-arm64-research-beamfs-qemuarm64.beamfs";
    out.push_str("=== canonical ===\n");
    let canonical_resolved = match std::fs::canonicalize(canonical_link) {
        Ok(p) => p,
        Err(e) => {
            writeln!(out, "(readlink failed: {e})").unwrap();
            std::path::PathBuf::from(canonical_link)
        }
    };
    writeln!(out, "path: {}", canonical_resolved.display()).unwrap();
    match Command::new("sudo")
        .args(["qemu-img", "info", canonical_resolved.to_str().unwrap_or(canonical_link)])
        .output()
    {
        Ok(o) => out.push_str(&String::from_utf8_lossy(&o.stdout)),
        Err(e) => writeln!(out, "(qemu-img failed: {e})").unwrap(),
    }
    match Command::new("sudo")
        .args(["sha256sum", canonical_resolved.to_str().unwrap_or(canonical_link)])
        .output()
    {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            let sha = s.split_whitespace().next().unwrap_or("(none)");
            writeln!(out, "canonical sha256: {sha}").unwrap();
        }
        Err(e) => writeln!(out, "(sha256sum failed: {e})").unwrap(),
    }
    out.push('\n');

    // Per-VM: resolve vda source via libvirt XML, then qemu-img info + sha256.
    for vm in VM_NAMES {
        writeln!(out, "=== {vm} (vda) ===").unwrap();
        let path = match crate::pipeline::resolve_vda_source(vm) {
            Ok(p) => p,
            Err(e) => {
                write!(out, "(resolve_vda_source failed: {e:#})\n\n").unwrap();
                continue;
            }
        };
        writeln!(out, "resolved path: {path}").unwrap();
        match Command::new("sudo")
            .args(["qemu-img", "info", &path])
            .output()
        {
            Ok(o) => {
                let info = String::from_utf8_lossy(&o.stdout);
                for line in info.lines().take(5) {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            Err(e) => writeln!(out, "(qemu-img failed: {e})").unwrap(),
        }
        match Command::new("sudo")
            .args(["sha256sum", &path])
            .output()
        {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout);
                let sha = s.split_whitespace().next().unwrap_or("(none)");
                writeln!(out, "sha256: {sha}").unwrap();
            }
            Err(e) => writeln!(out, "(sha256sum failed: {e})").unwrap(),
        }
        out.push('\n');
    }

    let path = host_dir.join("vm-rootfs-format.log");
    if let Err(e) = fs::write(&path, out) {
        eprintln!("  host capture: write {} failed: {e:#}", path.display());
    }
}

/// Capture per-node identity check artefacts: in-VM beamfs.ko sha256 +
/// host-side reference (lsmod, modinfo head).
fn capture_identity_per_node(host_dir: &Path) {
    println!("[pre]    Host capture: identity per node (4 SSH probes)");
    for (vm, ip) in VM_IPS {
        let remote = r#"
echo "=== uname -r ==="
uname -r
echo
echo "=== beamfs.ko sha256 in /lib/modules ==="
sudo find /lib/modules -name 'beamfs.ko*' -type f 2>/dev/null | xargs -r sudo sha256sum 2>&1
echo
echo "=== lsmod | grep beamfs ==="
lsmod | grep -E 'beamfs|reed_solomon|radfi'
"#;
        let out = ssh_capture(ip, remote);
        let path = host_dir.join(format!("identity-{vm}.txt"));
        if let Err(e) = fs::write(&path, out) {
            eprintln!("  identity-{vm}.txt write failed: {e:#}");
        }
    }
}

/// Capture VM-side runtime state pre-attack: df, mount, lsblk, ip, cmdline.
/// Reproducibility baseline.
fn capture_vm_runtime_state(host_dir: &Path) {
    println!("[pre]    Host capture: VM runtime state (4 SSH probes)");
    for (vm, ip) in VM_IPS {
        let remote = r#"
echo "=== df -h ==="
df -h 2>&1
echo
echo "=== mount ==="
mount 2>&1
echo
echo "=== lsblk ==="
lsblk 2>&1
echo
echo "=== ip a ==="
ip a 2>&1
echo
echo "=== ip route ==="
ip route 2>&1
echo
echo "=== /proc/cmdline ==="
cat /proc/cmdline 2>&1
echo
echo "=== /etc/os-release ==="
cat /etc/os-release 2>&1
"#;
        let out = ssh_capture(ip, remote);
        let path = host_dir.join(format!("vm-state-{vm}.log"));
        if let Err(e) = fs::write(&path, out) {
            eprintln!("  vm-state-{vm}.log write failed: {e:#}");
        }
    }
}

/// Capture full modinfo for beamfs, `reed_solomon`, radfi on each node.
fn capture_vm_modinfo(host_dir: &Path) {
    println!("[pre]    Host capture: modinfo per node (4 SSH probes)");
    for (vm, ip) in VM_IPS {
        let remote = r#"
for mod in beamfs reed_solomon radfi; do
    echo "=== modinfo $mod ==="
    sudo modinfo "$mod" 2>&1
    echo
done
"#;
        let out = ssh_capture(ip, remote);
        let path = host_dir.join(format!("modinfo-{vm}.log"));
        if let Err(e) = fs::write(&path, out) {
            eprintln!("  modinfo-{vm}.log write failed: {e:#}");
        }
    }
}
