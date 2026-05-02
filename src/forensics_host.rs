//! forensics_host.rs - host-side forensic capture for beamfs-bench.
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
//!                              (block_rq_complete + sched_switch counts)
//!
//! ## Why a separate module
//!
//! `forensics.rs` is VM-side: every function takes a list of `ClusterNode`
//! and SSHes into the guest. Adding host-side captures there would
//! conflate two responsibilities and break the existing single-purpose
//! contract documented at the top of `forensics.rs`. Keeping host-side
//! in `forensics_host.rs` makes the orchestration in `analyse.rs` an
//! explicit two-step parallel: VM forensics + host forensics.
//!
//! ## bpftrace VM-side (out of scope for this module)
//!
//! bpftrace is not currently in the Yocto image
//! `hpc-arm64-research-beamfs.bb` (R23). VM-side bpftrace would require
//! adding it to IMAGE_INSTALL and rebuilding. Tracked as a follow-up.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::forensics::Scope;

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
        .with_context(|| format!("spawn bash -c {cmd:?}"))?;
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
        .with_context(|| format!("create_dir_all {:?}", host_dir))?;

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
IMG=~/yocto/poky/build-qemu-arm64/tmp/deploy/images/qemuarm64/hpc-arm64-research-beamfs-qemuarm64.ext2
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
    let pid = match fs::read_to_string(BPFTRACE_PID_FILE) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            eprintln!("[post]   bpftrace stop skipped: no PID file (was bpftrace started?)");
            return;
        }
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
            .map(|s| s.success())
            .unwrap_or(false);
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
