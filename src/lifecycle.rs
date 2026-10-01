//! lifecycle.rs - VM lifecycle management for beamfs-bench full.
//!
//! ## Pipeline (per spec R0/R1)
//!
//! 1. Define missing VMs from /etc/libvirt/qemu/<vm>.xml if not in libvirt
//! 2. Destroy ALL 4 VMs unconditionally (R1: destroy aveugle - graceful
//!    shutdown does not work reliably on these images)
//! 3. Start hpcnet if inactive
//! 4. Start the 4 VMs cold
//! 5. Wait SSH ready on all 4 nodes in parallel (R3: parallele + verbose)
//! 6. ABORT on any node timeout (R3: 1 fail = full abort)
//!
//! All virsh operations go through `sudo virsh -c qemu:///system` because
//! the system URI requires root, and the user is in the libvirt group with
//! NOPASSWD virsh in /etc/sudoers.d/beamfs-bench (installed by ebuild).

use anyhow::{anyhow, bail, Context, Result};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The 4 VMs managed by lifecycle. Order matches `cluster.rs::CLUSTER_NODES`.
pub const VMS: &[(&str, &str)] = &[
    ("beamfs-master",    "192.168.56.10"),
    ("beamfs-compute01", "192.168.56.11"),
    ("beamfs-compute02", "192.168.56.12"),
    ("beamfs-compute03", "192.168.56.13"),
];

/// Network name in libvirt. Bridge = virbr1.
pub const HPCNET: &str = "hpcnet";

/// SSH wait per-node timeout in seconds. Parallel across nodes.
pub const SSH_WAIT_TIMEOUT_SEC: u64 = 180;

/// Run a virsh command via sudo on <qemu:///system>. Returns trimmed stdout.
fn virsh_sudo(args: &[&str]) -> Result<String> {
    let mut full_args = vec!["virsh", "-c", "qemu:///system"];
    full_args.extend_from_slice(args);

    let output = Command::new("sudo")
        .args(&full_args)
        .output()
        .with_context(|| format!("spawn sudo virsh {args:?}"))?;

    if !output.status.success() {
        return Err(anyhow!(
            "sudo virsh {args:?} failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Same as `virsh_sudo` but tolerates non-zero exit (some virsh subcommands
/// like `domstate` on undefined domain return 1 normally).
pub(crate) fn virsh_sudo_lenient(args: &[&str]) -> (i32, String, String) {
    let mut full_args = vec!["virsh", "-c", "qemu:///system"];
    full_args.extend_from_slice(args);

    match Command::new("sudo").args(&full_args).output() {
        Ok(out) => (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ),
        Err(e) => (-1, String::new(), format!("spawn error: {e}")),
    }
}

/// Phase 1.1: define missing VMs from /etc/libvirt/qemu/<vm>.xml if not yet
/// known to libvirt. No-op if already defined.
pub fn define_missing_vms() -> Result<()> {
    println!("[lifecycle] Phase 1.1 - define missing VMs (if any)");
    for (vm, _ip) in VMS {
        let (rc, _, _) = virsh_sudo_lenient(&["domstate", vm]);
        if rc == 0 {
            println!("  {vm} : already defined");
            continue;
        }
        // Not defined - try to define from XML on disk
        let xml_path = format!("/etc/libvirt/qemu/{vm}.xml");
        if !Path::new(&xml_path).exists() {
            bail!("VM {vm} is not defined and {xml_path} does not exist");
        }
        println!("  {vm} : defining from {xml_path}");
        let out = virsh_sudo(&["define", &xml_path])
            .with_context(|| format!("virsh define {xml_path}"))?;
        println!("    -> {out}");
    }
    Ok(())
}

/// Phase 1.2: destroy ALL VMs unconditionally (R1 destroy aveugle).
/// destroy on a shut-off domain returns error; we tolerate it.
pub fn destroy_all_vms() {
    println!("[lifecycle] Phase 1.2 - destroy all 4 VMs (aveugle)");
    for (vm, _ip) in VMS {
        let (rc, _stdout, stderr) = virsh_sudo_lenient(&["destroy", vm]);
        if rc == 0 {
            println!("  {vm} : destroyed");
        } else if stderr.contains("not running") || stderr.contains("not active") {
            println!("  {vm} : already shut off");
        } else {
            // Unexpected error: surface it but do not abort yet
            // (the start phase will fail clearly if the VM is in a bad state)
            eprintln!("  {vm} : destroy returned rc={rc}: {stderr}");
        }
    }
    // Brief settle wait so libvirt fully releases resources before start
    thread::sleep(Duration::from_secs(2));
}

/// Phase 1.3: start hpcnet if not active.
pub fn start_network() -> Result<()> {
    println!("[lifecycle] Phase 1.3 - ensure hpcnet network is active");
    // Query state
    let (_rc, info, _) = virsh_sudo_lenient(&["net-info", HPCNET]);
    let active = info.lines()
        .find(|l| l.starts_with("Active:"))
        .is_some_and(|l| l.trim_end().ends_with("yes"));
    if active {
        println!("  {HPCNET} : already active");
        return Ok(());
    }
    println!("  {HPCNET} : starting");
    virsh_sudo(&["net-start", HPCNET])
        .with_context(|| format!("net-start {HPCNET}"))?;
    println!("  {HPCNET} : started");
    Ok(())
}

/// Phase 1.4: start the 4 VMs.
pub fn start_all_vms() -> Result<()> {
    println!("[lifecycle] Phase 1.4 - start all 4 VMs");
    for (vm, _ip) in VMS {
        let out = virsh_sudo(&["start", vm])
            .with_context(|| format!("virsh start {vm}"))?;
        println!("  {vm} : {out}");
    }
    Ok(())
}

/// Phase 1.5: wait for SSH to become ready on all 4 nodes IN PARALLEL.
/// Returns Err if any node times out (R3: 1 fail = full abort).
pub fn wait_ssh_ready_parallel() -> Result<()> {
    println!("[lifecycle] Phase 1.5 - waiting for SSH on 4 nodes in parallel (timeout {SSH_WAIT_TIMEOUT_SEC}s each)");

    // Shared progress mutex to prevent interleaved println from 4 threads
    let progress: Arc<Mutex<()>> = Arc::new(Mutex::new(()));

    let mut handles = Vec::with_capacity(VMS.len());
    for (vm, ip) in VMS {
        let vm = vm.to_string();
        let ip = ip.to_string();
        let progress = Arc::clone(&progress);
        let h = thread::spawn(move || -> Result<()> {
            let key_path = crate::lab::ssh_key().to_string();
            let start = Instant::now();
            let timeout = Duration::from_secs(SSH_WAIT_TIMEOUT_SEC);
            let mut attempt = 0u32;
            loop {
                attempt += 1;
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    let _g = progress.lock();
                    eprintln!("  [{vm}] TIMEOUT after {}s (attempt {attempt})", elapsed.as_secs());
                    return Err(anyhow!(
                        "SSH wait timeout for {vm} ({ip}); ssh said: {}",
                        last_probe_error(&ip)
                    ));
                }
                let ok = ssh_probe(&ip, &key_path);
                {
                    let _g = progress.lock();
                    if ok {
                        println!("  [{vm}] READY (attempt {attempt}, {}s)", elapsed.as_secs());
                        return Ok(());
                    }
                    // Verbose every 5 attempts to avoid noise but show liveness (R3)
                    if attempt == 1 || attempt.is_multiple_of(5) {
                        println!("  [{vm}] retry {attempt} ({}s elapsed)", elapsed.as_secs());
                    }
                }
                thread::sleep(Duration::from_secs(2));
            }
        });
        handles.push(h);
    }

    let mut errors: Vec<anyhow::Error> = Vec::new();
    for h in handles {
        match h.join().map_err(|_| anyhow!("ssh-wait thread panicked")) {
            Ok(Ok(())) => {}
            Ok(Err(e)) | Err(e) => errors.push(e),
        }
    }

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("[lifecycle] SSH wait error: {e:#}");
        }
        bail!("{} node(s) failed SSH readiness", errors.len());
    }
    println!("[lifecycle] All 4 nodes SSH ready");
    Ok(())
}

/// Single SSH probe: ssh -`BatchMode` -ConnectTimeout=2 'true'.
/// Returns true on exit 0, false otherwise.
///
/// What ssh printed on a failure is kept, per address, for the timeout
/// to report: until 0.14.5 stderr went to /dev/null, and four domains
/// refusing the key read as four domains that never came up.
pub(crate) fn ssh_probe(ip: &str, key_path: &str) -> bool {
    let out = Command::new("ssh")
        .args([
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=2",
            "-o", "LogLevel=ERROR",
            "-i", key_path,
            &format!("hpcadmin@{ip}"),
            "true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .output();
    let (ok, why) = match out {
        Ok(o) if o.status.success() => (true, String::new()),
        Ok(o) => {
            let said = String::from_utf8_lossy(&o.stderr).trim().to_string();
            let status = o.status;
            (false, if said.is_empty() { format!("nothing, and exited with {status}") } else { said })
        }
        Err(e) => (false, format!("ssh did not start: {e}")),
    };
    if let Ok(mut m) = last_probe_errors().lock() {
        if ok {
            m.remove(ip);
        } else {
            m.insert(ip.to_string(), why);
        }
    }
    ok
}

/// The last thing ssh said, per address, when a probe failed.
fn last_probe_errors() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static M: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        std::sync::OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// What ssh said the last time a probe of `ip` failed.
#[must_use]
pub(crate) fn last_probe_error(ip: &str) -> String {
    last_probe_errors()
        .lock()
        .ok()
        .and_then(|m| m.get(ip).cloned())
        .unwrap_or_else(|| "no failed probe recorded".to_string())
}

/// Top-level entry: run the full Phase 1 lifecycle pipeline.
/// Returns Ok(()) only when 4 VMs are running and SSH-ready.
/// Pre-flight assertion: verify the cluster is in the expected isolated
/// architecture before any other action.
///
/// Architecture per recadrage R-isolation:
///   master    : vda (rootfs) + vdb (cluster /data) ONLY
///                (orchestrator, never `RadFI` target, no FS-test USB)
///   compute01 : vda + vdb + N USB FS-test victims at vdc..vd?
///                (N is adaptive ; count is read from libvirt XML
///                 by Phase 0.0a `usb_health`, not enforced here)
///   compute02 : vda + vdb only
///   compute03 : vda + vdb only
///
/// Returns Err if the persistent libvirt XML diverges from this contract.
/// This guarantees the bench cannot run on a misconfigured cluster
/// where transverse `RadFI` contamination would invalidate results.
pub fn assert_isolation_architecture() -> Result<()> {

    println!("================================================================");
    println!(" beamfs-bench lifecycle - Phase 0: isolation pre-flight check");
    println!("================================================================");

    // Per-VM check policy (Architecture C, 2026-05-07 hardware refresh).
    //
    // master : strict equal vs ["vda", "vdb"].
    //   Invariant : master is orchestrator and never a FS-test victim.
    //   Any extra disk indicates a transverse-RadFI contamination risk.
    //
    // compute01 + compute02 + compute03 : start with ["vda", "vdb"],
    //   then accept any number (including 0) of vd[c-z] USB slots.
    //   Phase 0.0a usb_health audits those slots in detail immediately
    //   after. Invariant : the FS-test USB topology is symmetric across
    //   the 3 computes (5 USB per compute on Architecture C, total 15) ;
    //   the exact USB count is hardware-dependent and adaptive.
    let strict_vms: &[(&str, &[&str])] = &[
        ("beamfs-master", &["vda", "vdb"]),
    ];
    let usb_compute_vms: &[&str] = &[
        "beamfs-compute01",
        "beamfs-compute02",
        "beamfs-compute03",
    ];

    let extract_disk_targets = |xml: &str| -> Vec<String> {
        let mut found: Vec<String> = xml.lines()
            .filter_map(|l| {
                let l = l.trim();
                if l.starts_with("<target dev='vd") && l.contains("bus='virtio'") {
                    let start = l.find("dev='").map(|i| i + 5)?;
                    let rest = &l[start..];
                    let end = rest.find('\'')?;
                    Some(rest[..end].to_string())
                } else {
                    None
                }
            })
            .collect();
        found.sort();
        found
    };

    let dumpxml = |vm: &str| -> Result<String> {
        let out = Command::new("sudo")
            .args(["virsh", "-c", "qemu:///system", "dumpxml", vm])
            .output()
            .with_context(|| format!("virsh dumpxml {vm}"))?;
        if !out.status.success() {
            bail!("virsh dumpxml {vm} failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    };

    // 1. Strict-equal VMs.
    for (vm, want) in strict_vms {
        let xml = dumpxml(vm)?;
        let found = extract_disk_targets(&xml);
        let mut want_sorted: Vec<String> = want.iter().map(std::string::ToString::to_string).collect();
        want_sorted.sort();
        if found != want_sorted {
            eprintln!("  [{vm}] FAIL");
            eprintln!("    expected : {want_sorted:?}");
            eprintln!("    found    : {found:?}");
            bail!(
                "isolation architecture violation on {vm}: expected disk targets {want_sorted:?}, found {found:?}. \
                 The cluster has been modified outside beamfs-bench and the FS-test isolation \
                 contract is broken (a non-compute01 VM has a USB attached). \
                 Restore architecture before running this bench. \
                 See context-recadrage.md R-isolation."
            );
        }
        println!("  [{vm}] OK ({} disks: {})", found.len(), found.join(","));
    }

    // 2. compute01 + compute02 + compute03 : vda + vdb + any vd[c-z] (>= 0 USBs).
    for vm in usb_compute_vms {
        let vm = *vm;
        let xml = dumpxml(vm)?;
        let found = extract_disk_targets(&xml);

        // Required prefix.
        if !found.contains(&"vda".to_string()) || !found.contains(&"vdb".to_string()) {
            eprintln!("  [{vm}] FAIL");
            eprintln!("    expected : at least vda + vdb");
            eprintln!("    found    : {found:?}");
            bail!(
                "isolation architecture violation on {vm}: missing vda or vdb. \
                 {vm} needs a rootfs (vda) and cluster /data (vdb) at minimum. \
                 See context-recadrage.md R-isolation."
            );
        }

        // Other disks must be vd[c-z] (USB slots).
        let extras: Vec<&String> = found.iter()
            .filter(|d| d.as_str() != "vda" && d.as_str() != "vdb")
            .collect();
        for d in &extras {
            if d.len() != 3 || !d.starts_with("vd") {
                eprintln!("  [{vm}] FAIL");
                eprintln!("    found    : {found:?}");
                bail!(
                    "isolation architecture violation on {vm}: unexpected disk target {d:?}. \
                     {vm} disks must be vda + vdb + USB slots at vd[c-z]. \
                     See context-recadrage.md R-isolation."
                );
            }
            let suffix = d.chars().nth(2).unwrap();
            if !('c'..='z').contains(&suffix) {
                eprintln!("  [{vm}] FAIL");
                eprintln!("    found    : {found:?}");
                bail!(
                    "isolation architecture violation on {vm}: USB slot has out-of-range \
                     target {d:?} (allowed: vdc..vdz). \
                     See context-recadrage.md R-isolation."
                );
            }
        }

        println!(
            "  [{vm}] OK ({} disks: {} ; {} USB slot(s) -- audit in Phase 0.0a)",
            found.len(),
            found.join(","),
            extras.len(),
        );
    }

    println!("[isolation] Phase 0 complete - architecture matches R-isolation contract");
    Ok(())
}

/// Optional shutdown phase (called by `full --shutdown` only).
pub fn bring_cluster_down() {
    println!("[lifecycle] Phase 8 - shutdown (--shutdown given)");
    destroy_all_vms();
}
