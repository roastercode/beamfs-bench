//! devices.rs  -  authoritative device discovery via `virsh dumpxml`.
//!
//! ## Why this module exists (anti-NAK / R12 of context-recadrage)
//!
//! virtio-blk strips the SCSI/USB serial inside the guest VM. So
//! `/dev/disk/by-id/` does not exist in the master VM, and the worker
//! cannot tell which physical USB stick is behind /dev/vdc, vdd, ...
//!
//! The ONLY authoritative source of the (vdX -> usb-by-id) mapping is
//! the libvirt domain XML on the host (spartian). This module:
//!
//!   1. Calls `virsh -c qemu:///system dumpxml <vm>` (no sudo needed
//!      when the user is in the libvirt group).
//!   2. Parses the XML and extracts each <disk><target dev="vdX">
//!      <source dev="..."/></disk> block.
//!   3. Resolves the symlink chain to get the kernel device (e.g. /dev/sde1).
//!   4. Renders a clear validation table with full by-id paths + sizes.
//!   5. Prompts the user for confirmation, defaulting to ABORT.
//!
//! No mkfs/dd/destructive action runs until the table has been validated.
//! `--auto-confirm` skips the prompt for CI/scripted use only.

use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::fmt::Write;

/// Authoritative description of a single virtio-blk target as wired up
/// by libvirt. The `host_byid_path` is the path passed to qemu in the
/// domain XML, which is typically a /dev/disk/by-id/usb-... symlink
/// pointing at the actual /dev/sdX1 partition.
#[derive(Debug, Clone)]
pub struct VirtioDisk {
    /// Guest target name (e.g. "vdc").
    pub guest_dev: String,
    /// Host path written in the domain XML (e.g.
    /// "/dev/disk/by-id/usb-Kingston_DataTraveler_3.0_E0D55EA574E5E9C119DA006B-0:0-part1").
    pub host_byid_path: String,
    /// Resolved kernel device on the host (e.g. "/dev/sde1").
    pub host_resolved: Option<PathBuf>,
    /// Size on the host (e.g. "2.0G"), best-effort via blockdev.
    pub host_size: Option<String>,
    /// Optional human-friendly model derived from by-id name, for the table.
    pub host_model_summary: String,
}

/// Skip the system disks (vda = guest root, vdb = system /data).
/// vdb hosts beamfs on /data which is the cluster scope target;
/// it is intentionally NOT exposed as a multifs candidate.
const SKIPPED_TARGETS: &[&str] = &["vda", "vdb"];

/// Run `virsh -c qemu:///system dumpxml <vm>` and parse out the virtio-blk
/// disks (targets vd[c-z]). Returns an ordered map keyed by `guest_dev`.
pub fn discover_virtio_disks(vm_name: &str) -> Result<BTreeMap<String, VirtioDisk>> {
    let output = Command::new("virsh")
        .args(["-c", "qemu:///system", "dumpxml", vm_name])
        .output()
        .with_context(|| format!("failed to spawn `virsh dumpxml {vm_name}`"))?;

    if !output.status.success() {
        return Err(anyhow!(
            "virsh dumpxml {} failed (exit {:?}): {}",
            vm_name,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let xml = String::from_utf8(output.stdout)
        .context("virsh dumpxml stdout is not UTF-8")?;

    let doc = roxmltree::Document::parse(&xml)
        .with_context(|| format!("failed to parse virsh dumpxml output for {vm_name}"))?;

    let mut disks: BTreeMap<String, VirtioDisk> = BTreeMap::new();

    for disk in doc.descendants().filter(|n| n.has_tag_name("disk")) {
        // Only consider <disk type='block' device='disk'>
        let disk_type = disk.attribute("type").unwrap_or("");
        let device_kind = disk.attribute("device").unwrap_or("");
        if disk_type != "block" || device_kind != "disk" {
            continue;
        }

        let target = disk.children().find(|n| n.has_tag_name("target"));
        let source = disk.children().find(|n| n.has_tag_name("source"));
        let driver = disk.children().find(|n| n.has_tag_name("driver"));

        let (Some(target), Some(source)) = (target, source) else {
            continue;
        };

        // Only virtio bus
        let bus = target.attribute("bus").unwrap_or("");
        if bus != "virtio" {
            continue;
        }
        // Driver name should be qemu (skip exotic ones)
        if let Some(d) = driver {
            let driver_name = d.attribute("name").unwrap_or("");
            if driver_name != "qemu" {
                continue;
            }
        }

        let guest_dev = match target.attribute("dev") {
            Some(s) => s.to_string(),
            None => continue,
        };
        if SKIPPED_TARGETS.contains(&guest_dev.as_str()) {
            continue;
        }

        let host_byid_path = match source.attribute("dev") {
            Some(s) => s.to_string(),
            None => continue, // file-backed: not in scope for this multifs
        };

        // Resolve symlink to the actual /dev/sdX[1] kernel device.
        let host_resolved = std::fs::canonicalize(&host_byid_path).ok();

        // Size via blockdev --getsize64, formatted to human-readable IEC.
        let host_size = host_resolved.as_ref().and_then(|p| query_size_human(p));

        let host_model_summary = summarize_byid(&host_byid_path);

        disks.insert(
            guest_dev.clone(),
            VirtioDisk {
                guest_dev,
                host_byid_path,
                host_resolved,
                host_size,
                host_model_summary,
            },
        );
    }

    if disks.is_empty() {
        return Err(anyhow!(
            "no virtio-blk targets found in domain XML for {vm_name} (skipped vda/vdb)"
        ));
    }
    Ok(disks)
}

/// Get human-readable size of a block device. Tries `lsblk -bn -o SIZE`
/// first (no sudo needed); falls back to `blockdev --getsize64` (which
/// requires read access to the device, available without sudo if user
/// is in the disk/plugdev group). Returns None on any failure.
fn query_size_human(path: &std::path::Path) -> Option<String> {
    // Try lsblk first (works without sudo for block-readable devices)
    let out = Command::new("lsblk")
        .args(["-bndo", "SIZE"])
        .arg(path)
        .output()
        .ok()?;
    if out.status.success() {
        if let Ok(s) = std::str::from_utf8(&out.stdout) {
            if let Ok(n) = s.trim().parse::<u64>() {
                return Some(format_iec(n));
            }
        }
    }
    // Fallback: blockdev --getsize64
    let out = Command::new("blockdev")
        .args(["--getsize64"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let n: u64 = std::str::from_utf8(&out.stdout).ok()?.trim().parse().ok()?;
    Some(format_iec(n))
}

#[allow(clippy::cast_precision_loss)] // display only: exact below 2^53 bytes
fn format_iec(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut size = n as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n}B")
    } else {
        format!("{:.1}{}", size, UNITS[unit])
    }
}

/// Best-effort short label derived from the by-id path. Used in the
/// validation table so the user can quickly recognize physical sticks.
/// Example:
///   /dev/disk/by-id/usb-Kingston_DataTraveler_3.0_E0D55EA574E5E9C119DA006B-0:0-part1
///   -> "Kingston `DataTraveler` ...DA006B"
fn summarize_byid(path: &str) -> String {
    let basename = path.rsplit('/').next().unwrap_or(path);
    // Strip "usb-" / "ata-" prefix and "-0:0-part1" suffix
    let stripped = basename
        .trim_start_matches("usb-")
        .trim_start_matches("ata-")
        .trim_end_matches("-part1")
        .trim_end_matches("-0:0");

    // Try to extract last 6 chars of the long serial as a short id
    let parts: Vec<&str> = stripped.rsplitn(2, '_').collect();
    if parts.len() == 2 {
        let serial = parts[0];
        let model = parts[1].replace('_', " ");
        let tail: String = serial.chars().rev().take(6).collect::<Vec<_>>()
            .into_iter().rev().collect();
        format!("{model} ...{tail}")
    } else {
        stripped.replace('_', " ")
    }
}

/// Mapping (`fs_name`, `guest_dev`) requested by the user, derived from the
/// default multifs FS list and the disks discovered.
#[derive(Debug, Clone)]
pub struct ProposedMapping {
    pub fs_name: String,
    pub disk: VirtioDisk,
}

/// Match the default multifs FS list to the discovered disks by `guest_dev`.
/// Returns mappings only for disks that match a known FS slot (vdc=ext4, etc.).
/// Disks with no matching FS slot are reported separately so the user can see
/// what's "extra" on the VM.
pub fn build_default_mapping(
    disks: &BTreeMap<String, VirtioDisk>,
    fs_list: &[(&str, &str)],
) -> (Vec<ProposedMapping>, Vec<VirtioDisk>) {
    let mut matched: Vec<ProposedMapping> = Vec::new();
    let mut extras: Vec<VirtioDisk> = Vec::new();

    let mut consumed: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (fs, vd) in fs_list {
        if let Some(disk) = disks.get(*vd) {
            matched.push(ProposedMapping {
                fs_name: fs.to_string(),
                disk: disk.clone(),
            });
            consumed.insert((*vd).to_string());
        }
    }
    for (vd, disk) in disks {
        if !consumed.contains(vd) {
            extras.push(disk.clone());
        }
    }
    (matched, extras)
}

/// Render the validation table to stdout. Returns the rendered string
/// for inclusion in run_dir/devices-validated.txt as audit trail.
pub fn render_validation_table(
    vm_name: &str,
    matched: &[ProposedMapping],
    extras: &[VirtioDisk],
) -> String {
    let mut out = String::new();
    out.push_str("================================================================\n");
    out.push_str(" beamfs-bench: device validation required\n");
    out.push_str("================================================================\n");
    writeln!(out, " VM: {vm_name} (libvirt qemu:///system)").unwrap();
    out.push('\n');
    out.push_str(" The following devices on the HOST will be used as multifs targets.\n");
    out.push_str(" Each line shows the GUEST device (vdX) and its HOST identity\n");
    out.push_str(" (by-id path -> kernel device -> size). All filesystems will be\n");
    out.push_str(" REFORMATTED. ALL EXISTING DATA ON THESE DEVICES WILL BE DESTROYED.\n");
    out.push('\n');
    out.push_str(" FS slot  | Guest | Host kernel dev | Size  | Physical identity\n");
    out.push_str(" ---------+-------+-----------------+-------+----------------------------\n");
    for m in matched {
        let resolved = m.disk.host_resolved.as_ref().map_or_else(|| "(unresolved)".to_string(), |p| p.display().to_string());
        let size = m.disk.host_size.as_deref().unwrap_or("?");
        writeln!(out,
            " {:<8} | {:<5} | {:<15} | {:<5} | {}",
            m.fs_name, m.disk.guest_dev, resolved, size, m.disk.host_model_summary
        ).unwrap();
    }
    if !extras.is_empty() {
        out.push('\n');
        out.push_str(" Disks present on the VM but NOT in the default FS slot list:\n");
        for e in extras {
            let resolved = e.host_resolved.as_ref().map_or_else(|| "(unresolved)".to_string(), |p| p.display().to_string());
            let size = e.host_size.as_deref().unwrap_or("?");
            writeln!(out,
                "   {:<5} -> {} ({}) [{}]",
                e.guest_dev, resolved, size, e.host_model_summary
            ).unwrap();
        }
        out.push_str(" These disks will NOT be touched.\n");
    }
    out.push('\n');
    out.push_str(" By-id paths (full, copy-pasteable for `ls -la`):\n");
    for m in matched {
        writeln!(out, "   {} -> {}", m.disk.guest_dev, m.disk.host_byid_path).unwrap();
    }
    out.push_str("================================================================\n");
    out
}

/// Prompt the user with a [y/N] confirmation, default = N (abort).
/// Returns true on explicit yes only. Honors --auto-confirm.
pub fn prompt_confirm(auto_confirm: bool) -> Result<bool> {
    if auto_confirm {
        eprintln!("beamfs-bench: --auto-confirm given, proceeding without prompt.");
        return Ok(true);
    }
    let confirmed = dialoguer::Confirm::new()
        .with_prompt("Proceed with these targets?")
        .default(false)
        .interact()
        .context("failed to read user confirmation")?;
    Ok(confirmed)
}

/// One-shot pipeline: discover + render + (optionally) prompt.
/// Returns the validated mappings ready for `MultifsConfig::fs_list`.
pub fn discover_and_validate(
    vm_name: &str,
    fs_list: &[(&str, &str)],
    auto_confirm: bool,
    dry_run: bool,
) -> Result<Vec<ProposedMapping>> {
    let disks = discover_virtio_disks(vm_name)
        .with_context(|| format!("device discovery failed for {vm_name}"))?;
    let (matched, extras) = build_default_mapping(&disks, fs_list);

    let table = render_validation_table(vm_name, &matched, &extras);
    print!("{table}");

    if matched.len() != fs_list.len() {
        eprintln!(
            "beamfs-bench: WARNING  -  {} FS slot(s) declared but only {} disk(s) matched.",
            fs_list.len(),
            matched.len()
        );
        let missing: Vec<&str> = fs_list.iter()
            .filter(|(_, vd)| !disks.contains_key(*vd))
            .map(|(_, vd)| *vd)
            .collect();
        eprintln!("beamfs-bench: missing guest device(s): {missing:?}");
    }

    if dry_run {
        eprintln!("beamfs-bench: --dry-run given, NOT prompting and NOT proceeding.");
        return Err(anyhow!("dry-run aborted before any destructive action"));
    }

    if !prompt_confirm(auto_confirm)? {
        return Err(anyhow!("user did not confirm; aborting"));
    }

    Ok(matched)
}
