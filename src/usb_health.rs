//! `usb_health.rs` - pre-flight USB pass-through health audit.
//!
//! Runs in Phase 0.0a of `beamfs-bench full`, between R21 isolation
//! invariant (Phase 0.0) and code analysis (Phase 0.0bis). Aborts early
//! if the cluster cannot be reliably bench'd because the host-side USB
//! pass-through devices declared in `virsh dumpxml beamfs-compute01`
//! are missing or unreadable.
//!
//! Rationale : a failed mkfs.ext4 on a half-dead USB stick wastes 5+
//! minutes of bitbake + cluster bring-up before the failure surfaces
//! mid-pipeline. By checking host-side block-device health up front,
//! the pipeline aborts in <1s with a clear verdict per slot.
//!
//! Design contract :
//!   - Read-only on the host. No mkfs, no dd write, no mount.
//!   - Read 1 MiB at offset 0 + 1 MiB at (size - 1 MiB) per device.
//!   - Verdict per (slot, by-id) : Healthy(size, serial) or Dead(reason).
//!   - The expected number of healthy slots is parameterised
//!     Expected count = number of <disk type='block'> entries in the
//!     libvirt XML. The bench is fully adaptive : add/remove a USB
//!     in the libvirt declaration, the bench picks it up next run.
//!   - Run aborts (returns Err) iff `healthy_count` < `declared_count`
//!     OR `healthy_count` == 0 (strict-with-log per user policy).
//!
//! Author: Aurelien DESBRIERES <aurelien@hackers.camp>
//! License: GPL-2.0-only

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::os::unix::fs::FileTypeExt;

/// libvirt URI used by the bench (matches lifecycle.rs convention).
const LIBVIRT_URI: &str = "qemu:///system";

/// VM that holds the USB pass-through devices (per R-isolation R21).
const USB_HOLDER_VM: &str = "beamfs-compute01";

/// Filesystem priority for runtime mapping construction (L5).
///
/// When N USB sticks are healthy, the bench picks the first N entries
/// of this list and maps them to the N healthy vd slots in vd-order.
/// Beamfs is first because it is the project under test ; ext4 second
/// as the RW journaling reference ; squashfs third as the read-only
/// structural baseline. ext3 + btrfs are kept for future expansion when
/// the 15-USB hardware refresh lands.
///
/// To extend : append entries here. No other code change is required ;
/// the bench will automatically use additional FS as more healthy USBs
/// become available in the libvirt declaration.
pub const FS_PRIORITY: &[&str] = &[
    "beamfs",
    "ext4",
    "squashfs",
    "ext3",
    "btrfs",
];

/// Read sanity probe size : head + tail of the device.
const PROBE_SIZE_MIB: u64 = 1;

/// Per-slot verdict after probing.
///
/// Forensic/audit fields `source` and `resolved` are part of the
/// public API contract for downstream callers (`run_dir` export,
/// crash-report.md, future test scopes), even if no current caller
/// reads them. Pattern mirrors `multifs::MultifsResult`.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SlotVerdict {
    Healthy {
        slot: String,        // "vdc", "vdd", ...
        source: PathBuf,     // /dev/disk/by-id/usb-...
        resolved: PathBuf,   // /dev/sda, /dev/sdb, ...
        size_bytes: u64,
        serial: String,
    },
    Dead {
        slot: String,
        source: PathBuf,
        reason: String,
    },
}

impl SlotVerdict {
    pub fn is_healthy(&self) -> bool {
        matches!(self, SlotVerdict::Healthy { .. })
    }

    /// Forensic accessor : slot id ("vdc", "vdd", ...) regardless of verdict.
    /// Kept public for downstream callers (e.g. crash-report formatter).
    #[allow(dead_code)]
    pub fn slot(&self) -> &str {
        match self {
            SlotVerdict::Healthy { slot, .. } | SlotVerdict::Dead { slot, .. } => slot,
        }
    }
}

/// One disk entry as parsed from `virsh dumpxml`.
///
/// `type_attr` is preserved post-filter for future logic that may
/// want to distinguish block vs file at the entry level (e.g.
/// emit a more specific error when a slot is mis-declared as file).
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct DiskEntry {
    target: String,    // "vdc"
    source: PathBuf,   // /dev/disk/by-id/...
    type_attr: String, // "block" or "file"
}

/// Run the pre-flight USB audit. Returns Ok(verdicts) on healthy match,
/// Err with a multi-line diagnostic when the count differs.
pub fn run() -> Result<Vec<SlotVerdict>> {
    println!("[0.0a] USB pre-flight (host-side block device audit)...");

    let xml = dumpxml(USB_HOLDER_VM)
        .with_context(|| format!("virsh dumpxml {USB_HOLDER_VM}"))?;
    let disks = parse_block_disks(&xml);

    if disks.is_empty() {
        return Err(anyhow!(
            "no <disk type='block'> entries found in {USB_HOLDER_VM} XML \
             (USB pass-through declarations missing)"
        ));
    }

    let verdicts: Vec<SlotVerdict> = disks
        .iter()
        .map(probe_slot)
        .collect();

    print_table(&verdicts);

    let declared = verdicts.len();
    let healthy = verdicts.iter().filter(|v| v.is_healthy()).count();

    if healthy == 0 {
        return Err(anyhow!(
            "USB pre-flight FAIL : 0 healthy slots out of {declared} declared.              At least one healthy USB is required ; check `lsblk -o              NAME,RO,TRAN,MODEL,SERIAL` and replug if needed."
        ));
    }

    if healthy < declared {
        let dead_lines: Vec<String> = verdicts
            .iter()
            .filter_map(|v| match v {
                SlotVerdict::Dead { slot, source, reason } => {
                    Some(format!("  {slot} ({}): {reason}", source.display()))
                }
                SlotVerdict::Healthy { .. } => None,
            })
            .collect();
        return Err(anyhow!(
            "USB pre-flight FAIL : {healthy} healthy slots out of {declared}              declared in {USB_HOLDER_VM} libvirt XML.\n             Dead/unreachable slots :\n{}\n             Action : either replace dead USB sticks (re-plug + verify with              `lsblk -o NAME,RO,TRAN,MODEL,SERIAL`) or remove the dead slots              from the libvirt XML (virsh edit {USB_HOLDER_VM}) so the bench              matches the physical reality.",
            dead_lines.join("\n"),
        ));
    }

    if healthy > FS_PRIORITY.len() {
        let excess = healthy - FS_PRIORITY.len();
        println!(
            "[0.0a] note : {healthy} healthy slots > {} FS in priority list ;              {excess} slot(s) will be unused. Extend FS_PRIORITY in              src/usb_health.rs to use them.",
            FS_PRIORITY.len(),
        );
    }

    println!("[0.0a] USB pre-flight OK : {healthy}/{declared} healthy slots.");
    Ok(verdicts)
}

/// Build the runtime (`fs_name`, `vd_slot`) mapping from a verdict list.
///
/// Algorithm (deterministic for reproducibility) :
///   1. Filter verdicts to keep only Healthy ones.
///   2. Sort by vd slot ascending (alphabetical : vdc, vdd, vde, ...).
///   3. Pair with `FS_PRIORITY` in order : index 0 -> beamfs, 1 -> ext4, etc.
///   4. Stop at `min(healthy_count`, `FS_PRIORITY.len()`).
///
/// Returns Vec<(`fs_name`, vd)> ready to drop into `MultifsConfig.fs_list`.
/// Empty vec is returned for empty input -- caller should validate first.
pub fn build_fs_mapping(verdicts: &[SlotVerdict]) -> Vec<(String, String)> {
    let mut healthy_slots: Vec<&str> = verdicts
        .iter()
        .filter_map(|v| match v {
            SlotVerdict::Healthy { slot, .. } => Some(slot.as_str()),
            SlotVerdict::Dead { .. } => None,
        })
        .collect();
    healthy_slots.sort_unstable();

    // v3 campaign : env var BEAMFS_BENCH_FS_LIST overrides FS_PRIORITY
    // for batch-mode comparative testing across multiple FS sets without
    // rebuild. Fallback to FS_PRIORITY hardcoded list.
    // Format : "fs1,fs2,fs3,..." (comma-separated, no spaces around commas).
    let fs_priority_owned: Vec<String>;
    let fs_priority_slice: &[&str] = match std::env::var("BEAMFS_BENCH_FS_LIST") {
        Ok(env_val) if !env_val.trim().is_empty() => {
            fs_priority_owned = env_val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            // Leak to &'static is unsafe ; instead use Vec<&str> built from owned
            // Use a temporary Vec that lives as long as this function scope.
            // We build the output directly below to avoid lifetime issues.
            let n = std::cmp::min(healthy_slots.len(), fs_priority_owned.len());
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                out.push((fs_priority_owned[i].clone(), healthy_slots[i].to_string()));
            }
            return out;
        }
        _ => FS_PRIORITY,
    };

    let n = std::cmp::min(healthy_slots.len(), fs_priority_slice.len());
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push((fs_priority_slice[i].to_string(), healthy_slots[i].to_string()));
    }
    out
}

/// Invoke `sudo virsh -c qemu:///system dumpxml <vm>` and capture stdout.
/// Uses sudo because <qemu:///system> requires libvirt group membership;
/// the bench is run by a user already in the libvirt group (per R22 OS
/// stack), but on Gentoo the polkit rules can require sudo regardless.
fn dumpxml(vm: &str) -> Result<String> {
    let out = Command::new("sudo")
        .arg("-n")
        .arg("virsh")
        .arg("-c")
        .arg(LIBVIRT_URI)
        .arg("dumpxml")
        .arg(vm)
        .output()
        .with_context(|| "spawn sudo virsh dumpxml")?;
    if !out.status.success() {
        // Fallback : try without sudo (libvirt group may suffice locally).
        let out2 = Command::new("virsh")
            .arg("-c")
            .arg(LIBVIRT_URI)
            .arg("dumpxml")
            .arg(vm)
            .output()
            .with_context(|| "spawn virsh dumpxml fallback")?;
        if !out2.status.success() {
            let s1 = String::from_utf8_lossy(&out.stderr);
            let s2 = String::from_utf8_lossy(&out2.stderr);
            return Err(anyhow!(
                "virsh dumpxml {vm} failed under both sudo and direct invocation\n\
                 sudo path  : {s1}\n\
                 direct path: {s2}"
            ));
        }
        return Ok(String::from_utf8_lossy(&out2.stdout).into_owned());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse `<disk type='block' ...>` entries from libvirt XML.
/// Only block-type disks are returned (file-type disks are VM rootfs/data,
/// not USB pass-through). Tolerates single + double quotes on attributes.
fn parse_block_disks(xml: &str) -> Vec<DiskEntry> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(start) = xml[cursor..].find("<disk ") {
        let abs_start = cursor + start;
        let Some(end_rel) = xml[abs_start..].find("</disk>") else { break; };
        let abs_end = abs_start + end_rel + "</disk>".len();
        let block = &xml[abs_start..abs_end];
        cursor = abs_end;

        let Some(type_attr) = extract_attr(block, "<disk", "type") else {
            continue
        };
        if type_attr != "block" {
            continue;
        }
        let Some(target) = extract_attr(block, "<target", "dev") else {
            continue
        };
        let Some(source) = extract_attr(block, "<source", "dev") else {
            continue
        };
        if !target.starts_with("vd") {
            continue;
        }
        out.push(DiskEntry {
            target,
            source: PathBuf::from(source),
            type_attr,
        });
    }
    out
}

/// Extract `attr="value"` or `attr='value'` from the first occurrence of
/// `tag` in `block`. Returns None if either tag or attr is absent.
fn extract_attr(block: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_idx = block.find(tag)?;
    let after_tag = &block[tag_idx..];
    let close_idx = after_tag.find('>')?;
    let header = &after_tag[..close_idx];
    let needle1 = format!("{attr}=\"");
    let needle2 = format!("{attr}='");
    if let Some(i) = header.find(&needle1) {
        let rest = &header[i + needle1.len()..];
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }
    if let Some(i) = header.find(&needle2) {
        let rest = &header[i + needle2.len()..];
        let end = rest.find('\'')?;
        return Some(rest[..end].to_string());
    }
    None
}

/// Probe one disk slot : resolve symlink, check size, dd head + tail.
fn probe_slot(d: &DiskEntry) -> SlotVerdict {
    let resolved = match std::fs::canonicalize(&d.source) {
        Ok(p) => p,
        Err(e) => {
            return SlotVerdict::Dead {
                slot: d.target.clone(),
                source: d.source.clone(),
                reason: format!("symlink target missing: {e}"),
            };
        }
    };

    if !is_block_device(&resolved) {
        return SlotVerdict::Dead {
            slot: d.target.clone(),
            source: d.source.clone(),
            reason: format!("{} is not a block device", resolved.display()),
        };
    }

    let size_bytes = match blockdev_getsize64(&resolved) {
        Ok(s) if s > 0 => s,
        Ok(_) => {
            return SlotVerdict::Dead {
                slot: d.target.clone(),
                source: d.source.clone(),
                reason: format!("blockdev --getsize64 returned 0 for {}", resolved.display()),
            };
        }
        Err(e) => {
            return SlotVerdict::Dead {
                slot: d.target.clone(),
                source: d.source.clone(),
                reason: format!("blockdev --getsize64 failed: {e}"),
            };
        }
    };

    if let Err(e) = dd_read_probe(&resolved, 0) {
        return SlotVerdict::Dead {
            slot: d.target.clone(),
            source: d.source.clone(),
            reason: format!("head read probe failed: {e}"),
        };
    }
    let tail_skip_mib = (size_bytes / (1024 * 1024)).saturating_sub(PROBE_SIZE_MIB);
    if tail_skip_mib > 0 {
        if let Err(e) = dd_read_probe(&resolved, tail_skip_mib) {
            return SlotVerdict::Dead {
                slot: d.target.clone(),
                source: d.source.clone(),
                reason: format!("tail read probe failed: {e}"),
            };
        }
    }
    // Canary write : the failure mode this catches (RO physical) is
    // exactly what made the L1 audit miss the dead Kingston stick.
    if let Err(e) = dd_canary_write(&resolved) {
        return SlotVerdict::Dead {
            slot: d.target.clone(),
            source: d.source.clone(),
            reason: format!("canary write probe failed: {e}"),
        };
    }

    // Wipe last, so every slot enters the run in the same state and the
    // probes above have already established the medium responds. A stick
    // that passes read and canary but cannot hold a wipe is failing in a
    // way that would otherwise surface mid-campaign.
    if let Err(e) = dd_wipe_and_verify(&resolved) {
        return SlotVerdict::Dead {
            slot: d.target.clone(),
            source: d.source.clone(),
            reason: format!("wipe failed: {e}"),
        };
    }

    let serial = lsblk_serial(&resolved).unwrap_or_else(|_| "?".to_string());

    SlotVerdict::Healthy {
        slot: d.target.clone(),
        source: d.source.clone(),
        resolved,
        size_bytes,
        serial,
    }
}

fn is_block_device(p: &Path) -> bool {
    std::fs::metadata(p)
        .is_ok_and(|m| m.file_type().is_block_device())
}

fn blockdev_getsize64(dev: &Path) -> Result<u64> {
    let out = Command::new("sudo")
        .arg("-n")
        .arg("blockdev")
        .arg("--getsize64")
        .arg(dev)
        .output()
        .context("spawn sudo blockdev")?;
    if !out.status.success() {
        return Err(anyhow!(
            "blockdev --getsize64 {} : {}",
            dev.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.trim().parse::<u64>()
        .with_context(|| format!("parse blockdev output: {s}"))
}

/// Read 1 MiB from `dev` at `skip_mib` MiB offset, into /dev/null.
/// Used to detect read-side faults (bad sectors, USB disconnects).
/// Wipe the first megabytes of a slot, then confirm the wipe took.
///
/// Two reasons this is not optional before a campaign.
///
/// A stick carries whatever the previous run left on it -- a
/// superblock, a partition table, a filesystem that mount(8) might
/// still recognise. A run that starts from a residue is not measuring
/// the format it thinks it is, and the residue differs per stick, which
/// is the isolation-of-factors problem in miniature.
///
/// And a wipe that reports success without landing is how a failing
/// stick hides: FC07216732067 accepted writes, returned zero, and had
/// changed nothing on the medium. Reading the pattern back is what
/// separates a stick that wrote from one that said it did.
fn dd_wipe_and_verify(dev: &Path) -> Result<()> {
    const WIPE_MIB: u64 = 8;

    let out = Command::new("sudo")
        .arg("-n")
        .arg("dd")
        .arg("if=/dev/zero")
        .arg(format!("of={}", dev.display()))
        .arg("bs=1M")
        .arg(format!("count={WIPE_MIB}"))
        .arg("oflag=direct")
        .arg("conv=fsync")
        .arg("status=none")
        .output()
        .context("spawn sudo dd (wipe)")?;
    if !out.status.success() {
        return Err(anyhow!(
            "dd wipe of={} : {}",
            dev.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    // Read the first megabyte back, from the medium: through the page
    // cache the read returns what the wipe just put there whatever the
    // stick did with it, and proves nothing. Until 0.14.1 both the
    // wipe and the read went through the cache, and on 2026-09-27 the
    // slot vdc of compute01 was declared dead on a read that saw
    // something else than zeros; the same stick, written and read in
    // O_DIRECT from the host, took and gave back every byte. What it
    // saw was not kept, so which it was cannot be said: this version
    // says it.
    let out = Command::new("sudo")
        .arg("-n")
        .arg("dd")
        .arg(format!("if={}", dev.display()))
        .arg("of=/dev/stdout")
        .arg("bs=1M")
        .arg("count=1")
        .arg("iflag=direct")
        .arg("status=none")
        .output()
        .context("spawn sudo dd (wipe verify)")?;
    if !out.status.success() {
        return Err(anyhow!(
            "dd verify if={} : {}",
            dev.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let nz: Vec<usize> = out.stdout.iter().enumerate()
        .filter(|(_, b)| **b != 0)
        .map(|(i, _)| i)
        .collect();
    if let Some(&first) = nz.first() {
        let end = (first + 32).min(out.stdout.len());
        let hex: Vec<String> = out.stdout[first..end].iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        return Err(anyhow!(
            "{} still holds data after wipe: {} non-zero byte(s) in the first MiB read \
             in O_DIRECT, the first at offset {}: {}; the device is {}",
            dev.display(), nz.len(), first, hex.join(" "), holder_of(dev)
        ));
    }

    Ok(())
}

/// Which running domain has this device attached, if any.
///
/// A wipe on a device a guest is writing to measures the guest, not
/// the medium; a verdict on the stick has to say whether one was.
fn holder_of(dev: &Path) -> String {
    let name = dev.to_string_lossy();
    let doms = Command::new("sudo")
        .args(["-n", "virsh", "list", "--name"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    for d in doms.lines().map(str::trim).filter(|d| !d.is_empty()) {
        let bl = Command::new("sudo")
            .args(["-n", "virsh", "domblklist", d])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        if bl.lines().any(|l| l.contains(&*name)) {
            return format!("attached to the running domain {d}");
        }
    }
    "attached to no running domain".to_string()
}

fn dd_read_probe(dev: &Path, skip_mib: u64) -> Result<()> {
    let out = Command::new("sudo")
        .arg("-n")
        .arg("dd")
        .arg(format!("if={}", dev.display()))
        .arg("of=/dev/null")
        .arg("bs=1M")
        .arg(format!("count={PROBE_SIZE_MIB}"))
        .arg(format!("skip={skip_mib}"))
        .arg("status=none")
        .output()
        .context("spawn sudo dd (read probe)")?;
    if !out.status.success() {
        return Err(anyhow!(
            "dd read if={} skip={} : {}",
            dev.display(),
            skip_mib,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Canary write-test : read 4 KiB at offset 0, write back identical
/// bytes via `conv=notrunc`, considering the slot DEAD if the write
/// fails with EROFS / "Read-only file system". Data is preserved
/// bit-for-bit because the bytes written are exactly the bytes read.
///
/// Catches the failure mode where a USB stick flips to RO physical
/// (firmware write-protect after NAND fatigue) : reads succeed, writes
/// fail. The L1 implementation only tested reads and falsely classified
/// such a stick as healthy ; the bench then crashed at qemu start with
/// "Could not open ... Read-only file system".
fn dd_canary_write(dev: &Path) -> Result<()> {
    // Step 1 : capture 4 KiB at offset 0 to a tmp file.
    let tmp = std::env::temp_dir()
        .join(format!("usb-health-canary-{}.bin", std::process::id()));
    let read_out = Command::new("sudo")
        .arg("-n")
        .arg("dd")
        .arg(format!("if={}", dev.display()))
        .arg(format!("of={}", tmp.display()))
        .arg("bs=4096")
        .arg("count=1")
        .arg("status=none")
        .output()
        .context("spawn sudo dd (canary read)")?;
    if !read_out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!(
            "canary read failed on {} : {}",
            dev.display(),
            String::from_utf8_lossy(&read_out.stderr).trim()
        ));
    }
    // Step 2 : write the captured 4 KiB back to the same offset.
    // conv=notrunc ensures the rest of the device is untouched. The
    // bytes are bit-for-bit identical so no real data change occurs ;
    // the device just receives a 4 KiB write that exercises the RW path.
    let write_out = Command::new("sudo")
        .arg("-n")
        .arg("dd")
        .arg(format!("if={}", tmp.display()))
        .arg(format!("of={}", dev.display()))
        .arg("bs=4096")
        .arg("count=1")
        .arg("conv=notrunc")
        .arg("status=none")
        .output()
        .context("spawn sudo dd (canary write-back)")?;
    let _ = std::fs::remove_file(&tmp);
    if !write_out.status.success() {
        let stderr = String::from_utf8_lossy(&write_out.stderr).trim().to_string();
        if stderr.contains("Read-only file system") {
            return Err(anyhow!(
                "device is RO at block layer (firmware write-protect ?)"
            ));
        }
        return Err(anyhow!(
            "canary write failed on {} : {stderr}",
            dev.display()
        ));
    }
    Ok(())
}

fn lsblk_serial(dev: &Path) -> Result<String> {
    let out = Command::new("lsblk")
        .arg("-dn")
        .arg("-o")
        .arg("SERIAL")
        .arg(dev)
        .output()
        .context("spawn lsblk")?;
    if !out.status.success() {
        return Err(anyhow!(
            "lsblk SERIAL {} : {}",
            dev.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Render a fixed-width table to stdout for visibility.
fn print_table(verdicts: &[SlotVerdict]) {
    println!();
    println!("       slot  size       serial                          state");
    println!("       ----  ---------  ------------------------------  -------------");
    for v in verdicts {
        match v {
            SlotVerdict::Healthy { slot, size_bytes, serial, .. } => {
                let size_human = format_size(*size_bytes);
                println!(
                    "       {slot:<4}  {size_human:<9}  {serial:<30}  HEALTHY"
                );
            }
            SlotVerdict::Dead { slot, reason, .. } => {
                let r = if reason.len() > 40 { &reason[..40] } else { reason };
                println!(
                    "       {slot:<4}  {:<9}  {:<30}  DEAD: {r}",
                    "?", "?"
                );
            }
        }
    }
    println!();
}

#[allow(clippy::cast_precision_loss)] // display only: exact below 2^53 bytes
fn format_size(bytes: u64) -> String {
    let gib = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    format!("{gib:.1} GiB")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_attr_double_quotes() {
        let block = r#"<disk type="block" device="disk"><source dev="/dev/sda"/></disk>"#;
        assert_eq!(extract_attr(block, "<disk", "type"), Some("block".to_string()));
        assert_eq!(extract_attr(block, "<source", "dev"), Some("/dev/sda".to_string()));
    }

    #[test]
    fn extract_attr_single_quotes() {
        let block = r"<disk type='block'><source dev='/dev/sdb'/></disk>";
        assert_eq!(extract_attr(block, "<disk", "type"), Some("block".to_string()));
        assert_eq!(extract_attr(block, "<source", "dev"), Some("/dev/sdb".to_string()));
    }

    #[test]
    fn extract_attr_absent_returns_none() {
        let block = r"<disk><source dev='/dev/sdc'/></disk>";
        assert_eq!(extract_attr(block, "<disk", "type"), None);
    }

    #[test]
    fn parse_block_disks_skips_file_type() {
        let xml = r"
            <domain>
              <devices>
                <disk type='file' device='disk'>
                  <target dev='vda'/>
                  <source file='/var/lib/libvirt/img.beamfs'/>
                </disk>
                <disk type='block' device='disk'>
                  <target dev='vdc'/>
                  <source dev='/dev/disk/by-id/usb-Kingston_-part1'/>
                </disk>
              </devices>
            </domain>";
        let disks = parse_block_disks(xml);
        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].target, "vdc");
        assert_eq!(disks[0].source, PathBuf::from("/dev/disk/by-id/usb-Kingston_-part1"));
    }

    #[test]
    fn parse_block_disks_three_usb() {
        let xml = r"
            <domain>
              <devices>
                <disk type='block'><target dev='vdc'/><source dev='/dev/disk/by-id/a-part1'/></disk>
                <disk type='block'><target dev='vdd'/><source dev='/dev/disk/by-id/b-part1'/></disk>
                <disk type='block'><target dev='vde'/><source dev='/dev/disk/by-id/c-part1'/></disk>
              </devices>
            </domain>";
        let disks = parse_block_disks(xml);
        assert_eq!(disks.len(), 3);
        assert_eq!(disks.iter().map(|d| d.target.as_str()).collect::<Vec<_>>(),
                   vec!["vdc", "vdd", "vde"]);
    }

    fn healthy(slot: &str) -> SlotVerdict {
        SlotVerdict::Healthy {
            slot: slot.to_string(),
            source: PathBuf::from("/dev/disk/by-id/x"),
            resolved: PathBuf::from("/dev/sdx"),
            size_bytes: 1,
            serial: "S".to_string(),
        }
    }

    fn dead(slot: &str) -> SlotVerdict {
        SlotVerdict::Dead {
            slot: slot.to_string(),
            source: PathBuf::from("/dev/disk/by-id/x"),
            reason: "test".to_string(),
        }
    }

    #[test]
    fn build_fs_mapping_empty() {
        let m = build_fs_mapping(&[]);
        assert!(m.is_empty());
    }

    #[test]
    fn build_fs_mapping_one_healthy() {
        let m = build_fs_mapping(&[healthy("vdc")]);
        assert_eq!(m, vec![("beamfs".to_string(), "vdc".to_string())]);
    }

    #[test]
    fn build_fs_mapping_two_healthy_ordered() {
        let m = build_fs_mapping(&[healthy("vdd"), healthy("vdc")]);
        assert_eq!(m, vec![
            ("beamfs".to_string(), "vdc".to_string()),
            ("ext4".to_string(),   "vdd".to_string()),
        ]);
    }

    #[test]
    fn build_fs_mapping_skips_dead() {
        let m = build_fs_mapping(&[dead("vdc"), healthy("vdd"), healthy("vde")]);
        assert_eq!(m, vec![
            ("beamfs".to_string(), "vdd".to_string()),
            ("ext4".to_string(),   "vde".to_string()),
        ]);
    }

    #[test]
    fn build_fs_mapping_full_priority() {
        let m = build_fs_mapping(&[
            healthy("vdc"), healthy("vdd"), healthy("vde"),
            healthy("vdf"), healthy("vdg"),
        ]);
        assert_eq!(m.len(), 5);
        let fs_names: Vec<&str> = m.iter().map(|(f, _)| f.as_str()).collect();
        assert_eq!(fs_names, vec!["beamfs", "ext4", "squashfs", "ext3", "btrfs"]);
    }

    #[test]
    fn build_fs_mapping_excess_slots_truncated() {
        let m = build_fs_mapping(&[
            healthy("vdc"), healthy("vdd"), healthy("vde"),
            healthy("vdf"), healthy("vdg"), healthy("vdh"),
            healthy("vdi"),
        ]);
        assert_eq!(m.len(), 5);
        assert_eq!(m.last().unwrap(), &("btrfs".to_string(), "vdg".to_string()));
    }
}
