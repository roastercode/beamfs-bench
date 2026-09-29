// SPDX-License-Identifier: GPL-2.0-only
//
// Author: Aurelien Desbrieres <aurelien@hackers.camp>

//! scrub.rs - Test G: does the scrubber keep up, and does it repair?
//!
//! ## Role
//!
//! Every other scenario measures what the filesystem does when a file is
//! read. This one measures what it does when nobody is reading.
//!
//! That gap matters because the scrubber is the only mechanism that acts
//! on data nobody has touched, and a volume in a linac vault spends most
//! of its life untouched while the flux keeps arriving. Corrections that
//! only happen on read are corrections that never happen for cold data,
//! and cold data is most of it.
//!
//! Two questions, neither of which the harness could previously ask:
//!
//!   1. Does a repair survive? A scrubber that decodes in memory and
//!      discards the result leaves the block damaged, so the next upset
//!      adds to the first rather than replacing it. Eight correctable
//!      symbols reached one at a time is a block lost to eight events
//!      that were individually harmless. This was real: measured at 120
//!      corrections of one block across 119 sweeps, none of them
//!      persisted, before it was fixed.
//!
//!   2. Does the sweep rate follow the flux? The interval halves on any
//!      correction and drifts back when sweeps come up clean. Under a
//!      dose the rate should rise and stay up; after it, it should
//!      settle. A rate that does not move under load is a rate that is
//!      not being asked to.
//!
//! ## Method
//!
//! The volume is filled, a known number of symbols are corrupted offline
//! -- derived from the deployment's exposure, not chosen -- and then the
//! observer waits without reading anything. Only the scrubber can act.
//!
//! Sampling is by sweep, not by wall clock: a sweep is the scrubber's own
//! unit of work, and comparing counts between two different sweeps of the
//! same volume is the only comparison that means anything under emulation
//! where wall-clock rates vary with host load.
//!
//! What counts as a repair is the block on the medium. It is read raw,
//! volume unmounted and in `O_DIRECT`, before the injection, after it, and
//! after the sweeps; a repair is the third reading equal to the first.
//! The digest of the file at the end goes through a read, and a read
//! corrects in memory whatever the scrubber did or did not write: it says
//! the data can be read, not that the scrubber repaired it. Until 0.14.4
//! it was all this scenario said about the data.
//!
//! ## Where
//!
//! compute01 by default. `--node` and `--device` run it on another node:
//! the scrubber is the same code on both architectures, but it is built
//! and run on each, and x86-01 is where the x86-64 chain is measured.
//! Reaching that node takes the key and account beamfs-xfstests uses,
//! given through `BEAMFS_BENCH_SSH_KEY` and `BEAMFS_BENCH_SSH_USER`.
//!
//! As everywhere in this harness: observations are recorded, judgment is
//! left to synthesis.

use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::dose::Deployment;
use crate::ssh::SshTarget;

/// One reading of the scrubber's own counters.
///
/// Taken from sysfs rather than dmesg: dmesg is rate-limited and reports
/// events, sysfs reports state, and state is what a control loop has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScrubSample {
    pub seconds: u64,
    pub passes: u64,
    pub blocks: u64,
    pub corrected: u64,
    pub uncorrectable: u64,
    pub interval_ms: u64,
    pub base_ms: u64,
    pub wear_visits: u64,
}

impl ScrubSample {
    /// How much faster than the operator's setting the sweep is running.
    ///
    /// 1 means at rest. Higher means the loop has seen corrections
    /// recently and has not yet drifted back.
    #[must_use]
    pub fn factor(&self) -> u64 {
        if self.interval_ms > 0 && self.base_ms > self.interval_ms {
            self.base_ms / self.interval_ms
        } else {
            1
        }
    }

    fn parse(text: &str, seconds: u64) -> Self {
        let mut s = Self { seconds, ..Default::default() };
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let (Some(k), Some(v)) = (it.next(), it.next()) else { continue };
            let n: u64 = v.parse().unwrap_or(0);
            match k {
                "passes" => s.passes = n,
                "blocks" => s.blocks = n,
                "corrected" => s.corrected = n,
                "uncorrectable" => s.uncorrectable = n,
                "interval_ms" => s.interval_ms = n,
                "base_ms" => s.base_ms = n,
                "wear_visits" => s.wear_visits = n,
                _ => {}
            }
        }
        s
    }
}

/// What the run observed. No verdict: that belongs to synthesis.
#[derive(Debug, Clone)]
pub struct ScrubObservation {
    pub deployment: Deployment,
    /// The node and device the observation was made on.
    pub node: String,
    pub symbols_injected: u32,
    /// Bytes of the damaged block that differ from the clean one, read
    /// from the medium: what the injection actually changed.
    pub injected_bytes: u64,
    /// Bytes still different from the clean block on the medium after
    /// the sweeps, or `None` when the block could not be read back.
    pub left_bytes: Option<u64>,
    pub samples: Vec<ScrubSample>,
    /// Data digest before injection and at the end.
    pub digest_before: String,
    pub digest_after: String,
}

impl ScrubObservation {
    /// Corrections attributed to each block that needed one.
    ///
    /// The number that exposed the missing writeback. With repair
    /// persisted it converges on the count of damaged blocks; without,
    /// it grows without bound because the same block is found every
    /// sweep. Reported as a ratio so the shape is visible whatever the
    /// injection size.
    #[must_use]
    pub fn corrections_per_sweep(&self) -> f64 {
        let (Some(first), Some(last)) = (self.samples.first(), self.samples.last())
        else {
            return 0.0;
        };
        let sweeps = last.passes.saturating_sub(first.passes);
        if sweeps == 0 {
            return 0.0;
        }
        (last.corrected.saturating_sub(first.corrected)) as f64 / sweeps as f64
    }

    /// The highest rate the loop reached.
    #[must_use]
    pub fn peak_factor(&self) -> u64 {
        self.samples.iter().map(ScrubSample::factor).max().unwrap_or(1)
    }

    /// The rate at the end.
    #[must_use]
    pub fn final_factor(&self) -> u64 {
        self.samples.last().map_or(1, ScrubSample::factor)
    }

    /// Did the data come back to what it was, as a read sees it?
    ///
    /// A read corrects in memory: this is true whether or not the
    /// scrubber repaired anything on the medium.
    #[must_use]
    pub fn data_intact(&self) -> bool {
        !self.digest_before.is_empty() && self.digest_before == self.digest_after
    }

    /// Is the damaged block, on the medium, the clean block again?
    ///
    /// Only the scrubber can have written it: nothing reads the file
    /// between the injection and the last raw reading.
    #[must_use]
    pub fn repaired_on_medium(&self) -> bool {
        self.injected_bytes > 0 && self.left_bytes == Some(0)
    }

    /// The observation record, in the harness's usual form.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("# Test G -- scrubber under dose\n\n");
        s.push_str(&format!("- deployment: {}\n", self.deployment.as_str()));
        s.push_str(&format!("- node: {}\n", self.node));
        s.push_str(&format!("- symbols injected: {}\n", self.symbols_injected));
        s.push_str(&format!("- samples: {}\n\n", self.samples.len()));

        s.push_str("| sweep | s | blocks | corrected | uncorr | interval | factor | wear |\n");
        s.push_str("|---|---|---|---|---|---|---|---|\n");
        for x in &self.samples {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                x.passes, x.seconds, x.blocks, x.corrected,
                x.uncorrectable, x.interval_ms, x.factor(), x.wear_visits
            ));
        }

        s.push_str("\n## Observations\n\n");
        s.push_str(&format!("- corrections per sweep: {:.2}\n",
                            self.corrections_per_sweep()));
        s.push_str(&format!("- peak rate factor: {}\n", self.peak_factor()));
        s.push_str(&format!("- final rate factor: {}\n", self.final_factor()));
        s.push_str(&format!("- digest before: {}\n", self.digest_before));
        s.push_str(&format!("- digest after:  {}\n", self.digest_after));
        s.push_str(&format!("- data identical: {}\n", self.data_intact()));
        s.push_str(&format!(
            "- block on the medium: {} byte(s) changed by the injection, {} still different after the sweeps\n",
            self.injected_bytes,
            self.left_bytes.map_or_else(|| "unreadable".to_string(), |n| n.to_string())
        ));
        s.push_str(&format!("- repaired on the medium: {}\n", self.repaired_on_medium()));

        s.push_str("\n## Reading these numbers\n\n");
        s.push_str(
            "Corrections per sweep near the count of damaged blocks means each\n\
             was repaired once. A figure that stays near the damaged-block count\n\
             sweep after sweep means repairs are not reaching the disk: the same\n\
             blocks are being found again, and their margin is being consumed\n\
             rather than restored.\n\n\
             A peak factor above 1 means the rate responded to what was found. A\n\
             final factor of 1 means it settled once there was nothing left to\n\
             find. Peak 1 under a non-zero injection means the loop did not\n\
             engage, which is a defect in the loop rather than in the volume.\n\n\
             Repaired on the medium is the damaged block read back raw, volume\n\
             unmounted, equal to the clean one: the scrubber wrote its repair and\n\
             it reached the disk. Data identical goes through a read, which\n\
             corrects in memory, and holds with or without a repair.\n\n\
             Whether these values are acceptable for a given deployment is a\n\
             question for synthesis, not for this file.\n",
        );
        s
    }
}

/// The node this scenario runs on.
///
/// One node, not the cluster: the scrubber is per-mount, and observing
/// four of them at once would measure the host's scheduler as much as
/// the filesystem.
fn lab_target(node: &str) -> SshTarget {
    let key = crate::lab::ssh_key().to_string();
    SshTarget::new(crate::lab::ssh_user(), node, &key)
}

/// Entry point for the `scrub` subcommand.
pub fn run_cli(deployment: &str, sweeps: u64, node: &str, device: &str) -> Result<i32> {
    let dep = Deployment::parse(deployment)
        .with_context(|| format!("unknown deployment {deployment}"))?;
    let ssh = lab_target(node);

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let run_dir = std::path::PathBuf::from(format!("beamfs-bench-scrub-{stamp}"));
    std::fs::create_dir_all(&run_dir).context("create scrub run dir")?;
    println!("Run dir: {}", run_dir.display());

    let cfg = ScrubConfig {
        ssh: &ssh,
        node: node.to_string(),
        device: device.to_string(),
        mount: "/mnt/k".into(),
        deployment: dep,
        sweeps,
        run_dir: &run_dir,
    };

    let obs = run(&cfg)?;
    println!();
    println!("  node              {} /dev/{device}", obs.node);
    println!("  deployment        {}", obs.deployment.as_str());
    println!("  symbols injected  {}", obs.symbols_injected);
    println!("  sweeps observed   {}", obs.samples.len());
    println!("  corr/sweep        {:.2}", obs.corrections_per_sweep());
    println!("  peak factor       {}", obs.peak_factor());
    println!("  final factor      {}", obs.final_factor());
    println!("  data identical    {}  (through a read, which corrects in memory)", obs.data_intact());
    println!("  injected bytes    {}  (on the medium)", obs.injected_bytes);
    println!(
        "  left on medium    {}",
        obs.left_bytes.map_or_else(|| "unreadable".to_string(), |n| n.to_string())
    );
    println!("  repaired on disk  {}", obs.repaired_on_medium());
    println!();
    println!("  record: {}", run_dir.join("test-g-scrub.md").display());

    // The bench reports; it does not judge. A non-zero exit is for the
    // scenario failing to run, not for the filesystem behaving badly.
    Ok(0)
}

/// Configuration for one observation.
pub struct ScrubConfig<'a> {
    pub ssh: &'a SshTarget,
    pub node: String,
    pub device: String,
    pub mount: String,
    pub deployment: Deployment,
    /// Sweeps to observe after injection.
    pub sweeps: u64,
    pub run_dir: &'a Path,
}

/// Fill the volume, damage it by a known amount, then watch without reading.
pub fn run(cfg: &ScrubConfig) -> Result<ScrubObservation> {
    let s = cfg.ssh;
    let dev = &cfg.device;
    let mnt = &cfg.mount;

    // Symbols to corrupt, from the deployment rather than a round number.
    // Bounded to what a single block can carry: past the correctable
    // limit the observation is about failure, not about scrubbing.
    let symbols = symbols_for(cfg.deployment);

    s.exec_lenient(&format!("sudo umount {mnt} 2>/dev/null; sudo mkdir -p {mnt}"))?;
    s.exec(&format!("sudo mkfs.beamfs --error-budget -N 256 /dev/{dev}"))
        .context("mkfs")?;
    s.exec(&format!("sudo mount -t beamfs /dev/{dev} {mnt}")).context("mount")?;
    s.exec(&format!(
        "sudo dd if=/dev/urandom of={mnt}/probe bs=4096 count=64 2>/dev/null; sudo sync"
    ))?;

    let digest_before = s
        .exec(&format!("sudo md5sum {mnt}/probe | cut -d' ' -f1"))?
        .trim()
        .to_string();

    // Where the file starts, so the injection lands on data rather than
    // on whatever happens to be at a guessed offset.
    let phys: u64 = s
        .exec(&format!(
            "sudo filefrag -v -b4096 {mnt}/probe | awk '/^ +0:/ {{gsub(/[.:]/,\"\",$4); print $4}}'"
        ))?
        .trim()
        .parse()
        .context("physical block of probe file")?;

    // Offline: the scrubber must be the only thing that repairs this.
    s.exec(&format!("sudo umount {mnt}"))?;

    // The block as the medium holds it, clean, then damaged: raw, the
    // volume unmounted, in O_DIRECT so that the page cache answers for
    // nothing.
    let raw = |tag: &str| {
        format!(
            "sudo dd if=/dev/{dev} of=/tmp/testg-{dev}-{tag}.blk bs=4096 skip={phys} \
             count=1 iflag=direct status=none"
        )
    };
    s.exec(&raw("clean")).context("raw read of the clean block")?;
    for k in 0..symbols {
        let off = phys * 4096 + u64::from(k) * 7;
        s.exec(&format!(
            "printf '\\xFF' | sudo dd of=/dev/{dev} bs=1 seek={off} count=1 conv=notrunc 2>/dev/null"
        ))?;
    }
    s.exec("sudo sync")?;
    s.exec(&raw("damaged")).context("raw read of the damaged block")?;
    let injected_bytes = differing_bytes(s, dev, "damaged")?;
    s.exec(&format!("sudo mount -t beamfs /dev/{dev} {mnt}"))?;

    // Watch. Nothing here reads the file: only the scrubber can act.
    let started = Instant::now();
    let mut samples = Vec::new();
    let mut last_pass = u64::MAX;

    while samples.len() < 64 {
        let secs = started.elapsed().as_secs();
        let raw = s.exec_lenient(&format!(
            "for f in passes blocks corrected uncorrectable; do \
               echo \"$f $(sudo cat /sys/fs/beamfs/{dev}/$f 2>/dev/null)\"; done; \
             sudo cat /sys/fs/beamfs/{dev}/scrub_pace 2>/dev/null"
        ))?;
        let sample = ScrubSample::parse(&raw, secs);

        // One sample per sweep: the scrubber's unit, not the clock's.
        if sample.passes != last_pass {
            last_pass = sample.passes;
            let done = sample.passes;
            samples.push(sample);
            if done >= cfg.sweeps {
                break;
            }
        }
        sleep(Duration::from_secs(3));
        if started.elapsed() > Duration::from_secs(900) {
            break;
        }
    }

    // The medium first, before anything reads the file: a read corrects
    // in memory, and what it returns says nothing about what the
    // scrubber wrote.
    s.exec("sudo sync")?;
    s.exec(&format!("sudo umount {mnt}"))?;
    let left_bytes = s
        .exec(&raw("after"))
        .and_then(|_| differing_bytes(s, dev, "after"))
        .ok();
    s.exec(&format!("sudo mount -t beamfs /dev/{dev} {mnt}")).context("remount")?;
    let digest_after = s
        .exec_lenient(&format!("sudo md5sum {mnt}/probe | cut -d' ' -f1"))?
        .trim()
        .to_string();
    s.exec_lenient(&format!("sudo umount -l {mnt} 2>/dev/null; true"))?;

    let obs = ScrubObservation {
        deployment: cfg.deployment,
        node: cfg.node.clone(),
        symbols_injected: symbols,
        injected_bytes,
        left_bytes,
        samples,
        digest_before,
        digest_after,
    };

    let out = cfg.run_dir.join("test-g-scrub.md");
    std::fs::write(&out, obs.to_markdown())
        .with_context(|| format!("writing {}", out.display()))?;

    Ok(obs)
}

/// Bytes of a raw reading that differ from the clean one.
fn differing_bytes(s: &SshTarget, dev: &str, tag: &str) -> Result<u64> {
    let out = s.exec(&format!(
        "sudo cmp -l /tmp/testg-{dev}-clean.blk /tmp/testg-{dev}-{tag}.blk | wc -l"
    ))?;
    out.trim().parse().context("count of differing bytes")
}

/// Symbols to inject for a deployment.
///
/// Scaled by the same neutron factor the rest of the harness uses, and
/// capped below the correctable limit: this scenario is about whether
/// repairs happen and persist, and an uncorrectable block answers a
/// different question.
fn symbols_for(d: Deployment) -> u32 {
    let f = d.neutron_factor();
    let n = if f >= 1.0e5 {
        6
    } else if f >= 100.0 {
        3
    } else {
        1
    };
    n.min(7)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factor_is_one_at_rest() {
        let s = ScrubSample { interval_ms: 100, base_ms: 100, ..Default::default() };
        assert_eq!(s.factor(), 1);
    }

    #[test]
    fn factor_reports_the_speedup() {
        let s = ScrubSample { interval_ms: 25, base_ms: 100, ..Default::default() };
        assert_eq!(s.factor(), 4);
    }

    #[test]
    fn parsing_takes_what_it_recognises() {
        let raw = "passes 7\nblocks 900\ncorrected 3\ninterval_ms 50\nbase_ms 100\nwear_visits 12\n";
        let s = ScrubSample::parse(raw, 42);
        assert_eq!(s.passes, 7);
        assert_eq!(s.corrected, 3);
        assert_eq!(s.wear_visits, 12);
        assert_eq!(s.factor(), 2);
        assert_eq!(s.seconds, 42);
    }

    #[test]
    fn repairs_that_persist_converge() {
        // One damaged block, repaired once: corrections stop climbing.
        let obs = ScrubObservation {
            deployment: Deployment::MedicalLinacVault,
            node: "192.168.56.11".into(),
            symbols_injected: 6,
            injected_bytes: 6,
            left_bytes: Some(0),
            samples: vec![
                ScrubSample { passes: 1, corrected: 1, interval_ms: 50, base_ms: 100,
                              ..Default::default() },
                ScrubSample { passes: 9, corrected: 1, interval_ms: 100, base_ms: 100,
                              ..Default::default() },
            ],
            digest_before: "abc".into(),
            digest_after: "abc".into(),
        };
        assert_eq!(obs.corrections_per_sweep(), 0.0);
        assert_eq!(obs.peak_factor(), 2);
        assert_eq!(obs.final_factor(), 1);
        assert!(obs.data_intact());
        assert!(obs.repaired_on_medium());
    }

    #[test]
    fn repairs_that_do_not_persist_keep_climbing() {
        // The shape the defect produced: one correction every sweep,
        // forever, and the rate pinned because it never comes clean.
        let obs = ScrubObservation {
            deployment: Deployment::MedicalLinacVault,
            node: "192.168.56.11".into(),
            symbols_injected: 6,
            injected_bytes: 6,
            left_bytes: Some(6),
            samples: vec![
                ScrubSample { passes: 1, corrected: 1, interval_ms: 50, base_ms: 100,
                              ..Default::default() },
                ScrubSample { passes: 101, corrected: 101, interval_ms: 1, base_ms: 100,
                              ..Default::default() },
            ],
            digest_before: "abc".into(),
            digest_after: "abc".into(),
        };
        assert_eq!(obs.corrections_per_sweep(), 1.0);
        assert_eq!(obs.peak_factor(), 100);
        // The shape 0.14.3 could not tell apart: the read gives the
        // data back, the medium still holds the damage.
        assert!(obs.data_intact());
        assert!(!obs.repaired_on_medium());
    }

    #[test]
    fn nothing_injected_is_not_a_repair() {
        let obs = ScrubObservation {
            deployment: Deployment::Terrestrial,
            node: "192.168.122.99".into(),
            symbols_injected: 1,
            injected_bytes: 0,
            left_bytes: Some(0),
            samples: Vec::new(),
            digest_before: "abc".into(),
            digest_after: "abc".into(),
        };
        assert!(!obs.repaired_on_medium());
    }

    #[test]
    fn injection_follows_the_deployment() {
        assert!(symbols_for(Deployment::MedicalLinacVault)
                > symbols_for(Deployment::Terrestrial));
        assert!(symbols_for(Deployment::MedicalLinacVault) < 8);
    }
}
