// SPDX-License-Identifier: GPL-2.0-only
//
// beamfs-bench -- performance characterisation
//
// Author: Aurelien Desbrieres <aurelien@hackers.camp>

//! Measure what the filesystem costs, on each operation, in two
//! regimes.
//!
//! A filesystem that adds forward error correction is slower. The
//! question is by how much, on which operation, and how predictably --
//! so each dimension is measured on its own rather than through one
//! aggregate figure, and percentiles are recorded rather than means.
//! beamfs trades median latency for a tighter distribution: v2 measured
//! a 1.74x p50/p99 spread against 5.00x for ext4, which a mean hides.
//!
//! Two regimes, because the format's cost and the correction's cost are
//! different questions:
//!
//! - `nominal`: no injection. What the on-disk layout costs.
//! - `correcting`: injector armed throughout. What the filesystem costs
//!   while doing the work it exists for.
//!
//! The gap between them is what resilience actually costs, and it is
//! the figure that sizes a deployment -- a system under radiation keeps
//! serving while upsets arrive. It came out of an accident on
//! 2026-08-30, when a perf run overlapped an injection run and system
//! CPU reached 94-97% on reads against a far lower nominal load. That
//! number would not have appeared in a nominal-only campaign.

use anyhow::{Context, Result};
use std::collections::BTreeMap;

use crate::ssh::SshTarget;

/// One measured operation.
#[derive(Debug, Clone, Default)]
pub struct PerfRow {
    pub fs: String,
    pub regime: String,
    pub op: String,
    pub bw_bytes: u64,
    pub iops: f64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub usr_cpu: f64,
    pub sys_cpu: f64,
    pub logical_bytes: u64,
    pub device_bytes: u64,
}

impl PerfRow {
    /// Parse one `PERF|...` line emitted by the worker.
    ///
    /// Unknown keys are ignored rather than rejected: the worker and
    /// the orchestrator are versioned separately, and a run should not
    /// fail because one side learned a new field first.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if !line.starts_with("PERF|") {
            return None;
        }
        let mut kv: BTreeMap<&str, &str> = BTreeMap::new();
        for tok in line.trim_start_matches("PERF|").split('|') {
            if let Some((k, v)) = tok.split_once('=') {
                kv.insert(k, v);
            }
        }
        let num = |k: &str| -> u64 { kv.get(k).and_then(|v| v.parse().ok()).unwrap_or(0) };
        let flt = |k: &str| -> f64 { kv.get(k).and_then(|v| v.parse().ok()).unwrap_or(0.0) };

        Some(Self {
            fs: (*kv.get("FS")?).to_string(),
            regime: (*kv.get("REGIME").unwrap_or(&"nominal")).to_string(),
            op: (*kv.get("OP")?).to_string(),
            bw_bytes: num("BW_BYTES"),
            iops: flt("IOPS"),
            p50_ns: num("P50_NS"),
            p95_ns: num("P95_NS"),
            p99_ns: num("P99_NS"),
            p999_ns: num("P999_NS"),
            usr_cpu: flt("USR_CPU"),
            sys_cpu: flt("SYS_CPU"),
            logical_bytes: num("LOGICAL_BYTES"),
            device_bytes: num("DEVICE_BYTES"),
        })
    }

    /// Write amplification: device bytes per logical byte.
    ///
    /// INLINE stores 3824 logical bytes in a 4096-byte block, so 1.07
    /// is structural. Anything above that is read-modify-write on
    /// partial writes.
    #[must_use]
    pub fn amplification(&self) -> Option<f64> {
        if self.op != "amplification" || self.logical_bytes == 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        Some(self.device_bytes as f64 / self.logical_bytes as f64)
    }

    /// p99 over p50. A filesystem can be slower on the median and still
    /// be the better choice under a deadline if its tail is tighter.
    #[must_use]
    pub fn spread(&self) -> Option<f64> {
        if self.p50_ns == 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        Some(self.p99_ns as f64 / self.p50_ns as f64)
    }
}

/// Run the perf action for one filesystem in one regime.
pub fn measure_one(
    ssh: &SshTarget,
    injector: &str,
    fs: &str,
    guest_dev: &str,
    regime: &str,
    prob: u32,
) -> Result<Vec<PerfRow>> {
    std::env::set_var("PERF_REGIME", regime);
    if regime == "correcting" {
        std::env::set_var("PROB", prob.to_string());
    } else {
        std::env::remove_var("PROB");
    }
    let cmd = crate::cluster::worker_cmd(injector, &format!("perf {fs} {guest_dev}"));
    let out = ssh
        .exec_lenient(&cmd)
        .with_context(|| format!("perf {fs} regime={regime}"))?;
    Ok(out.lines().filter_map(PerfRow::parse).collect())
}

/// Configuration for a performance campaign.
pub struct PerfConfig {
    pub fs_list: Vec<(String, String)>,
    pub ssh_user: String,
    pub master_ip: String,
    pub ssh_key_path: String,
    pub injector: String,
    /// Injection probability in ppm, used in the correcting regime.
    pub prob: u32,
    /// Skip the nominal regime, or the correcting one, when only one
    /// side is wanted.
    pub regimes: Vec<String>,
}

/// Measure every filesystem in every regime.
///
/// Filesystems are already set up by the caller (the multifs setup
/// phase); this walks them and runs the perf action. Order matters:
/// nominal first, so a correcting run cannot leave the injector armed
/// under a measurement that is supposed to be clean.
pub fn run(cfg: &PerfConfig) -> Result<Vec<PerfRow>> {
    let ssh = SshTarget::new(&cfg.ssh_user, &cfg.master_ip, &cfg.ssh_key_path);
    let mut rows = Vec::new();

    for regime in &cfg.regimes {
        println!("[perf] regime = {regime}");
        for (fs, dev) in &cfg.fs_list {
            match measure_one(&ssh, &cfg.injector, fs, dev, regime, cfg.prob) {
                Ok(mut r) => {
                    for row in &r {
                        if row.op == "amplification" {
                            if let Some(a) = row.amplification() {
                                println!("  {fs:<8} amplification {a:.2}x");
                            }
                        } else {
                            #[allow(clippy::cast_precision_loss)]
                            let mb = row.bw_bytes as f64 / 1_048_576.0;
                            let spread = row.spread().unwrap_or(0.0);
                            println!(
                                "  {fs:<8} {:<11} {mb:>7.2} MB/s  p50 {:>9} ns  p99 {:>9} ns  spread {spread:.2}x  sys {:.0}%",
                                row.op, row.p50_ns, row.p99_ns, row.sys_cpu
                            );
                        }
                    }
                    rows.append(&mut r);
                }
                Err(e) => eprintln!("  {fs:<8} FAILED: {e:#}"),
            }
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_measurement_line() {
        let l = "PERF|FS=beamfs|REGIME=nominal|OP=randwrite|BW_BYTES=717763|IOPS=175.2|P50_NS=189440|P95_NS=346112|P99_NS=464896|P999_NS=757760|USR_CPU=0.58|SYS_CPU=48.09";
        let r = PerfRow::parse(l).expect("parses");
        assert_eq!(r.fs, "beamfs");
        assert_eq!(r.regime, "nominal");
        assert_eq!(r.op, "randwrite");
        assert_eq!(r.bw_bytes, 717_763);
        assert_eq!(r.p99_ns, 464_896);
    }

    #[test]
    fn regime_defaults_to_nominal() {
        let l = "PERF|FS=ext4|OP=seqread|BW_BYTES=1|IOPS=1|P50_NS=1|P95_NS=1|P99_NS=1|P999_NS=1|USR_CPU=0|SYS_CPU=0";
        assert_eq!(PerfRow::parse(l).expect("parses").regime, "nominal");
    }

    #[test]
    fn amplification_is_device_over_logical() {
        let l = "PERF|FS=beamfs|REGIME=nominal|OP=amplification|LOGICAL_BYTES=8388608|DEVICE_BYTES=17342464";
        let a = PerfRow::parse(l).expect("parses").amplification().expect("amp");
        assert!((a - 2.067).abs() < 0.01, "got {a}");
    }

    #[test]
    fn spread_is_p99_over_p50() {
        let l = "PERF|FS=beamfs|OP=randwrite|BW_BYTES=1|IOPS=1|P50_NS=100|P95_NS=200|P99_NS=250|P999_NS=300|USR_CPU=0|SYS_CPU=0";
        let s = PerfRow::parse(l).expect("parses").spread().expect("spread");
        assert!((s - 2.5).abs() < 0.001, "got {s}");
    }

    #[test]
    fn non_perf_lines_are_ignored() {
        assert!(PerfRow::parse("WORKER|HOST=x|OK=1").is_none());
    }
}
