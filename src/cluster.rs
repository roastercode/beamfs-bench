//! cluster.rs  -  multi-node orchestration for analyse --scope=full.
//!
//! ## Topology (per recadrage R13)
//!
//! The beamfs cluster is NOT master-only. Each compute node has its own
//! beamfs instance on /dev/vdb mounted on /data, with kernel 7.0.3 +
//! beamfs.ko + `reed_solomon.ko` + radfi.ko (loadable). Compute nodes are
//! first-class targets, not passive observers.
//!
//! This module provides:
//!
//!   - `ClusterNode`: one (ip, hostname) entry with discovered state
//!   - `discover_cluster()`: query all 4 nodes for /data state, modules,
//!     ftrace/perf availability
//!   - `render_cluster_table()`: present the topology to the user before
//!     any cluster-wide action
//!   - `cluster_setup_all()` / `cluster_attack_all()` / `cluster_verify_all()`:
//!     parallel execution across nodes via `std::thread` (one thread per node)
//!
//! No external async runtime needed: we spawn 1 OS thread per node and
//! join. Total = 4 threads, lifetime = duration of one ssh roundtrip.

use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use std::thread;

use crate::ssh::SshTarget;
use std::fmt::Write;

/// The 4 cluster nodes. IP/hostname mapping is fixed by the lab topology.
pub const CLUSTER_NODES: &[(&str, &str)] = &[
    ("192.168.56.10", "beamfs-master"),
    ("192.168.56.11", "beamfs-compute01"),
    ("192.168.56.12", "beamfs-compute02"),
    ("192.168.56.13", "beamfs-compute03"),
];

pub const REMOTE_WORKER_PATH: &str = "/tmp/beamfs-bench-worker.sh";

/// Build a worker.sh remote command with INJECTOR env var prefixed.
///
/// The `injector` argument is propagated to worker.sh via the SSH
/// `remote_cmd` environment, where it dispatches between radfi (legacy
/// SEU) and emufi (MBU-capable successor, ref Zenodo DOI
/// 10.5281/zenodo.20041762).
///
/// Pass "radfi" for the historical R19 baseline behavior; pass "emufi"
/// to exercise the MBU-capable injector with stratified counters and
/// Weibull width sampling. The default at the worker.sh level is
/// "radfi" if INJECTOR is unset, so calling this helper without
/// thinking still yields zero regression.
pub fn worker_cmd(injector: &str, action_args: &str) -> String {
    // v0.7.7 : forward attack-tuning env vars from host to remote worker.
    // worker.sh consumes these (sites at lines ~244 multifs and ~497
    // metadata cluster). Without this prefix, setting them at the host
    // shell has no effect because ssh resets the environment.
    let mut env_prefix = format!("INJECTOR={injector}");
    // v0.8.0: full emufi 0.3.2 debugfs surface. All optional, all
    // cumulative simultaneous. Each var is forwarded to worker.sh which
    // pushes it to the matching debugfs entry IFF the entry exists
    // (sudo test -e guard), so radfi (which lacks most of these)
    // silently ignores vars it does not know.
    for var in &[
        // v0.7.x baseline (kept verbatim):
        "FLIP_WIDTH",
        "MAX_FLIPS",                 // u64, injection budget (emufi 0.6.0+)
        "INJECT_SCOPE",              // "targeted" (default) or "uniform"
        "DEPLOYMENT",                // named environment; derives the event
                                     // count from flux and exposure time
        "EXPOSURE_HOURS",            // f64, hours of modelled exposure
        "EXPOSURE_BYTES",            // u64, medium under exposure
        "SIGMA_CM2_PER_BIT",         // f64, measured SEU cross-section
        "FIXED_DOSE",                // 1 = every filtered bio injected until
        "PHYSICS_DRIVEN",            // 1 = placement from the generated
                                     // campaign in /tmp/emufi-campaign.bin
                                     // the budget runs out (emufi 0.8.0+)
        "TARGET_RANGES",             // "s:e,s:e" sectors (emufi 0.7.0+)
        "LET_CLASS",
        "FLIP_LOCALITY",
        "BURST_SYMBOLS",
        "TARGET_STRUCT",
        "TARGET_STRUCT_BLOCK_NO",
        "SEFI_PROBABILITY",
        "SEFI_WINDOW_MS",
        // Phase A.5: SB-targeted I/O burst loop count for RS saturation
        "SB_READ_LOOPS",
        // v0.8.0 additions, expose remaining emufi 0.3.2 surface:
        "TARGET_STRUCT_OFFSET",      // u32, byte offset within struct block
        "TARGET_INODE",              // u64, inode-aware FS targeting
        "HOOK_FS",                   // bool 0/1, FS-level hook (vs blk-only)
        "MULTI_SEGMENT",             // bool 0/1, multi-segment burst
        "MULTI_CHIP",                // bool 0/1, multi-chip injection
        "CHIP_COUNT",                // u8, number of chips when multi_chip=1
        "WIDTH_MODE",                // u8, MBU width sampling mode
        "FLIP_STRIDE_BITS",          // u8, stride between flips in a burst
        "CODEWORD_SIZE_BYTES",       // u32, RS codeword size for FEC-aware
        "CODEWORD_ALIGN_BYTES",      // u32, RS codeword alignment
        "RESEED",                    // u64, reseed PRNG (write-only command)
        // Phase A.3 -- workload mode declaration:
        "WORKLOAD_MODE",             // string: "static" (default) or "write-active"
        "WORKLOAD_DURATION",         // u32, seconds for active workload (default 15)
        // S3.1 -- file-precise targeting via emufi v0.3.4+ target_block_range:
        "TARGET_BLOCK_RANGE_START",  // u64, sector unit (= fs_block × 8)
        "TARGET_BLOCK_RANGE_END",    // u64, sector unit, exclusive bound
        // pre-N100 fix : forward beamfs publication-campaign env vars
        // BEAMFS_SCHEME is consumed directly by worker.sh:62 (mkfs.beamfs -s)
        // BEAMFS_BENCH_FS_LIST and BEAMFS_BENCH_PROBS are consumed orchestrator-
        // side but forwarded for consistency (Rust reads from local env, not SSH).
        "BEAMFS_SCHEME",             // string: "inline" | "inode-universal"
        "BEAMFS_INODE_COUNT",        // u64, total inodes at mkfs time (0=default 256)
        "BEAMFS_DATA_CSUM",          // "1" -> mkfs --data-csum (format-v6 DATA_CSUM)
        "BEAMFS_INTERLEAVE",         // "1" -> mkfs --interleave (capsule layout)
        "BEAMFS_BENCH_FS_LIST",      // CSV: "beamfs,ext4,btrfs,xfs,ext2"
        "BEAMFS_BENCH_PROBS",        // CSV: "100,1000,10000,100000,500000,1000000"
    ] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                write!(env_prefix, " {var}={v}").unwrap();
            }
        }
    }
    format!("{env_prefix} {REMOTE_WORKER_PATH} {action_args}")
}

/// One cluster node with its runtime-discovered state.
#[derive(Debug, Clone)]
pub struct ClusterNode {
    pub ip: String,
    pub expected_hostname: String,
    pub discovered: NodeState,
}

#[derive(Debug, Clone, Default)]
pub struct NodeState {
    pub hostname: Option<String>,
    pub kernel: Option<String>,
    pub data_mount: Option<String>,
    pub data_used: Option<String>,
    pub beamfs_loaded: bool,
    /// Active injector name (radfi or emufi) as reported by worker.sh
    /// `discover_cluster` output (key: `INJECTOR_NAME`). Defaults to empty
    /// string if absent (legacy worker.sh).
    pub injector_name: String,
    /// EMUFI module currently loaded? (key: `EMUFI_LOADED`)
    pub emufi_loaded: bool,
    /// EMUFI .ko file present in /lib/modules/<kver>/updates/?
    /// (key: `EMUFI_KO_PRESENT`)
    pub emufi_ko_present: bool,
    pub perf_available: bool,
    pub ftrace_debugfs: bool,
    pub reachable: bool,
    pub error: Option<String>,
}

/// Build `SshTarget` for a given IP, using the standard hpcadmin key.
fn ssh_for(ip: &str) -> Result<SshTarget> {
    let key_path = std::env::var("HOME")
        .map(|h| format!("{h}/.ssh/hpclab_admin"))
        .context("HOME not set")?;
    Ok(SshTarget::new("hpcadmin", ip, &key_path))
}

/// Run `discover_cluster` on each of the 4 nodes in parallel.
/// Returns one `ClusterNode` per entry in `CLUSTER_NODES`.
pub fn discover_cluster() -> Result<Vec<ClusterNode>> {
    let mut handles = Vec::with_capacity(CLUSTER_NODES.len());

    for (ip, hostname) in CLUSTER_NODES {
        let ip = ip.to_string();
        let hostname = hostname.to_string();
        let h = thread::spawn(move || -> ClusterNode {
            let ssh = match ssh_for(&ip) {
                Ok(s) => s,
                Err(e) => return ClusterNode {
                    ip: ip.clone(),
                    expected_hostname: hostname,
                    discovered: NodeState {
                        reachable: false,
                        error: Some(format!("ssh setup: {e:#}")),
                        ..Default::default()
                    },
                },
            };

            let cmd = format!("{REMOTE_WORKER_PATH} discover_cluster");
            let out = match ssh.exec_lenient(&cmd) {
                Ok(s) => s,
                Err(e) => {
                    return ClusterNode {
                        ip: ip.clone(),
                        expected_hostname: hostname,
                        discovered: NodeState {
                            reachable: false,
                            error: Some(format!("ssh exec: {e:#}")),
                            ..Default::default()
                        },
                    };
                }
            };

            let mut state = NodeState {
                reachable: true,
                ..Default::default()
            };
            for line in out.lines() {
                if let Some((k, v)) = line.split_once('=') {
                    match k {
                        "HOST" => state.hostname = Some(v.to_string()),
                        "KERNEL" => state.kernel = Some(v.to_string()),
                        "DATA_MOUNT" => state.data_mount = Some(v.to_string()),
                        "DATA_USED" => state.data_used = Some(v.to_string()),
                        "BEAMFS_LOADED" => state.beamfs_loaded = v == "yes",
                        "INJECTOR_NAME" => state.injector_name = v.to_string(),
                        "EMUFI_LOADED" => state.emufi_loaded = v == "yes",
                        "EMUFI_KO_PRESENT" => state.emufi_ko_present = v == "yes",
                        "PERF_AVAILABLE" => state.perf_available = v == "yes",
                        "FTRACE_DEBUGFS" => state.ftrace_debugfs = v == "yes",
                        _ => {}
                    }
                }
            }
            ClusterNode {
                ip: ip.clone(),
                expected_hostname: hostname,
                discovered: state,
            }
        });
        handles.push(h);
    }

    let mut nodes: Vec<ClusterNode> = Vec::with_capacity(handles.len());
    for h in handles {
        let node = h.join().map_err(|_| anyhow!("cluster discovery thread panicked"))?;
        nodes.push(node);
    }
    Ok(nodes)
}

/// Render the cluster topology table to a String. Used by analyse to print
/// the topology BEFORE any cluster-wide destructive action.
pub fn render_cluster_table(nodes: &[ClusterNode]) -> String {
    let mut out = String::new();
    out.push_str("================================================================\n");
    out.push_str(" beamfs-bench cluster topology (auto-discovered)\n");
    out.push_str("================================================================\n");
    out.push('\n');
    out.push_str(" Node              | IP            | Kernel | beamfs | injector | inj.ko | perf | /data\n");
    out.push_str(" ------------------+---------------+--------+--------+-------+----------+------+-----------\n");
    for n in nodes {
        let host = n.discovered.hostname.as_deref().unwrap_or(&n.expected_hostname);
        let kernel = n.discovered.kernel.as_deref().unwrap_or("?");
        let beamfs = if n.discovered.beamfs_loaded { "yes" } else { "no " };
        // emufi is the only injector since radfi was removed.
        let injector = if n.discovered.emufi_loaded { "yes" } else { "no " };
        let injector_ko = if n.discovered.emufi_ko_present { "yes" } else { "no " };
        let perf = if n.discovered.perf_available { "yes" } else { "no " };
        let data = n.discovered.data_used.as_deref().unwrap_or("?");
        if n.discovered.reachable {
            writeln!(out,
                " {host:<17} | {:<13} | {:<6} | {:<6} | {:<5} | {:<8} | {:<4} | {:<10}",
                n.ip, kernel, beamfs, injector, injector_ko, perf, data
            ).unwrap();
        } else {
            writeln!(out,
                " {host:<17} | {:<13} | UNREACHABLE: {}",
                n.ip, n.discovered.error.as_deref().unwrap_or("?")
            ).unwrap();
        }
    }
    out.push('\n');
    out.push_str(" Legend:\n");
    out.push_str("   beamfs   = beamfs.ko currently loaded\n");
    out.push_str("   injector = emufi module loaded; will be insmod'ed by attack action if missing\n");
    out.push_str("   inj.ko   = /lib/modules/$(uname -r)/updates/<injector>.ko present on disk\n");
    out.push_str("   perf     = /usr/bin/perf available (required for --scope=full perf record)\n");
    out.push_str("   /data    = used / total on the beamfs-on-vdb mount\n");
    out.push_str("================================================================\n");
    out
}

/// Deploy the worker on every reachable node. Each node gets its own scp+chmod.
/// Errors per-node are collected and reported but do not abort the whole deploy
/// (a failed compute should not stop master-side work).
pub fn deploy_worker_all(nodes: &[ClusterNode]) -> Result<Vec<(String, Result<()>)>> {
    let worker_sh: Arc<&'static str> = Arc::new(crate::multifs::worker_sh());
    let mut handles = Vec::with_capacity(nodes.len());
    for n in nodes {
        if !n.discovered.reachable {
            continue;
        }
        let ip = n.ip.clone();
        let hostname = n.expected_hostname.clone();
        let worker = Arc::clone(&worker_sh);
        let h = thread::spawn(move || -> (String, Result<()>) {
            let result = (|| -> Result<()> {
                let ssh = ssh_for(&ip)?;
                let local_path = std::env::temp_dir()
                    .join(format!("beamfs-bench-worker-{}-{}.sh", std::process::id(), ip.replace('.', "_")));
                std::fs::write(&local_path, *worker)
                    .with_context(|| format!("write local worker for {ip}"))?;
                ssh.scp_to(local_path.to_str().unwrap(), REMOTE_WORKER_PATH)?;
                ssh.exec(&format!("chmod +x {REMOTE_WORKER_PATH}"))?;
                let _ = std::fs::remove_file(&local_path);
                Ok(())
            })();
            (hostname, result)
        });
        handles.push(h);
    }
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        let r = h.join().map_err(|_| anyhow!("worker deploy thread panicked"))?;
        out.push(r);
    }
    Ok(out)
}

/// Per-node result line for a cluster_* action.
#[derive(Debug, Clone)]
pub struct ClusterActionResult {
    pub host: String,
    pub raw_output: String,
}

/// Run `cluster_setup <ts_tag>` on all reachable nodes in parallel.
pub fn cluster_setup_all(nodes: &[ClusterNode], ts_tag: &str, injector: &str) -> Result<Vec<ClusterActionResult>> {
    run_cluster_action(nodes, &format!("cluster_setup {ts_tag}"), injector)
}

/// Run `cluster_attack <ts_tag> <prob>` on all reachable nodes in parallel.
pub fn cluster_attack_all(nodes: &[ClusterNode], ts_tag: &str, prob: u32, injector: &str) -> Result<Vec<ClusterActionResult>> {
    run_cluster_action(nodes, &format!("cluster_attack {ts_tag} {prob}"), injector)
}

/// Run `cluster_verify <ts_tag>` on all reachable nodes in parallel.
pub fn cluster_verify_all(nodes: &[ClusterNode], ts_tag: &str, injector: &str) -> Result<Vec<ClusterActionResult>> {
    run_cluster_action(nodes, &format!("cluster_verify {ts_tag}"), injector)
}

/// Run `bootstrap_data` on all reachable nodes in parallel. Used as a
/// recovery action when `cluster_setup` fails (e.g. /data was umounted
/// collaterally by `RadFI` attack on vdb between probability iterations).
pub fn bootstrap_data_all(nodes: &[ClusterNode], injector: &str) -> Result<Vec<ClusterActionResult>> {
    run_cluster_action(nodes, "bootstrap_data", injector)
}

fn run_cluster_action(nodes: &[ClusterNode], action_args: &str, injector: &str) -> Result<Vec<ClusterActionResult>> {
    let mut handles = Vec::with_capacity(nodes.len());
    for n in nodes {
        if !n.discovered.reachable {
            continue;
        }
        let ip = n.ip.clone();
        let hostname = n.expected_hostname.clone();
        let cmd = worker_cmd(injector, action_args);
        let h = thread::spawn(move || -> ClusterActionResult {
            let raw = match ssh_for(&ip).and_then(|ssh| ssh.exec_lenient(&cmd)) {
                Ok(s) => s,
                Err(e) => format!("CLUSTER|HOST={hostname}|ERROR={e:#}"),
            };
            ClusterActionResult { host: hostname, raw_output: raw }
        });
        handles.push(h);
    }
    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        let r = h.join().map_err(|_| anyhow!("cluster action thread panicked"))?;
        results.push(r);
    }
    Ok(results)
}
