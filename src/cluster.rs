//! cluster.rs — multi-node orchestration for analyse --scope=full.
//!
//! ## Topology (per recadrage R13)
//!
//! The BEAMFS cluster is NOT master-only. Each compute node has its own
//! BEAMFS instance on /dev/vdb mounted on /data, with kernel 7.0.3 +
//! beamfs.ko + reed_solomon.ko + radfi.ko (loadable). Compute nodes are
//! first-class targets, not passive observers.
//!
//! This module provides:
//!
//!   - ClusterNode: one (ip, hostname) entry with discovered state
//!   - discover_cluster(): query all 4 nodes for /data state, modules,
//!     ftrace/perf availability
//!   - render_cluster_table(): present the topology to the user before
//!     any cluster-wide action
//!   - cluster_setup_all() / cluster_attack_all() / cluster_verify_all():
//!     parallel execution across nodes via std::thread (one thread per node)
//!
//! No external async runtime needed: we spawn 1 OS thread per node and
//! join. Total = 4 threads, lifetime = duration of one ssh roundtrip.

use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use std::thread;

use crate::ssh::SshTarget;

/// The 4 cluster nodes. IP/hostname mapping is fixed by the lab topology.
pub const CLUSTER_NODES: &[(&str, &str)] = &[
    ("192.168.56.10", "beamfs-master"),
    ("192.168.56.11", "beamfs-compute01"),
    ("192.168.56.12", "beamfs-compute02"),
    ("192.168.56.13", "beamfs-compute03"),
];

pub const REMOTE_WORKER_PATH: &str = "/tmp/beamfs-bench-worker.sh";

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
    pub radfi_loaded: bool,
    pub beamfs_loaded: bool,
    pub radfi_ko_present: bool,
    pub perf_available: bool,
    pub ftrace_debugfs: bool,
    pub reachable: bool,
    pub error: Option<String>,
}

/// Build SshTarget for a given IP, using the standard hpcadmin key.
fn ssh_for(ip: &str) -> Result<SshTarget> {
    let key_path = std::env::var("HOME")
        .map(|h| format!("{h}/.ssh/hpclab_admin"))
        .context("HOME not set")?;
    Ok(SshTarget::new("hpcadmin", ip, &key_path))
}

/// Run `discover_cluster` on each of the 4 nodes in parallel.
/// Returns one ClusterNode per entry in CLUSTER_NODES.
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
                        "RADFI_LOADED" => state.radfi_loaded = v == "yes",
                        "BEAMFS_LOADED" => state.beamfs_loaded = v == "yes",
                        "RADFI_KO_PRESENT" => state.radfi_ko_present = v == "yes",
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
    out.push_str("\n");
    out.push_str(" Node              | IP            | Kernel | beamfs | radfi | radfi.ko | perf | /data\n");
    out.push_str(" ------------------+---------------+--------+--------+-------+----------+------+-----------\n");
    for n in nodes {
        let host = n.discovered.hostname.as_deref().unwrap_or(&n.expected_hostname);
        let kernel = n.discovered.kernel.as_deref().unwrap_or("?");
        let beamfs = if n.discovered.beamfs_loaded { "yes" } else { "no " };
        let radfi = if n.discovered.radfi_loaded { "yes" } else { "no " };
        let radfi_ko = if n.discovered.radfi_ko_present { "yes" } else { "no " };
        let perf = if n.discovered.perf_available { "yes" } else { "no " };
        let data = n.discovered.data_used.as_deref().unwrap_or("?");
        if !n.discovered.reachable {
            out.push_str(&format!(
                " {host:<17} | {:<13} | UNREACHABLE: {}\n",
                n.ip, n.discovered.error.as_deref().unwrap_or("?")
            ));
        } else {
            out.push_str(&format!(
                " {host:<17} | {:<13} | {:<6} | {:<6} | {:<5} | {:<8} | {:<4} | {:<10}\n",
                n.ip, kernel, beamfs, radfi, radfi_ko, perf, data
            ));
        }
    }
    out.push_str("\n");
    out.push_str(" Legend:\n");
    out.push_str("   beamfs   = beamfs.ko currently loaded\n");
    out.push_str("   radfi    = radfi.ko currently loaded (will be insmod'ed by attack action if missing)\n");
    out.push_str("   radfi.ko = /lib/modules/$(uname -r)/updates/radfi.ko present on disk\n");
    out.push_str("   perf     = /usr/bin/perf available (required for --scope=full perf record)\n");
    out.push_str("   /data    = used / total on the BEAMFS-on-vdb mount\n");
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
pub fn cluster_setup_all(nodes: &[ClusterNode], ts_tag: &str) -> Result<Vec<ClusterActionResult>> {
    run_cluster_action(nodes, &format!("cluster_setup {ts_tag}"))
}

/// Run `cluster_attack <ts_tag> <prob>` on all reachable nodes in parallel.
pub fn cluster_attack_all(nodes: &[ClusterNode], ts_tag: &str, prob: u32) -> Result<Vec<ClusterActionResult>> {
    run_cluster_action(nodes, &format!("cluster_attack {ts_tag} {prob}"))
}

/// Run `cluster_verify <ts_tag>` on all reachable nodes in parallel.
pub fn cluster_verify_all(nodes: &[ClusterNode], ts_tag: &str) -> Result<Vec<ClusterActionResult>> {
    run_cluster_action(nodes, &format!("cluster_verify {ts_tag}"))
}

/// Run `bootstrap_data` on all reachable nodes in parallel. Used as a
/// recovery action when cluster_setup fails (e.g. /data was umounted
/// collaterally by RadFI attack on vdb between probability iterations).
pub fn bootstrap_data_all(nodes: &[ClusterNode]) -> Result<Vec<ClusterActionResult>> {
    run_cluster_action(nodes, "bootstrap_data")
}

fn run_cluster_action(nodes: &[ClusterNode], action_args: &str) -> Result<Vec<ClusterActionResult>> {
    let mut handles = Vec::with_capacity(nodes.len());
    for n in nodes {
        if !n.discovered.reachable {
            continue;
        }
        let ip = n.ip.clone();
        let hostname = n.expected_hostname.clone();
        let cmd = format!("{REMOTE_WORKER_PATH} {action_args}");
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
