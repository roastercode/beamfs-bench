//! bootstrap.rs - cluster /data bootstrap pipeline.
//!
//! ## What this module does (Phase 2 of `beamfs-bench full`)
//!
//! For each of the 4 cluster nodes, in PARALLEL (R3):
//!
//!   1. SSH to the node
//!   2. Invoke `worker.sh bootstrap_data` action
//!      (which insmods `reed_solomon` + beamfs, umounts /data if mounted,
//!      mkfs.beamfs /dev/vdb, mount -t beamfs /dev/vdb /data)
//!   3. Parse the response line `CLUSTER|HOST=<host>|BOOTSTRAP=OK|...`
//!      or `CLUSTER|HOST=<host>|BOOTSTRAP=ERROR|reason=...`
//!
//! If ANY node returns BOOTSTRAP=ERROR, the whole bootstrap aborts (R3
//! fail-fast). The cluster as a whole must be bootstrap-ready or not at
//! all - we never run the bench on a partial cluster.
//!
//! Worker deployment is assumed already done by the caller (analyse.rs
//! or the new `full` subcommand). This module does NOT scp the worker;
//! it just invokes it.

use anyhow::{anyhow, bail, Context, Result};
use std::sync::Arc;
use std::thread;

use crate::cluster::ClusterNode;
use crate::ssh::SshTarget;

/// Result of a per-node bootstrap.
#[derive(Debug, Clone)]
pub struct BootstrapResult {
    pub host: String,
    pub ok: bool,
    pub raw_output: String,
}

/// Build `SshTarget` for an IP using the standard hpcadmin key.
fn ssh_for(ip: &str) -> Result<SshTarget> {
    let key_path = std::env::var("HOME")
        .map(|h| format!("{h}/.ssh/hpclab_admin"))
        .context("HOME not set")?;
    Ok(SshTarget::new("hpcadmin", ip, &key_path))
}

/// Run `bootstrap_data` on every reachable node in parallel.
/// Returns Err if ANY node failed (R3 fail-fast).
pub fn bootstrap_all_data(nodes: &[ClusterNode], per_inode_rs: bool, injector: &str) -> Result<Vec<BootstrapResult>> {
    println!("================================================================");
    println!(" beamfs-bench bootstrap - Phase 2: prepare /data on 4 nodes");
    println!("================================================================");

    let nodes_arc: Arc<Vec<ClusterNode>> = Arc::new(nodes.to_vec());
    let mut handles = Vec::with_capacity(nodes.len());

    for (idx, n) in nodes.iter().enumerate() {
        if !n.discovered.reachable {
            println!("  [{}] unreachable - skipping (will fail bootstrap check)",
                     n.expected_hostname);
            continue;
        }
        let nodes = Arc::clone(&nodes_arc);
        let injector_local = injector.to_string();
        let h = thread::spawn(move || -> BootstrapResult {
            let n = &nodes[idx];
            let host = n.expected_hostname.clone();
            let ip = n.ip.clone();

            let ssh = match ssh_for(&ip) {
                Ok(s) => s,
                Err(e) => return BootstrapResult {
                    host: host.clone(),
                    ok: false,
                    raw_output: format!("CLUSTER|HOST={host}|BOOTSTRAP=ERROR|reason=ssh setup: {e:#}"),
                },
            };

            let cmd = if per_inode_rs {
                crate::cluster::worker_cmd(&injector_local, "bootstrap_data per_inode_rs")
            } else {
                crate::cluster::worker_cmd(&injector_local, "bootstrap_data")
            };
            let raw = match ssh.exec_lenient(&cmd) {
                Ok(s) => s,
                Err(e) => return BootstrapResult {
                    host: host.clone(),
                    ok: false,
                    raw_output: format!("CLUSTER|HOST={host}|BOOTSTRAP=ERROR|reason=ssh exec: {e:#}"),
                },
            };

            let ok = raw.contains("BOOTSTRAP=OK");
            BootstrapResult {
                host,
                ok,
                raw_output: raw,
            }
        });
        handles.push(h);
    }

    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        let r = h.join().map_err(|_| anyhow!("bootstrap thread panicked"))?;
        results.push(r);
    }

    // Print results
    let mut n_ok = 0;
    let mut n_err = 0;
    for r in &results {
        if r.ok {
            println!("  [{}] OK   {}", r.host, r.raw_output);
            n_ok += 1;
        } else {
            println!("  [{}] FAIL {}", r.host, r.raw_output);
            n_err += 1;
        }
    }

    println!("[bootstrap] Summary : {n_ok} OK, {n_err} FAIL");

    if n_err > 0 {
        bail!("{n_err} node(s) failed cluster /data bootstrap (R3 fail-fast)");
    }

    // Also fail if any expected node is missing (was unreachable from cluster discovery)
    let expected = nodes_arc.len();
    if results.len() != expected {
        bail!(
            "cluster bootstrap incomplete: {} node(s) processed, {} expected",
            results.len(), expected
        );
    }

    println!("[bootstrap] Phase 2 complete - 4 nodes ready (/data mounted beamfs)");
    Ok(results)
}
