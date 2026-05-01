//! forensics.rs - multi-node forensic capture for `analyse` subcommand.
//!
//! ## What is captured (per node, by scope)
//!
//! | Capture                | quick | standard | full |
//! |------------------------|-------|----------|------|
//! | dmesg dump             |  yes  |   yes    |  yes |
//! | RadFI debugfs counters |  yes  |   yes    |  yes |
//! | lsmod (top 30)         |  yes  |   yes    |  yes |
//! | ftrace function_graph  |  no   |   no     |  yes |
//! | perf record -a -g      |  no   |   no     |  yes |
//! | RS journal SB hexdump  |  no   |   yes    |  yes |
//!
//! Output : `<run_dir>/forensics-<hostname>/{dmesg.log, radfi-counters.log,
//! lsmod.log, ftrace.log, perf-report.log, rs-journal.log}`
//!
//! All captures are prefixed `sudo` because /sys/kernel/debug, /proc, and
//! perf record require root. The hpcadmin user has passwordless sudo on
//! the lab VMs (set up by the yocto recipe).

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use crate::cluster::ClusterNode;
use crate::ssh::SshTarget;

/// Forensic scope levels. Mapped 1:1 to `analyse --scope=<...>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Quick,
    Standard,
    Full,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Quick => "quick",
            Scope::Standard => "standard",
            Scope::Full => "full",
        }
    }
}

fn ssh_for(ip: &str) -> Result<SshTarget> {
    let key_path = std::env::var("HOME")
        .map(|h| format!("{h}/.ssh/hpclab_admin"))
        .context("HOME not set")?;
    Ok(SshTarget::new("hpcadmin", ip, &key_path))
}

// ----------------------------------------------------------------
// PRE-CAPTURE SETUP
// ----------------------------------------------------------------

/// Pre-capture: clear dmesg + arm ftrace (if scope=full) on every reachable node.
/// Returns per-node setup status. Failure on one node is logged but does not
/// abort other nodes.
pub fn pre_capture_all(nodes: &[ClusterNode], scope: Scope) -> Result<Vec<(String, Result<()>)>> {
    let mut handles = Vec::with_capacity(nodes.len());
    for n in nodes {
        if !n.discovered.reachable {
            continue;
        }
        let ip = n.ip.clone();
        let hostname = n.expected_hostname.clone();
        let need_ftrace = scope == Scope::Full;
        let h = thread::spawn(move || -> (String, Result<()>) {
            let result = (|| -> Result<()> {
                let ssh = ssh_for(&ip)?;
                ssh.exec_lenient("sudo dmesg -c >/dev/null 2>&1; true")?;
                if need_ftrace {
                    let setup = r#"
                        sudo bash -c '
                            if sudo test -d /sys/kernel/debug/tracing; then
                                echo nop > /sys/kernel/debug/tracing/current_tracer 2>/dev/null
                                echo > /sys/kernel/debug/tracing/trace 2>/dev/null
                                echo > /sys/kernel/debug/tracing/set_ftrace_filter 2>/dev/null
                                for sym in beamfs_* radfi_* submit_bio_noacct submit_bh; do
                                    echo "$sym" >> /sys/kernel/debug/tracing/set_ftrace_filter 2>/dev/null || true
                                done
                                echo function_graph > /sys/kernel/debug/tracing/current_tracer 2>/dev/null || true
                                echo 1 > /sys/kernel/debug/tracing/tracing_on 2>/dev/null
                            fi
                        '
                    "#;
                    ssh.exec_lenient(setup)?;
                }
                Ok(())
            })();
            (hostname, result)
        });
        handles.push(h);
    }
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        let r = h.join().map_err(|_| anyhow!("pre-capture thread panicked"))?;
        out.push(r);
    }
    Ok(out)
}

/// Start `perf record -a -g` in background on master only (for scope=full).
/// Returns immediately; stop_perf() must be called before final capture.
pub fn start_perf_master() -> Result<()> {
    let ssh = ssh_for("192.168.56.10")?;
    // Wipe stale PID file before launch (idempotent).
    ssh.exec_lenient("sudo rm -f /tmp/beamfs-bench-perf.pid")?;
    // nohup + sleep 3600 = bounded duration; we'll SIGINT it before that.
    // Capture the perf PID via $! into a sidecar file so stop_perf_master
    // can wait on the exact process and let perf finalize its header.
    let launch = r#"sudo bash -c 'nohup perf record -a -g -o /tmp/beamfs-bench-perf.data -- sleep 3600 >/tmp/beamfs-bench-perf.log 2>&1 & echo $! > /tmp/beamfs-bench-perf.pid'"#;
    ssh.exec_lenient(launch)?;
    // Give perf a moment to start sampling and write its header.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    Ok(())
}

/// Stop perf record on master. Sends SIGINT, then waits for perf to flush
/// its data file. Without this wait, perf's atomic rename of the .data file
/// can race with our subsequent cat/scp and produce a 0-byte file or a
/// "data size field is 0" error from `perf report`.
pub fn stop_perf_master() -> Result<()> {
    let ssh = ssh_for("192.168.56.10")?;
    // SIGINT to the exact PID, then bounded wait for process exit so perf
    // can complete its header finalize (perf_session__write_header runs
    // after main() returns). Validate via perf report --header-only;
    // if the header parses, data_size is non-zero and the file is intact.
    let probe = r#"
        PID=$(sudo cat /tmp/beamfs-bench-perf.pid 2>/dev/null || echo "")
        if [ -z "$PID" ]; then
            echo "perf_no_pid_file"
            exit 1
        fi
        sudo kill -INT "$PID" 2>/dev/null || true
        for i in $(seq 1 30); do
            if ! sudo kill -0 "$PID" 2>/dev/null; then
                break
            fi
            sleep 0.5
        done
        if sudo kill -0 "$PID" 2>/dev/null; then
            sudo kill -TERM "$PID" 2>/dev/null || true
            sleep 1
        fi
        size=$(sudo stat -c '%s' /tmp/beamfs-bench-perf.data 2>/dev/null || echo 0)
        if sudo perf report --header-only -i /tmp/beamfs-bench-perf.data >/dev/null 2>&1; then
            echo "perf_stopped_size=$size header_ok=1"
            exit 0
        fi
        echo "perf_stopped_size=$size header_ok=0"
        exit 2
    "#;
    let out = ssh.exec_lenient(probe).unwrap_or_default();
    if !out.is_empty() {
        eprintln!("beamfs-bench: {}", out.trim());
    }
    Ok(())
}

// ----------------------------------------------------------------
// POST-CAPTURE COLLECTION
// ----------------------------------------------------------------

/// Per-node forensic capture. Writes files into `<run_dir>/forensics-<hostname>/`.
pub fn post_capture_all(
    nodes: &[ClusterNode],
    run_dir: &Path,
    scope: Scope,
) -> Result<Vec<(String, Result<PathBuf>)>> {
    let run_dir_arc = Arc::new(run_dir.to_path_buf());
    let mut handles = Vec::with_capacity(nodes.len());
    for n in nodes {
        if !n.discovered.reachable {
            continue;
        }
        let ip = n.ip.clone();
        let hostname = n.discovered.hostname.clone()
            .unwrap_or_else(|| n.expected_hostname.clone());
        let run_dir = Arc::clone(&run_dir_arc);
        let scope = scope;
        let h = thread::spawn(move || -> (String, Result<PathBuf>) {
            let r = capture_one_node(&ip, &hostname, &run_dir, scope);
            (hostname, r)
        });
        handles.push(h);
    }
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        let r = h.join().map_err(|_| anyhow!("post-capture thread panicked"))?;
        out.push(r);
    }
    Ok(out)
}

fn capture_one_node(
    ip: &str,
    hostname: &str,
    run_dir: &Path,
    scope: Scope,
) -> Result<PathBuf> {
    let node_dir = run_dir.join(format!("forensics-{hostname}"));
    fs::create_dir_all(&node_dir)
        .with_context(|| format!("create_dir_all {:?}", node_dir))?;

    let ssh = ssh_for(ip)?;

    // 1. dmesg full
    let dmesg = ssh.exec_lenient("sudo dmesg")
        .with_context(|| format!("dmesg on {hostname}"))?;
    fs::write(node_dir.join("dmesg.log"), dmesg)
        .with_context(|| format!("write dmesg.log for {hostname}"))?;

    // 2. RadFI counters
    let radfi_cmd = r#"
        if sudo test -d /sys/kernel/debug/radfi; then
            echo '--- /sys/kernel/debug/radfi/ ---'
            for f in enabled hook_fs hook_blk inject_on_read probability target_dev target_inode target_block seed call_count flip_count skipped_disabled skipped_prob; do
                val=$(sudo cat /sys/kernel/debug/radfi/$f 2>/dev/null)
                printf "%-22s = %s\n" "$f" "$val"
            done
        elif lsmod | grep -q '^radfi'; then
            echo 'radfi.ko loaded but /sys/kernel/debug/radfi not accessible (debugfs mount or perms issue)'
        else
            echo 'radfi.ko not loaded'
        fi
        echo
        echo '--- lsmod (top 30) ---'
        lsmod | head -30
    "#;
    let radfi = ssh.exec_lenient(radfi_cmd)
        .with_context(|| format!("radfi counters on {hostname}"))?;
    fs::write(node_dir.join("radfi-counters.log"), radfi)
        .with_context(|| format!("write radfi-counters.log for {hostname}"))?;

    // 3. lsmod full (separate file)
    let lsmod = ssh.exec_lenient("lsmod")
        .with_context(|| format!("lsmod on {hostname}"))?;
    fs::write(node_dir.join("lsmod.log"), lsmod)
        .with_context(|| format!("write lsmod.log for {hostname}"))?;

    // 4. ftrace dump (full only)
    if scope == Scope::Full {
        let ftrace_cmd = r#"
            sudo bash -c '
                if sudo test -d /sys/kernel/debug/tracing; then
                    echo 0 > /sys/kernel/debug/tracing/tracing_on 2>/dev/null
                    cat /sys/kernel/debug/tracing/trace 2>/dev/null
                    echo nop > /sys/kernel/debug/tracing/current_tracer 2>/dev/null
                    : > /sys/kernel/debug/tracing/set_ftrace_filter 2>/dev/null
                else
                    echo "ftrace debugfs not accessible"
                fi
            '
        "#;
        let ftrace = ssh.exec_lenient(ftrace_cmd)
            .with_context(|| format!("ftrace dump on {hostname}"))?;
        fs::write(node_dir.join("ftrace.log"), ftrace)
            .with_context(|| format!("write ftrace.log for {hostname}"))?;
    }

    // 5. RS journal SB hexdump (standard + full, master only)
    if (scope == Scope::Standard || scope == Scope::Full) && hostname == "beamfs-master" {
        let rs_cmd = r#"
            if mount | grep -q '/dev/vdb on /data type beamfs'; then
                echo '--- /data beamfs state ---'
                df -hT /data
                echo
                echo '--- beamfs dmesg traces (last 5) ---'
                sudo dmesg | grep -E "beamfs:.*mounted|beamfs:.*scheme=" | tail -5
                echo
                echo '--- RS event journal (best effort, hexdump SB s_rs_journal area) ---'
                sudo dd if=/dev/vdb bs=4096 count=1 status=none 2>/dev/null | hexdump -C | sed -n "1,40p"
            else
                echo "/data not mounted as beamfs on this node"
            fi
        "#;
        let rs = ssh.exec_lenient(rs_cmd)
            .with_context(|| format!("rs journal on {hostname}"))?;
        fs::write(node_dir.join("rs-journal.log"), rs)
            .with_context(|| format!("write rs-journal.log for {hostname}"))?;
    }

    // 6. perf report (full only, master only)
    if scope == Scope::Full && hostname == "beamfs-master" {
        let perf_cmd = "sudo perf report --stdio -i /tmp/beamfs-bench-perf.data 2>&1 | head -200";
        let perf = ssh.exec_lenient(perf_cmd).unwrap_or_else(|e|
            format!("perf report failed: {e:#}"));
        fs::write(node_dir.join("perf-report.log"), perf)
            .with_context(|| format!("write perf-report.log for {hostname}"))?;

        // Pull the raw perf.data via scp (binary, not base64)
        let local_perf = node_dir.join("perf.data");
        let _ = ssh.exec_lenient(&format!("sudo chmod 644 /tmp/beamfs-bench-perf.data 2>/dev/null"));
        // scp_from is not yet in ssh.rs; fall back to base64 dump for now.
        // (TODO: add scp_from in ssh.rs in a follow-up.)
        let perf_b64 = ssh.exec_lenient("sudo cat /tmp/beamfs-bench-perf.data 2>/dev/null | base64")
            .unwrap_or_default();
        if !perf_b64.is_empty() {
            fs::write(node_dir.join("perf.data.b64"), perf_b64)
                .with_context(|| "write perf.data.b64")?;
        }
        let _ = local_perf; // silence unused warning until scp_from lands
    }

    Ok(node_dir)
}

// ----------------------------------------------------------------
// CRASH REPORT (when the wrapped run failed)
// ----------------------------------------------------------------

/// Generate `<run_dir>/crash-report.md` summarizing the failure for quick triage.
/// Only called when the wrapped multifs/cluster run reported errors.
pub fn write_crash_report(
    run_dir: &Path,
    ts_human: &str,
    exit_code: i32,
    tir_log_path: Option<&Path>,
) -> Result<()> {
    let path = run_dir.join("crash-report.md");
    let mut content = String::new();
    content.push_str("# beamfs-bench analyse: CRASH REPORT\n\n");
    content.push_str(&format!("**Date**: {ts_human}\n"));
    content.push_str(&format!("**Exit code**: {exit_code}\n"));
    content.push_str(&format!("**Run dir**: `{}`\n\n", run_dir.display()));

    if let Some(p) = tir_log_path {
        if let Ok(log) = fs::read_to_string(p) {
            content.push_str("## Run log tail (last 80 lines)\n\n```\n");
            let tail: Vec<&str> = log.lines().rev().take(80).collect();
            for l in tail.iter().rev() {
                content.push_str(l);
                content.push('\n');
            }
            content.push_str("```\n\n");
        }
    }

    let master_dmesg = run_dir.join("forensics-beamfs-master/dmesg.log");
    if let Ok(log) = fs::read_to_string(&master_dmesg) {
        content.push_str("## Master dmesg tail (last 60 lines)\n\n```\n");
        let tail: Vec<&str> = log.lines().rev().take(60).collect();
        for l in tail.iter().rev() {
            content.push_str(l);
            content.push('\n');
        }
        content.push_str("```\n\n");
    }

    let master_radfi = run_dir.join("forensics-beamfs-master/radfi-counters.log");
    if let Ok(log) = fs::read_to_string(&master_radfi) {
        content.push_str("## RadFI counters at end of run (master)\n\n```\n");
        content.push_str(&log);
        content.push_str("\n```\n\n");
    }

    content.push_str("## Files in this run dir\n\n");
    if let Ok(rd) = fs::read_dir(run_dir) {
        for entry in rd.flatten() {
            content.push_str(&format!("- `{}`\n", entry.path().display()));
        }
    }

    fs::write(&path, content)
        .with_context(|| format!("write {:?}", path))?;
    Ok(())
}
