// SPDX-License-Identifier: GPL-2.0-only
//
// Author: Aurelien DESBRIERES <aurelien@hackers.camp>

//! A bpftrace script, attached while something is happening.
//!
//! Every other scope here reads state after the fact: a dmesg, a frozen
//! volume, a checker run, counters sampled before and after. What that
//! cannot show is a sequence -- a pointer installed and read back as
//! zero twenty-five seconds later by a different task. The trace of a
//! race is not the race.
//!
//! `forensics_host` already starts a fixed script on the host during
//! `analyse --bpftrace`. This is the other half: a named script, chosen
//! per run, attached to a cluster node rather than to the station, for
//! as long as asked. It became possible on 2026-09-19, when meta-clang
//! was finally added to the arm64 build and bpftrace entered the image
//! -- the follow-up that `forensics_host` records as out of scope.
//!
//! ## The scripts are not here
//!
//! They live in beamfs-xfstests, under `scripts/`, twenty of them, each
//! written against a specific defect: `lostptr.bt` watches a slot lose
//! its pointer, `whyzero.bt` asks what read zero, `parity.bt` follows
//! the indirect parity path. Copying them here would leave two
//! collections drifting apart, and the one that matters would be the
//! other one. This module looks for them where they are, and a search
//! path lets a script edited for one run be used without reinstalling
//! anything.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cluster::CLUSTER_NODES;
use crate::ssh::SshTarget;

/// Where the script is dropped on the node before it is attached.
const REMOTE_SCRIPT: &str = "/tmp/beamfs-bench-probe.bt";

/// How long bpftrace is given to compile and attach before the run is
/// considered started.
///
/// A script over a tracepoint attaches in under a second; one over a
/// kprobe with struct access takes several. Waiting too little reports
/// a trace that never ran as a trace that found nothing.
const ATTACH_GRACE: Duration = Duration::from_secs(12);

/// Directories searched for scripts, in order.
///
/// The environment first, so a script being edited wins; then this
/// repository's own directory if it ever grows one; then the installed
/// and in-tree copies of the beamfs-xfstests collection.
#[must_use]
pub fn script_roots() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(p) = std::env::var("BEAMFS_BENCH_BPF_SCRIPTS") {
        v.push(PathBuf::from(p));
    }
    v.push(PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts")));
    if let Ok(home) = std::env::var("HOME") {
        v.push(PathBuf::from(format!("{home}/git/beamfs-xfstests/scripts")));
    }
    v.push(PathBuf::from("/usr/share/beamfs-xfstests/scripts"));
    v.push(PathBuf::from("/usr/share/beamfs-bench/scripts"));
    v
}

/// Find a script by name, with or without its `.bt` suffix.
///
/// # Errors
/// When no directory on the search path holds it.
pub fn find_script(name: &str) -> Result<PathBuf> {
    let file = if name.ends_with(".bt") {
        name.to_string()
    } else {
        format!("{name}.bt")
    };
    for root in script_roots() {
        let c = root.join(&file);
        if c.is_file() {
            return Ok(c);
        }
    }
    bail!(
        "no script named {file}; searched {}",
        script_roots()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Every script found, with the first line of its header comment.
///
/// The header is what tells one from another -- the names are short by
/// design -- so listing without it would say nothing useful.
#[must_use]
pub fn list_scripts() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for root in script_roots() {
        let Ok(rd) = std::fs::read_dir(&root) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_none_or(|x| x != "bt") {
                continue;
            }
            let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else { continue };
            if out.iter().any(|(n, _)| n == stem) {
                continue;
            }
            out.push((stem.to_string(), first_sentence(&p)));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The first line of prose in a script's header comment.
fn first_sentence(p: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(p) else {
        return String::from("(unreadable)");
    };
    for line in text.lines().take(12) {
        let t = line
            .trim_start_matches(['#', '/', '*', ' '])
            .trim();
        if t.is_empty() || t.starts_with("!/") || t == "SPDX-License-Identifier: GPL-2.0-only" {
            continue;
        }
        return t.chars().take(72).collect();
    }
    String::new()
}

/// Which machine the probe attaches to.
#[derive(Debug, Clone)]
pub enum Target {
    /// The station itself.
    Host,
    /// A cluster node, by hostname or by address.
    Node(String),
}

impl Target {
    /// Read a target from what the operator typed.
    ///
    /// # Errors
    /// When the name matches no configured node.
    pub fn parse(s: &str) -> Result<Self> {
        // An empty string is a suffix of every hostname, so the match
        // below would silently pick the first node in the table.
        if s.trim().is_empty() {
            bail!("no target given");
        }
        if s.eq_ignore_ascii_case("host") {
            return Ok(Self::Host);
        }
        for (ip, name) in CLUSTER_NODES {
            if s == *ip || s == *name || name.ends_with(s) {
                return Ok(Self::Node((*ip).to_string()));
            }
        }
        bail!(
            "unknown target {s}; use host, or one of {}",
            CLUSTER_NODES
                .iter()
                .map(|(_, n)| (*n).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    /// How the target names itself in output.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Host => "host".to_string(),
            Self::Node(ip) => CLUSTER_NODES
                .iter()
                .find(|(a, _)| a == ip)
                .map_or_else(|| ip.clone(), |(_, n)| (*n).to_string()),
        }
    }
}

/// Build the SSH target for a node, with the lab's standard key.
fn ssh_for(ip: &str) -> Result<SshTarget> {
    let key = std::env::var("HOME")
        .map(|h| format!("{h}/.ssh/hpclab_admin"))
        .context("HOME not set")?;
    Ok(SshTarget::new("hpcadmin", ip, &key))
}

/// Attach a script for a while and return what it printed.
///
/// The script is killed by name on the way in as well as on the way
/// out: a probe left attached by an interrupted run keeps instrumenting
/// the kernel, and the next measurement would carry its cost without
/// anybody knowing.
///
/// # Errors
/// When the script cannot be found, copied, or when bpftrace is absent
/// on the target.
pub fn attach(script: &str, target: &Target, seconds: u64) -> Result<String> {
    let path = find_script(script)?;
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;

    match target {
        Target::Host => attach_host(&body, seconds),
        Target::Node(ip) => attach_node(ip, &path, seconds),
    }
}

/// Attach on the station, through sudo -n so a password prompt fails
/// fast rather than hanging a run nobody is watching.
fn attach_host(body: &str, seconds: u64) -> Result<String> {
    std::fs::write(REMOTE_SCRIPT, body).context("stage script on host")?;
    let out = std::process::Command::new("sudo")
        .args([
            "-n",
            "timeout",
            "-s",
            "INT",
            &seconds.to_string(),
            "bpftrace",
            REMOTE_SCRIPT,
        ])
        .output()
        .context("spawn bpftrace on host")?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        s.push_str("\n--- stderr ---\n");
        s.push_str(&err);
    }
    Ok(s)
}

/// Attach on a cluster node: copy, verify bpftrace is there, run.
fn attach_node(ip: &str, path: &Path, seconds: u64) -> Result<String> {
    let s = ssh_for(ip)?;

    let have = s
        .exec_lenient("command -v bpftrace || echo ABSENT")
        .unwrap_or_default();
    if have.contains("ABSENT") || have.trim().is_empty() {
        bail!(
            "bpftrace is not on {ip}; the image needs meta-clang in its build \
             directory and bpftrace in IMAGE_INSTALL"
        );
    }

    s.exec_lenient("sudo pkill -x bpftrace 2>/dev/null; true")?;
    s.scp_to(
        path.to_str().context("script path is not valid UTF-8")?,
        REMOTE_SCRIPT,
    )
    .context("copy script to node")?;

    // timeout sends INT, which bpftrace handles by printing its maps
    // and leaving; a KILL would lose everything it had counted.
    let out = s.exec_lenient(&format!(
        "sudo timeout -s INT {seconds} bpftrace {REMOTE_SCRIPT} 2>&1"
    ))?;
    s.exec_lenient("sudo pkill -x bpftrace 2>/dev/null; true")?;
    Ok(out)
}

/// The `trace` subcommand.
///
/// # Errors
/// When the target or the script cannot be resolved, or the probe
/// cannot be attached.
pub fn run_cli(script: &str, target: &str, seconds: u64, list: bool) -> Result<i32> {
    if list {
        let all = list_scripts();
        if all.is_empty() {
            println!("  no scripts found; searched:");
            for r in script_roots() {
                println!("    {}", r.display());
            }
            return Ok(1);
        }
        println!("  {} script(s):", all.len());
        println!();
        for (name, what) in all {
            println!("    {name:<16} {what}");
        }
        println!();
        return Ok(0);
    }

    let t = Target::parse(target)?;
    let path = find_script(script)?;

    println!("  script  : {}", path.display());
    println!("  target  : {}", t.label());
    println!("  seconds : {seconds}");
    println!("  grace   : {}s to compile and attach", ATTACH_GRACE.as_secs());
    println!();

    let out = attach(script, &t, seconds)?;

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let dir = PathBuf::from("/tmp/beamfs-bench-current-run/trace");
    std::fs::create_dir_all(&dir).context("create trace dir")?;
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("probe");
    let log = dir.join(format!("{name}-{}-{stamp}.log", t.label()));
    std::fs::write(&log, &out).with_context(|| format!("write {}", log.display()))?;

    print!("{out}");
    println!();
    println!("  kept: {}", log.display());

    // The bench reports; it does not judge. A probe that found nothing
    // is a result, not a failure.
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name with or without its suffix names the same script.
    #[test]
    fn a_name_resolves_with_or_without_its_suffix() {
        let with = find_script("lostptr.bt");
        let without = find_script("lostptr");
        assert_eq!(with.is_ok(), without.is_ok());
        if let (Ok(a), Ok(b)) = (with, without) {
            assert_eq!(a, b);
        }
    }

    /// host is a target, and so is a node by its short name.
    #[test]
    fn the_station_and_a_node_are_both_targets() {
        assert!(matches!(Target::parse("host"), Ok(Target::Host)));
        assert!(matches!(Target::parse("compute01"), Ok(Target::Node(_))));
        assert!(matches!(Target::parse("192.168.56.10"), Ok(Target::Node(_))));
    }

    /// Anything else is refused rather than guessed at.
    #[test]
    fn an_unknown_target_is_refused() {
        assert!(Target::parse("compute99").is_err());
        assert!(Target::parse("").is_err());
    }

    /// A node names itself by hostname, not by address.
    #[test]
    fn a_node_labels_itself_by_name() {
        let t = Target::parse("192.168.56.11").expect("known node");
        assert_eq!(t.label(), "beamfs-compute01");
        assert_eq!(Target::Host.label(), "host");
    }

    /// The search path is ordered, and the environment comes first.
    #[test]
    fn the_environment_wins_the_search_path() {
        unsafe { std::env::set_var("BEAMFS_BENCH_BPF_SCRIPTS", "/tmp/bpf-elsewhere") };
        let roots = script_roots();
        unsafe { std::env::remove_var("BEAMFS_BENCH_BPF_SCRIPTS") };
        assert_eq!(roots.first().map(|p| p.display().to_string()),
                   Some("/tmp/bpf-elsewhere".to_string()));
    }
}
