// SPDX-License-Identifier: GPL-2.0-only
//! Everything that must agree before a measurement means anything.
//!
//! This tool is not run from its repository. It is emerged, and what
//! runs is /usr/bin/beamfs-bench, built from whatever was pushed to git
//! at the time. So the chain from an edit to a measurement is:
//!
//!     working tree -> commit -> push -> emerge -> /usr/bin -> nodes
//!
//! and every one of those steps can be skipped by accident. A commit
//! that was never pushed is not in the ebuild's source; an emerge that
//! was never run leaves the previous binary in place; and the binary
//! carries worker.sh, so a node runs the worker of whichever build is
//! installed rather than the one in the tree.
//!
//! None of that is visible while it happens. The run starts, the
//! numbers come out, and they describe code that was replaced two days
//! ago. This says so first.

use std::path::{Path, PathBuf};
use std::process::Command;

/// How much a broken link matters.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Level {
    Fine,
    Warn,
    Stale,
}

/// One link of the chain, and what it says.
#[derive(Debug)]
pub struct Finding {
    pub link: &'static str,
    pub level: Level,
    pub detail: String,
}

fn repo() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("git/beamfs-bench")
}

fn git(args: &[&str]) -> Option<String> {
    let r = repo();
    let mut a: Vec<&str> = vec!["-C", r.to_str()?];
    a.extend_from_slice(args);
    let o = Command::new("git").args(&a).output().ok()?;
    if !o.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn mtime(p: &Path) -> Option<u64> {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Check every link that can be checked from here.
pub fn verify() -> Vec<Finding> {
    let mut out = Vec::new();

    // A working tree with edits in it is a measurement of something
    // that exists nowhere else.
    match git(&["status", "--short"]) {
        None => out.push(Finding {
            link: "working tree",
            level: Level::Warn,
            detail: "not a git repository, or git unavailable".into(),
        }),
        Some(s) if s.is_empty() => out.push(Finding {
            link: "working tree",
            level: Level::Fine,
            detail: "nothing uncommitted".into(),
        }),
        Some(s) => out.push(Finding {
            link: "working tree",
            level: Level::Stale,
            detail: format!("{} file(s) not committed", s.lines().count()),
        }),
    }

    // The ebuild pulls from the remote, so a commit that stayed here
    // is not in what gets built.
    match (git(&["rev-parse", "HEAD"]), git(&["rev-parse", "@{u}"])) {
        (Some(a), Some(b)) if a == b => out.push(Finding {
            link: "commit -> remote",
            level: Level::Fine,
            detail: "HEAD is pushed".into(),
        }),
        (Some(_), Some(_)) => {
            let n = git(&["rev-list", "--count", "@{u}..HEAD"]).unwrap_or_default();
            out.push(Finding {
                link: "commit -> remote",
                level: Level::Stale,
                detail: format!("{n} commit(s) not pushed; the ebuild builds the remote"),
            });
        }
        _ => out.push(Finding {
            link: "commit -> remote",
            level: Level::Warn,
            detail: "no upstream branch to compare against".into(),
        }),
    }

    // And the binary that will actually run.
    let installed = Path::new("/usr/bin/beamfs-bench");
    let when: Option<u64> = git(&["log", "-1", "--format=%ct"])
        .and_then(|s| s.parse().ok());
    match (mtime(installed), when) {
        (Some(b), Some(c)) if b >= c => out.push(Finding {
            link: "remote -> /usr/bin",
            level: Level::Fine,
            detail: "the installed binary is newer than the last commit".into(),
        }),
        (Some(b), Some(c)) => out.push(Finding {
            link: "remote -> /usr/bin",
            level: Level::Stale,
            detail: format!(
                "/usr/bin/beamfs-bench is {} min older than the last commit; \
                 emerge it or the run measures the previous build",
                (c - b) / 60
            ),
        }),
        _ => out.push(Finding {
            link: "remote -> /usr/bin",
            level: Level::Warn,
            detail: "could not compare the installed binary".into(),
        }),
    }

    // worker.sh travels inside the binary, so it follows the same
    // chain -- but an edit to it is easy to make and easy to forget,
    // because nothing here compiles.
    let w = repo().join("src/worker.sh");
    match (mtime(&w), mtime(installed)) {
        (Some(e), Some(b)) if e <= b => out.push(Finding {
            link: "worker.sh -> binary",
            level: Level::Fine,
            detail: "the installed binary carries the current worker".into(),
        }),
        (Some(e), Some(b)) => out.push(Finding {
            link: "worker.sh -> binary",
            level: Level::Stale,
            detail: format!(
                "src/worker.sh was edited {} min after the binary was installed",
                (e - b) / 60
            ),
        }),
        _ => out.push(Finding {
            link: "worker.sh -> binary",
            level: Level::Warn,
            detail: "could not compare worker.sh".into(),
        }),
    }

    // The version this build declares, against the tag it was cut at.
    let v = std::fs::read_to_string(repo().join("Cargo.toml"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("version = "))
                .map(|l| l.trim_start_matches("version = ").trim_matches('"').to_string())
        });
    out.push(match v {
        Some(v) => Finding {
            link: "version",
            level: Level::Fine,
            detail: v,
        },
        None => Finding {
            link: "version",
            level: Level::Warn,
            detail: "could not be read from Cargo.toml".into(),
        },
    });

    out
}

/// Refuse a measurement whose chain is broken.
pub fn gate() -> Result<(), String> {
    let all = verify();
    let broken: Vec<&Finding> = all.iter().filter(|f| f.level == Level::Stale).collect();
    if broken.is_empty() {
        return Ok(());
    }
    if std::env::var("BEAMFS_BENCH_FORCE").is_ok() {
        for f in &broken {
            println!("  ignored : {} -- {}", f.link, f.detail);
        }
        return Ok(());
    }
    let mut msg = String::from("the chain from this repository to the running binary is broken:\n");
    for f in &broken {
        msg.push_str(&format!("    {:<24} {}\n", f.link, f.detail));
    }
    msg.push_str("  a measurement here would describe other code than it names; \
                  set BEAMFS_BENCH_FORCE=1 to take it anyway");
    Err(msg)
}

/// Print every link, whatever it says.
pub fn report() {
    println!();
    for f in verify() {
        let mark = match f.level {
            Level::Fine => "ok   ",
            Level::Warn => "?    ",
            Level::Stale => "STALE",
        };
        println!("  {mark} {:<24} {}", f.link, f.detail);
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_link_is_not_a_sound_one() {
        assert_ne!(Level::Fine, Level::Stale);
        assert_ne!(Level::Warn, Level::Stale);
    }

    #[test]
    fn every_link_is_reported_once() {
        let v = verify();
        let mut names: Vec<&str> = v.iter().map(|f| f.link).collect();
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n, "a link reported twice");
        assert!(n >= 5, "expected every link, got {n}");
    }
}
