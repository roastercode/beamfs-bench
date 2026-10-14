// SPDX-License-Identifier: GPL-2.0-only
//! The newest mainline tag kernel.org lists, read with `git ls-remote`.
//!
//! Nothing is fetched: `ls-remote` names every tag and, for an annotated
//! one, the commit it points to, on the line ending in `^{}`.

use std::collections::BTreeMap;
use std::process::Command;

/// The tree mainline is published from.
pub(crate) const MAINLINE: &str = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git";
const SECONDS: u32 = 20;

/// A mainline tag and the commit it names.
pub(crate) struct MainlineTag {
    pub(crate) name: String,
    pub(crate) commit: String,
}

/// The newest mainline tag kernel.org lists.
///
/// # Errors
///
/// kernel.org out of reach within 20 seconds, `git` not run, or no
/// mainline tag in what it listed.
pub(crate) fn latest() -> Result<MainlineTag, String> {
    let o = Command::new("timeout")
        .arg(SECONDS.to_string())
        .args(["git", "ls-remote", "--tags", MAINLINE, "refs/tags/v*"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|e| format!("git ls-remote not run: {e}"))?;
    if o.status.code() == Some(124) {
        return Err(format!("kernel.org did not answer within {SECONDS} s"));
    }
    if !o.status.success() {
        return Err(format!(
            "kernel.org not read: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    newest(&String::from_utf8_lossy(&o.stdout))
        .ok_or_else(|| "kernel.org listed no mainline tag".to_string())
}

/// A mainline tag, "v7.3-rc7" or "v7.3", in release order: an -rc
/// before its release, a release before the next -rc1. Anything else,
/// the three-part tags of the 2.6 years included, is not one.
fn order(name: &str) -> Option<(u32, u32, u32)> {
    let s = name.strip_prefix('v')?;
    let (base, stage) = match s.split_once("-rc") {
        Some((b, n)) => (b, digits(n).filter(|k| *k > 0)?),
        None => (s, u32::MAX),
    };
    let (major, minor) = base.split_once('.')?;
    Some((digits(major)?, digits(minor)?, stage))
}

fn digits(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// The newest mainline tag in what `git ls-remote --tags` printed, with
/// the commit it names.
fn newest(listed: &str) -> Option<MainlineTag> {
    let mut objects = BTreeMap::new();
    let mut peeled = BTreeMap::new();
    for line in listed.lines() {
        let Some((sha, r)) = line.split_once('\t') else {
            continue;
        };
        let Some(name) = r.trim().strip_prefix("refs/tags/") else {
            continue;
        };
        if let Some(n) = name.strip_suffix("^{}") {
            peeled.insert(n.to_string(), sha.to_string());
        } else {
            objects.insert(name.to_string(), sha.to_string());
        }
    }
    let (_, name, object) = objects
        .into_iter()
        .filter_map(|(name, object)| Some((order(&name)?, name, object)))
        .max_by_key(|(o, _, _)| *o)?;
    let commit = peeled.remove(&name).unwrap_or(object);
    Some(MainlineTag { name, commit })
}

#[cfg(test)]
mod tests {
    use super::{newest, order};

    #[test]
    fn mainline_tags_in_release_order() {
        assert!(order("v7.3-rc6") < order("v7.3-rc7"));
        assert!(order("v7.3-rc9") < order("v7.3-rc10"));
        assert!(order("v7.3-rc7") < order("v7.3"));
        assert!(order("v7.3") < order("v7.4-rc1"));
        assert!(order("v7.9") < order("v7.10-rc1"));
        for s in ["v2.6.12", "v7.3-rc", "v7.3-rc0", "v7", "v7.3-rc7-foo", "7.3", ""] {
            assert!(order(s).is_none(), "{s}");
        }
    }

    #[test]
    fn the_newest_tag_and_the_commit_it_names() {
        let a = "1".repeat(40);
        let b = "2".repeat(40);
        let c = "3".repeat(40);
        let listed = format!(
            "{a}\trefs/tags/v7.3-rc7\n{b}\trefs/tags/v7.3-rc7^{{}}\n\
             {a}\trefs/tags/v7.3-rc10\n{c}\trefs/tags/v7.3-rc10^{{}}\n\
             {a}\trefs/tags/v2.6.12\n"
        );
        let t = newest(&listed).unwrap();
        assert_eq!(t.name, "v7.3-rc10");
        assert_eq!(t.commit, c);
        let t = newest(&format!("{a}\trefs/tags/v7.3\n")).unwrap();
        assert_eq!(t.commit, a);
        assert!(newest("garbage\n").is_none());
    }
}
