// SPDX-License-Identifier: GPL-2.0-only
//
// Author: Aurelien DESBRIERES <aurelien@hackers.camp>

//! The seal that keeps this bench on the image BX measured.
//!
//! The validation chain is BX, then BB, then publication, and until
//! 2026-09-19 nothing tied the three together. The x86 lab ran images
//! built on 4 July against kernel 7.1.3 while this cluster ran
//! 7.3.0-rc2. It surfaced only because emufi's kprobe on submit_bh --
//! removed between those two kernels -- failed to register and took
//! the injector with it: twenty-seven attack runs delivered not one
//! flip, and the report scored the filesystem on the silence.
//!
//! beamfs-xfstests writes the seal when it deploys. This reads it and
//! compares the canonical image's sha256 against it. A mismatch stops
//! the pipeline, and so does a missing seal: a chain nobody opened is
//! not a chain, and a bench that runs anyway proves nothing about the
//! filesystem BX measured.
//!
//! BEAMFS_CHAIN_IGNORE=1 goes through, because a harness that cannot
//! be run during development gets bypassed permanently. The manifest
//! records that it was used, so a run that skipped the check cannot be
//! published as one that passed it.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Where the seal lives. Outside both repos: it belongs to the lab,
/// not to either tool, and it must survive a clean checkout of both.
#[must_use]
pub fn seal_path() -> PathBuf {
    if let Ok(p) = std::env::var("BEAMFS_CHAIN_SEAL") {
        if !p.trim().is_empty() {
            return PathBuf::from(p.trim());
        }
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_default())
        .join(".local/share/beamfs-chain/seal.json")
}

/// What the previous link of the chain recorded. Written by
/// beamfs-xfstests; the field names are the contract between the two.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Seal {
    #[serde(default)] pub tool: String,
    #[serde(default)] pub written_at: String,
    #[serde(default)] pub machine: String,
    #[serde(default)] pub image_path: String,
    #[serde(default)] pub image_sha256: String,
    #[serde(default)] pub kernel_release: String,
    #[serde(default)] pub commit_beamfs: String,
    #[serde(default)] pub commit_yocto: String,
}

/// What the check concluded, for the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The canonical image is the one the seal names.
    Matched,
    /// The check was bypassed with BEAMFS_CHAIN_IGNORE.
    Ignored,
}

fn ignoring() -> bool {
    std::env::var("BEAMFS_CHAIN_IGNORE").is_ok_and(|v| {
        let v = v.trim();
        !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
    })
}

/// Read the seal, if one was left.
///
/// # Errors
/// When the file exists but does not parse.
pub fn read() -> Result<Option<Seal>> {
    let p = seal_path();
    let Ok(txt) = std::fs::read_to_string(&p) else {
        return Ok(None);
    };
    let s: Seal = serde_json::from_str(&txt)
        .with_context(|| format!("parse seal {}", p.display()))?;
    // A half-written file must not pass for a seal: an empty hash
    // would compare equal to nothing and let any image through.
    if s.image_sha256.trim().is_empty() {
        bail!("seal {} carries no image_sha256", p.display());
    }
    Ok(Some(s))
}

fn short(s: &str) -> &str {
    &s[..16.min(s.len())]
}

/// Compare the canonical image against the seal BX left.
///
/// # Errors
/// When no seal exists, or it names a different image, unless
/// BEAMFS_CHAIN_IGNORE says otherwise.
pub fn verify(canonical_sha: &str, canonical_path: &Path) -> Result<(Verdict, Option<Seal>)> {
    let seal = read()?;

    let Some(seal) = seal else {
        if ignoring() {
            println!("  chain   : no seal, BEAMFS_CHAIN_IGNORE set -- the chain is open-ended");
            return Ok((Verdict::Ignored, None));
        }
        bail!(
            "no chain seal at {}: beamfs-xfstests has not deployed, so there is \
             no campaign this bench can be the second half of. Run BX first, or \
             set BEAMFS_CHAIN_IGNORE=1 to measure outside the chain -- the \
             manifest will record that it was set.",
            seal_path().display()
        );
    };

    if seal.image_sha256 == canonical_sha {
        println!(
            "  chain   : matched {} sealed by {} on {} (kernel {})",
            short(canonical_sha),
            seal.tool,
            seal.machine,
            if seal.kernel_release.is_empty() { "unknown" } else { &seal.kernel_release }
        );
        return Ok((Verdict::Matched, Some(seal)));
    }

    let msg = format!(
        "chain broken: this bench would measure {} ({}) while {} sealed {} ({}, kernel {}) at {}.\n  \
         sealed image : {}\n  \
         this image   : {}\n  \
         Point this bench at the sealed image -- BEAMFS_BENCH_MACHINE, \
         BEAMFS_BENCH_BUILD_DIR, BEAMFS_BENCH_IMAGE -- or rebuild it, or set \
         BEAMFS_CHAIN_IGNORE=1 to measure outside the chain.",
        short(canonical_sha),
        crate::lab::machine(),
        seal.tool,
        short(&seal.image_sha256),
        seal.machine,
        if seal.kernel_release.is_empty() { "unknown" } else { &seal.kernel_release },
        seal.written_at,
        seal.image_path,
        canonical_path.display(),
    );

    if ignoring() {
        println!("  chain   : BEAMFS_CHAIN_IGNORE set, going on anyway");
        for line in msg.lines() {
            println!("  chain   : {line}");
        }
        return Ok((Verdict::Ignored, Some(seal)));
    }
    bail!(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_seal(body: &str, f: impl FnOnce()) {
        let p = std::env::temp_dir().join("beamfs-bench-chain-test.json");
        std::fs::write(&p, body).unwrap();
        unsafe { std::env::set_var("BEAMFS_CHAIN_SEAL", &p) };
        f();
        let _ = std::fs::remove_file(&p);
        unsafe { std::env::remove_var("BEAMFS_CHAIN_SEAL") };
    }

    const GOOD: &str = concat!(
        r#"{"tool":"beamfs-xfstests","written_at":"2026-09-19T14:00:00Z","#,
        r#""machine":"qemux86-64","image_path":"/x/y.beamfs","#,
        r#""image_sha256":"aaaa","kernel_release":"7.3-rc3","#,
        r#""commit_beamfs":"c1","commit_yocto":"c2"}"#,
    );

    #[test]
    fn the_test_fixture_is_valid_json() {
        // It was not, on the first try: a line break landed inside a
        // key and three tests failed on the parser rather than on what
        // they meant to check.
        let s: Seal = serde_json::from_str(GOOD).expect("fixture parses");
        assert_eq!(s.image_sha256, "aaaa");
        assert_eq!(s.kernel_release, "7.3-rc3");
    }

    #[test]
    fn a_matching_image_passes() {
        let _g = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe { std::env::remove_var("BEAMFS_CHAIN_IGNORE") };
        with_seal(GOOD, || {
            let (v, s) = verify("aaaa", Path::new("/x/y.beamfs")).expect("matches");
            assert_eq!(v, Verdict::Matched);
            assert_eq!(s.unwrap().tool, "beamfs-xfstests");
        });
    }

    #[test]
    fn a_different_image_stops_the_run() {
        let _g = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe { std::env::remove_var("BEAMFS_CHAIN_IGNORE") };
        with_seal(GOOD, || {
            let e = verify("bbbb", Path::new("/other.beamfs")).unwrap_err();
            let t = e.to_string();
            assert!(t.contains("chain broken"), "{t}");
            assert!(t.contains("aaaa"), "{t}");
        });
    }

    #[test]
    fn a_missing_seal_stops_the_run() {
        let _g = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe { std::env::remove_var("BEAMFS_CHAIN_IGNORE") };
        let gone = std::env::temp_dir().join("beamfs-bench-no-such-seal.json");
        let _ = std::fs::remove_file(&gone);
        unsafe { std::env::set_var("BEAMFS_CHAIN_SEAL", &gone) };
        let e = verify("aaaa", Path::new("/x")).unwrap_err();
        assert!(e.to_string().contains("no chain seal"), "{e}");
        unsafe { std::env::remove_var("BEAMFS_CHAIN_SEAL") };
    }

    #[test]
    fn a_seal_without_a_hash_is_refused_not_ignored() {
        // An empty hash compares equal to nothing; treating it as
        // "no seal" would silently let any image through.
        let _g = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        with_seal(r#"{"tool":"x","image_sha256":""}"#, || {
            assert!(read().is_err());
        });
    }

    #[test]
    fn the_bypass_is_reported_as_ignored_not_as_a_match() {
        let _g = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe { std::env::set_var("BEAMFS_CHAIN_IGNORE", "1") };
        with_seal(GOOD, || {
            let (v, _) = verify("bbbb", Path::new("/other")).expect("bypassed");
            assert_eq!(v, Verdict::Ignored);
        });
        unsafe { std::env::remove_var("BEAMFS_CHAIN_IGNORE") };
    }

    #[test]
    fn zero_and_false_do_not_bypass() {
        let _g = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for v in ["0", "false", "", "  "] {
            unsafe { std::env::set_var("BEAMFS_CHAIN_IGNORE", v) };
            assert!(!ignoring(), "{v:?} should not bypass");
        }
        unsafe { std::env::remove_var("BEAMFS_CHAIN_IGNORE") };
    }
}
