//! Host-side credential session priming and keep-alive.
//!
//! beamfs-bench runs sudo commands on the host (mount, umount, cp,
//! sha256sum on privileged files, perf record, virsh outside the
//! NOPASSWD scope, etc.) and signs the manifest via gpg at end of
//! pipeline. Long pipelines (`cmd_full` = 5-15 min, `cmd_mega` = up to
//! 30 min) can outlive the default sudo `timestamp_timeout` (5 min) and
//! the gpg-agent default-cache-ttl (3600 s for signing keys).
//!
//! Without priming, the operator faces interactive password prompts
//! mid-run, potentially blocking the pipeline indefinitely if not at
//! the keyboard. With priming + keep-alive, all credentials are
//! collected once at session start and refreshed transparently for
//! the entire run.
//!
//! ## Components
//!
//! 1. sudo -v : prompts the operator password once, populates the
//!    sudo timestamp file, refreshed by every subsequent sudo call
//!    (which the bench performs continuously). A keep-alive thread
//!    additionally calls `sudo -n true` every 4 minutes as a defence
//!    in depth against quiet windows in the pipeline.
//!
//! 2. GPG cache : checks `gpg-connect-agent KEYINFO --list /bye` ; if
//!    state == "P" (no cache), triggers an interactive `gpg --sign`
//!    on a throwaway buffer to populate the cache via pinentry-curses.
//!    A keep-alive thread calls `gpg-connect-agent NOP /bye` every
//!    30 minutes to keep the cache from auto-clearing on idle.
//!
//! 3. ssh-agent (optional) : if ~/.`ssh/id_ed25519` exists and is
//!    passphrase-protected, ensures it is loaded in ssh-agent. Only
//!    relevant for future scopes that may push manifests upstream.
//!    Not required for the current bench (cluster keys `hpclab_admin`
//!    are passphrase-less).
//!
//! ## Invocation
//!
//! Call `prime_session()` once at the very start of `main()` before
//! any command dispatch (except Version which does no I/O). The
//! function is idempotent : if credentials are already cached, it
//! returns immediately with no prompt.
//!
//! The keep-alive thread is detached and runs for the lifetime of
//! the process. It exits cleanly when the main thread exits.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::io::Write;

const SUDO_KEEPALIVE_INTERVAL: Duration = Duration::from_mins(4); // 4 min
const GPG_KEEPALIVE_INTERVAL:  Duration = Duration::from_mins(30); // 30 min

/// Prime sudo + GPG + ssh-agent caches and spawn keep-alive threads.
///
/// Idempotent : safe to call multiple times. Returns Ok(()) on success
/// even if some components could not be primed (for example, gpg-agent
/// not running) ; only fatal errors that prevent the bench from running
/// at all bubble up.
pub fn prime_session() -> Result<()> {
    println!("================================================================");
    println!(" beamfs-bench session priming (sudo + GPG + ssh-agent)");
    println!("================================================================");

    // 1. sudo -v
    prime_sudo().context("sudo session priming")?;

    // 2. GPG cache (best-effort : warn but do not fail if gpg unavailable)
    if let Err(e) = prime_gpg() {
        eprintln!("[priming] GPG cache priming skipped: {e:#}");
    }

    // 3. ssh-agent (best-effort)
    if let Err(e) = prime_ssh() {
        eprintln!("[priming] ssh-agent priming skipped: {e:#}");
    }

    // 4. spawn keep-alive thread
    let alive = Arc::new(AtomicBool::new(true));
    spawn_keepalive(alive);

    println!("[priming] credentials primed, keep-alive thread spawned");
    println!();
    Ok(())
}

fn prime_sudo() -> Result<()> {
    print!("[priming] sudo session check... ");
    std::io::stdout().flush().ok();

    // v0.8.3 : detect NOPASSWD before invoking sudo -v.
    // sudo -v requires a TTY for password input even when NOPASSWD
    // is active (sudo only short-circuits -v in narrow conditions
    // depending on version + plugin). Without a TTY (nohup/setsid
    // detached batch run), sudo -v fails with -EIO and aborts the
    // bench. Test sudo -n true first : if it succeeds, NOPASSWD is
    // active for this user and no -v refresh is needed.
    let nopasswd = Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if nopasswd {
        println!("NOPASSWD detected, skipping -v refresh");
        return Ok(());
    }

    print!("(NOPASSWD not set, invoking sudo -v) ");
    std::io::stdout().flush().ok();
    let status = Command::new("sudo")
        .arg("-v")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("spawn sudo -v")?;
    if !status.success() {
        anyhow::bail!("sudo -v returned {status} (operator declined or wrong password)");
    }
    println!("OK");
    Ok(())
}

fn prime_gpg() -> Result<()> {
    print!("[priming] checking gpg-agent cache state... ");
    std::io::stdout().flush().ok();
    let out = Command::new("gpg-connect-agent")
        .args(["KEYINFO --list", "/bye"])
        .env("PAGER", "cat")
        .output()
        .context("spawn gpg-connect-agent")?;
    if !out.status.success() {
        anyhow::bail!(
            "gpg-connect-agent failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut any_primed = false;
    for line in stdout.lines() {
        if !line.starts_with("S KEYINFO ") { continue; }
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() >= 7 && toks[6] == "1" {
            any_primed = true;
            break;
        }
    }
    if any_primed {
        println!("primed");
        return Ok(());
    }
    println!("empty, triggering interactive sign");

    // Trigger interactive sign to populate cache.
    let mut child = Command::new("gpg")
        .args(["--clearsign", "--armor", "-o", "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn gpg --clearsign")?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(b"beamfs-bench session priming\n")
            .context("write to gpg stdin")?;
    }
    let status = child.wait().context("wait gpg")?;
    if !status.success() {
        anyhow::bail!("gpg sign returned {status} (passphrase declined)");
    }
    println!("[priming] gpg cache populated");
    Ok(())
}

fn prime_ssh() -> Result<()> {
    let home: PathBuf = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME not set")?;
    let key = home.join(".ssh/id_ed25519");
    if !key.exists() {
        return Ok(()); // no key, nothing to prime
    }
    // Check ssh-agent reachable
    if std::env::var("SSH_AUTH_SOCK").is_err() {
        anyhow::bail!("SSH_AUTH_SOCK not set, ssh-agent not running");
    }
    let listed = Command::new("ssh-add")
        .arg("-l")
        .output()
        .context("ssh-add -l")?;
    let stdout = String::from_utf8_lossy(&listed.stdout);
    if stdout.contains("ED25519") || stdout.contains("RSA") || stdout.contains("ECDSA") {
        return Ok(()); // already loaded
    }
    print!("[priming] ssh-add {}... ", key.display());
    std::io::stdout().flush().ok();
    let status = Command::new("ssh-add")
        .arg(&key)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("ssh-add")?;
    if !status.success() {
        anyhow::bail!("ssh-add returned {status}");
    }
    println!("OK");
    Ok(())
}

fn spawn_keepalive(alive: Arc<AtomicBool>) {
    let alive2 = Arc::clone(&alive);
    thread::spawn(move || {
        let mut last_sudo = std::time::Instant::now();
        let mut last_gpg  = std::time::Instant::now();
        while alive2.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(30));
            if last_sudo.elapsed() >= SUDO_KEEPALIVE_INTERVAL {
                let _ = Command::new("sudo")
                    .args(["-n", "true"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                last_sudo = std::time::Instant::now();
            }
            if last_gpg.elapsed() >= GPG_KEEPALIVE_INTERVAL {
                let _ = Command::new("gpg-connect-agent")
                    .args(["NOP", "/bye"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                last_gpg = std::time::Instant::now();
            }
        }
    });
}
