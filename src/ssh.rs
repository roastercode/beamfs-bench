//! ssh.rs — SSH/SCP wrapper using std::process::Command.
//!
//! Mirrors exactly what Tir-multifs.sh does:
//!   ssh $SSH_OPTS user@host "cmd"
//!   scp $SSH_OPTS file user@host:dest
//!
//! No fancy session reuse, no async. Each call spawns ssh. Same semantics
//! as the bash, same failure modes, same exit codes propagated.

use anyhow::{anyhow, Context, Result};
use std::process::{Command, Stdio};

/// SSH connection target.
pub struct SshTarget {
    pub user: String,
    pub host: String,
    pub key_path: String,
}

impl SshTarget {
    pub fn new(user: &str, host: &str, key_path: &str) -> Self {
        Self {
            user: user.to_string(),
            host: host.to_string(),
            key_path: key_path.to_string(),
        }
    }

    /// Standard SSH options used throughout the harness. Mirror bash:
    ///   -o StrictHostKeyChecking=no
    ///   -o UserKnownHostsFile=/dev/null
    ///   -o LogLevel=ERROR
    ///   -i <key_path>
    fn opts(&self) -> Vec<String> {
        vec![
            "-o".into(), "StrictHostKeyChecking=no".into(),
            "-o".into(), "UserKnownHostsFile=/dev/null".into(),
            "-o".into(), "LogLevel=ERROR".into(),
            "-i".into(), self.key_path.clone(),
        ]
    }

    fn user_at_host(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// Execute a remote command. Captures stdout (trimmed of trailing
    /// newlines) and returns it. Stderr is captured but currently
    /// discarded; if needed for debugging, set BEAMFS_BENCH_DEBUG_SSH=1
    /// in the environment to print stderr to our own stderr.
    pub fn exec(&self, remote_cmd: &str) -> Result<String> {
        let mut cmd = Command::new("ssh");
        for opt in self.opts() {
            cmd.arg(opt);
        }
        cmd.arg(self.user_at_host());
        cmd.arg(remote_cmd);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = cmd.output()
            .with_context(|| format!("failed to spawn ssh for {}", self.user_at_host()))?;

        if std::env::var("BEAMFS_BENCH_DEBUG_SSH").is_ok() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                eprintln!("beamfs-bench: ssh stderr: {}", stderr.trim_end());
            }
        }

        if !output.status.success() {
            return Err(anyhow!(
                "ssh {} failed (exit {:?}): {}",
                self.user_at_host(),
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.trim_end_matches('\n').to_string())
    }

    /// Same as exec() but tolerates a non-zero exit and still returns
    /// stdout. Used for verify/attack actions where the worker may
    /// legitimately exit non-zero on FS_PANIC etc. but its stdout is
    /// still the verdict line we need.
    pub fn exec_lenient(&self, remote_cmd: &str) -> Result<String> {
        let mut cmd = Command::new("ssh");
        for opt in self.opts() {
            cmd.arg(opt);
        }
        cmd.arg(self.user_at_host());
        cmd.arg(remote_cmd);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = cmd.output()
            .with_context(|| format!("failed to spawn ssh for {}", self.user_at_host()))?;

        if std::env::var("BEAMFS_BENCH_DEBUG_SSH").is_ok() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                eprintln!("beamfs-bench: ssh stderr: {}", stderr.trim_end());
            }
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.trim_end_matches('\n').to_string())
    }

    /// Copy a local file to remote. Mirror of scp behaviour.
    pub fn scp_to(&self, local_path: &str, remote_path: &str) -> Result<()> {
        let mut cmd = Command::new("scp");
        for opt in self.opts() {
            cmd.arg(opt);
        }
        cmd.arg(local_path);
        cmd.arg(format!("{}:{}", self.user_at_host(), remote_path));
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());

        let output = cmd.output()
            .with_context(|| format!("failed to spawn scp to {}:{}", self.user_at_host(), remote_path))?;

        if !output.status.success() {
            return Err(anyhow!(
                "scp to {}:{} failed: {}",
                self.user_at_host(),
                remote_path,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }
}
