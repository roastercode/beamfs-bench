// SPDX-License-Identifier: GPL-2.0-only
//
// Author: Aurelien DESBRIERES <aurelien@hackers.camp>

//! What a kernel patch series has to pass before it is mailed.
//!
//! On 2026-10-09 the beamfs RFC series was checked by hand, patch by
//! patch, and checkpatch found ten lines over 100 columns in code that
//! every pipeline had passed. The code analysis gate could not have seen
//! them: it ran the host kernel's checkpatch with --no-tree, so spdxcheck
//! never ran; in --file mode, where a long line is a CHECK and not a
//! WARNING; and it counted ERROR lines only. The other checks of that
//! day -- trailers, subject lengths, mail sizes, MAINTAINERS, the builds,
//! the documentation -- existed nowhere but in a shell script written
//! for the occasion.
//!
//! `beamfs-bench upstream` runs them on the series itself, from the
//! kernel repository that holds its branch, together with the part of
//! Documentation/process/submit-checklist.rst that can be checked
//! without booting: sparse, checkstack, kernel-doc, the documentation of
//! the userspace interfaces, builds at =m and =y under several
//! configurations, with clang, allnoconfig and allmodconfig, on arm64,
//! and on the newer trees. The runtime half of the checklist -- debug
//! kernels, lockdep, fault injection -- belongs to BX, on a kernel the
//! bitbake chain built.
//!
//! The code analysis gate runs its checkpatch through
//! [`checkpatch_module`], the same way.
//!
//! A check whose tool cannot run fails. A spdxcheck that does not start
//! says nothing, and that silence is how it went unnoticed.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::Instant;

/// Longest subject a mail keeps whole, its PATCH nn/NN prefix included.
const SUBJECT_MAX: usize = 60;

/// Author of the synthetic patch the code analysis gate checks.
const MODULE_AUTHOR: &str = "Aurelien DESBRIERES <aurelien@hackers.camp>";

/// Cross compilers looked for, in this order, for the arm64 build.
const CROSS_PREFIXES: [&str; 2] = ["aarch64-unknown-linux-gnu-", "aarch64-linux-gnu-"];

/// Where linux-next is fetched from.
const LINUX_NEXT: &str = "https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git";

/// Where kernel-doc may live in the tree, the documentation tools having
/// moved between releases.
const KERNEL_DOC: [&str; 3] = [
    "scripts/kernel-doc",
    "tools/docs/kernel-doc",
    "scripts/kernel-doc.py",
];

/// Where checkstack.pl may live in the tree.
const CHECKSTACK: [&str; 2] = ["scripts/checkstack.pl", "tools/scripts/checkstack.pl"];

/// Macros that declare a module parameter.
const PARAM_MACROS: [&str; 9] = [
    "module_param",
    "module_param_named",
    "module_param_cb",
    "module_param_unsafe",
    "module_param_named_unsafe",
    "module_param_string",
    "module_param_array",
    "module_param_array_named",
    "module_param_call",
];

/// What a run is asked to check.
pub struct Config {
    /// Kernel repository holding the series branch.
    pub linux: PathBuf,
    /// The beamfs repository, sources at its root.
    pub beamfs: PathBuf,
    /// Branch carrying the series.
    pub series: String,
    /// Commit the series is based on.
    pub base: String,
    /// beamfs commit whose sources the series carries, byte for byte.
    pub measured: String,
    /// beamfs commit whose compiled code the series must reproduce.
    pub same_text_as: Option<String>,
    /// Directory of the filesystem under fs/.
    pub fs: String,
    /// Revisions the series must still merge into and build on.
    pub newer: Vec<String>,
    /// Fetch the remotes of the newer revisions first.
    pub fetch: bool,
    /// Subject prefix of the mails, "PATCH" or "RFC PATCH".
    pub subject_prefix: String,
    /// Author, From and Signed-off-by of every patch.
    pub author: String,
    /// Value of the Assisted-by line every patch carries; empty for none.
    pub assisted_by: String,
    /// Largest mail accepted, in bytes.
    pub max_mail_bytes: u64,
    /// Whether the --strict CHECKs of checkpatch block as well.
    pub strict_blocking: bool,
    /// Whether arm64 is built here, with a cross compiler.
    pub cross: bool,
    /// Largest stack frame accepted, in bytes.
    pub stack_limit: u64,
    /// Where the patches, the logs and the summary go; absolute.
    pub out: PathBuf,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub summary: String,
    pub details: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub bench_version: &'static str,
    pub started_at: String,
    pub finished_at: String,
    pub linux: String,
    pub series: String,
    pub series_tip: String,
    pub base: String,
    pub base_sha: String,
    pub measured: String,
    pub measured_sha: String,
    pub same_text_as: Option<String>,
    pub newer: Vec<String>,
    pub patches: Vec<String>,
    pub checks: Vec<Check>,
    pub pass: bool,
}

/// What the code analysis gate learns from checkpatch.
pub struct ModuleCheck {
    /// Every ERROR and WARNING line; empty when the gate passes.
    pub blocking: Vec<String>,
    /// Both runs in full, and the CHECK lines counted by type.
    pub log: PathBuf,
}

/// The kernel repository: `BEAMFS_BENCH_LINUX_REPO`, or ~/git/linux.
#[must_use]
pub fn linux_repo() -> PathBuf {
    if let Ok(v) = std::env::var("BEAMFS_BENCH_LINUX_REPO") {
        let v = v.trim();
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/aurelien".to_string());
    PathBuf::from(format!("{home}/git/linux"))
}

/// The default output directory of a run on `series`.
#[must_use]
pub fn default_out(series: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/aurelien".to_string());
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    PathBuf::from(format!(
        "{home}/.local/share/beamfs-bench/upstream/{series}-{stamp}"
    ))
}

// ------------------------------------------------------------------
// Small helpers
// ------------------------------------------------------------------

fn ms(t0: Instant) -> u64 {
    u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn short(s: &str) -> &str {
    s.get(..12).unwrap_or(s)
}

fn is_source(n: &str) -> bool {
    (n.ends_with(".c") || n.ends_with(".h")) && !n.ends_with(".mod.c")
}

fn jobs() -> usize {
    std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get)
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|c| c.is_file())
}

fn tree_script(tree: &Path, candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(|c| tree.join(c))
        .find(|p| p.is_file())
}

fn output(cmd: &mut Command) -> Result<Output> {
    let what = format!("{cmd:?}");
    cmd.output().with_context(|| format!("cannot run {what}"))
}

fn lossy(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn read_lossy(p: &Path) -> Option<String> {
    std::fs::read(p)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn dir_names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn lines_of(s: &str) -> Vec<String> {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let o = output(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("--no-pager")
            .args(args),
    )?;
    if !o.status.success() {
        bail!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim_end().to_string())
}

fn git_bytes(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let o = output(Command::new("git").arg("-C").arg(repo).args(args))?;
    if !o.status.success() {
        bail!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(o.stdout)
}

fn resolve(repo: &Path, rev: &str) -> Result<String> {
    git(
        repo,
        &["rev-parse", "--verify", "--quiet", &format!("{rev}^{{commit}}")],
    )
    .with_context(|| format!("{rev} does not name a commit in {}", repo.display()))
}

fn finish(
    name: &'static str,
    t0: Instant,
    problems: Vec<String>,
    ok: String,
    notes: Vec<String>,
) -> Check {
    let status = if problems.is_empty() {
        Status::Pass
    } else {
        Status::Fail
    };
    let summary = if problems.is_empty() {
        ok
    } else {
        format!("{} problem(s)", problems.len())
    };
    let mut details = problems;
    details.extend(notes);
    Check {
        name,
        status,
        summary,
        details,
        duration_ms: ms(t0),
    }
}

fn skip(name: &'static str, t0: Instant, why: String) -> Check {
    Check {
        name,
        status: Status::Skip,
        summary: why,
        details: Vec::new(),
        duration_ms: ms(t0),
    }
}

fn check_lines(c: &Check) -> String {
    let tag = match c.status {
        Status::Pass => "PASS",
        Status::Fail => "FAIL",
        Status::Skip => "SKIP",
    };
    let mut r = format!(
        "  [{tag}] {:<14} {} ({} s)\n",
        c.name,
        c.summary,
        c.duration_ms / 1000
    );
    for d in &c.details {
        let _ = writeln!(r, "           {d}");
    }
    r
}

fn print_check(c: &Check) {
    print!("{}", check_lines(c));
}

/// Said before a check that takes minutes, so that the terminal is not
/// silent while it runs.
fn begin(name: &str, what: &str) {
    println!("  [ .. ] {name:<14} {what}");
}

/// A detached worktree of the kernel, removed when it goes out of scope.
struct Worktree {
    repo: PathBuf,
    path: PathBuf,
}

impl Worktree {
    fn add(repo: &Path, path: &Path, rev: &str) -> Result<Self> {
        if path.exists() {
            bail!("{} exists already", path.display());
        }
        let p = path_str(path);
        git(repo, &["worktree", "add", "--detach", "-q", &p, rev])?;
        Ok(Self {
            repo: repo.to_path_buf(),
            path: path.to_path_buf(),
        })
    }
}

impl Drop for Worktree {
    fn drop(&mut self) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.repo)
            .args(["worktree", "remove", "--force"])
            .arg(&self.path)
            .output();
    }
}

// ------------------------------------------------------------------
// Pure parsing, tested below
// ------------------------------------------------------------------

/// The subject a patch carries once git format-patch has numbered it.
fn mail_subject(prefix: &str, n: usize, total: usize, subject: &str) -> String {
    let w = total.to_string().len();
    format!("[{prefix} {n:0w$}/{total}] {subject}")
}

/// Typographic dashes and quotes, by line.
fn forbidden_chars(text: &str) -> Vec<String> {
    let mut v = Vec::new();
    for (i, line) in text.lines().enumerate() {
        for &(ch, label) in crate::code_analysis::FORBIDDEN_R16 {
            if line.contains(ch) {
                v.push(format!("line {}: {label}", i + 1));
            }
        }
    }
    v
}

/// Numbers of the lines that are not plain ASCII.
fn non_ascii_lines(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.is_ascii())
        .map(|(i, _)| i + 1)
        .collect()
}

/// What is wrong with a commit message, if anything.
fn message_findings(msg: &str, author: &str, assisted_by: &str) -> Vec<String> {
    let mut v = Vec::new();
    let lines: Vec<&str> = msg.lines().map(str::trim_end).collect();
    let signoff = format!("Signed-off-by: {author}");
    if !lines.contains(&signoff.as_str()) {
        v.push(format!("no line \"{signoff}\""));
    }
    if !assisted_by.is_empty() {
        let a = format!("Assisted-by: {assisted_by}");
        if !lines.contains(&a.as_str()) {
            v.push(format!("no line \"{a}\""));
        }
    }
    for l in &lines {
        let low = l.to_ascii_lowercase();
        if low.starts_with("co-authored-by:") {
            v.push(format!("Co-Authored-By line: {l}"));
        }
        if low.contains("claude-session") {
            v.push(format!("session link: {l}"));
        }
    }
    v.extend(forbidden_chars(msg));
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    level: String,
    kind: String,
    line: String,
}

/// checkpatch --terse --show-types --showfile output, one finding a line.
fn parse_checkpatch(out: &str) -> Vec<Finding> {
    let mut v = Vec::new();
    for line in out.lines() {
        for level in ["ERROR", "WARNING", "CHECK"] {
            let tag = format!(": {level}:");
            if let Some(i) = line.find(&tag) {
                let rest = &line[i + tag.len()..];
                let kind = rest.split(':').next().unwrap_or("").trim().to_string();
                v.push(Finding {
                    level: level.to_string(),
                    kind,
                    line: line.to_string(),
                });
                break;
            }
        }
    }
    v
}

/// Whether spdxcheck died under checkpatch, which checkpatch does not
/// report as a finding.
fn spdx_failed(stderr: &str) -> bool {
    stderr.contains("Traceback")
        || stderr.contains("ModuleNotFoundError")
        || stderr.contains("No module named")
}

/// Placeholders a cover letter must not carry when it is mailed.
fn placeholders(text: &str) -> Vec<String> {
    let mut v = Vec::new();
    for line in text.lines() {
        if line.contains("*** SUBJECT HERE ***") || line.contains("*** BLURB HERE ***") {
            v.push(line.trim().to_string());
            continue;
        }
        let mut rest = line;
        while let Some(i) = rest.find("@@") {
            let after = &rest[i + 2..];
            let Some(j) = after.find("@@") else { break };
            let inner = &after[..j];
            if !inner.is_empty()
                && inner
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            {
                v.push(format!("@@{inner}@@"));
            }
            rest = &after[j + 2..];
        }
    }
    v
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct KconfigEntry {
    name: String,
    kind: String,
    prompt: bool,
    help_lines: usize,
    defaults: Vec<String>,
}

/// Columns of leading whitespace, a tab to the next multiple of eight.
fn indent_of(line: &str) -> usize {
    let mut n = 0;
    for c in line.chars() {
        match c {
            ' ' => n += 1,
            '\t' => n = (n / 8 + 1) * 8,
            _ => break,
        }
    }
    n
}

/// The config entries of a Kconfig file: type, prompt, help, defaults.
fn kconfig_entries(text: &str) -> Vec<KconfigEntry> {
    let mut v: Vec<KconfigEntry> = Vec::new();
    let mut help: Option<usize> = None;
    let mut current = false;
    for line in text.lines() {
        let t = line.trim();
        if let Some(kw) = help {
            if t.is_empty() {
                continue;
            }
            if indent_of(line) > kw {
                if let Some(e) = v.last_mut() {
                    e.help_lines += 1;
                }
                continue;
            }
            help = None;
        }
        let first = t.split_whitespace().next().unwrap_or("");
        if first == "config" || first == "menuconfig" {
            let name = t[first.len()..].trim().to_string();
            v.push(KconfigEntry {
                name,
                ..KconfigEntry::default()
            });
            current = true;
            continue;
        }
        if matches!(
            first,
            "menu" | "endmenu" | "if" | "endif" | "source" | "choice" | "endchoice" | "comment"
                | "mainmenu"
        ) {
            current = false;
            continue;
        }
        if !current {
            continue;
        }
        let Some(e) = v.last_mut() else { continue };
        if t == "help" || t == "---help---" {
            help = Some(indent_of(line));
            continue;
        }
        let rest = t[first.len()..].trim();
        match first {
            "tristate" | "bool" => {
                e.kind = first.to_string();
                if rest.starts_with('"') {
                    e.prompt = true;
                }
            }
            "def_bool" => e.kind = "bool".to_string(),
            "def_tristate" => e.kind = "tristate".to_string(),
            "prompt" => e.prompt = true,
            "default" => e.defaults.push(rest.to_string()),
            _ => {}
        }
    }
    v
}

/// The value a .config gives a symbol: y, m, n, or v for anything else.
fn config_value(config: &str, sym: &str) -> char {
    let on = format!("CONFIG_{sym}=");
    for l in config.lines() {
        if let Some(v) = l.strip_prefix(&on) {
            return match v {
                "y" => 'y',
                "m" => 'm',
                _ => 'v',
            };
        }
    }
    'n'
}

/// Calls of the accepted macros, with their first argument when it is
/// an identifier. Macro definitions are skipped: their arguments are
/// parameters, not names.
fn macro_first_args(src: &str, accept: &dyn Fn(&str) -> bool) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut continued = false;
    for line in src.lines() {
        let in_define = continued || line.trim_start().starts_with("#define");
        continued = line.trim_end().ends_with('\\');
        if in_define {
            continue;
        }
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i].is_ascii_alphabetic() || b[i] == b'_' {
                let s = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                let ident = &line[s..i];
                if i < b.len() && b[i] == b'(' && accept(ident) {
                    let arg: String = line[i + 1..]
                        .trim_start()
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !arg.is_empty() {
                        out.push((ident.to_string(), arg));
                    }
                }
            } else {
                i += 1;
            }
        }
    }
    out
}

fn module_params(src: &str) -> BTreeSet<String> {
    macro_first_args(src, &|m: &str| PARAM_MACROS.contains(&m))
        .into_iter()
        .map(|(_, a)| a)
        .collect()
}

fn param_descriptions(src: &str) -> BTreeSet<String> {
    macro_first_args(src, &|m: &str| m == "MODULE_PARM_DESC")
        .into_iter()
        .map(|(_, a)| a)
        .collect()
}

fn is_attr_macro(m: &str) -> bool {
    ["ATTR", "ATTR_RO", "ATTR_RW", "ATTR_WO"]
        .iter()
        .any(|s| m.ends_with(s))
}

/// Names of the sysfs attributes the sources declare.
fn sysfs_attributes(src: &str) -> BTreeSet<String> {
    macro_first_args(src, &is_attr_macro)
        .into_iter()
        .map(|(_, a)| a)
        .filter(|a| !a.starts_with('_'))
        .collect()
}

fn has_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| text.contains(n))
}

/// Whether `text` names `/name` as a whole path component.
fn mentions_component(text: &str, name: &str) -> bool {
    let needle = format!("/{name}");
    text.match_indices(&needle).any(|(i, _)| {
        text[i + needle.len()..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
    })
}

/// Files laid out as one new-file patch, so that checkpatch reads them
/// as a reviewer will, at the levels it uses for patches.
fn module_patch(author: &str, files: &[(String, Vec<u8>)]) -> String {
    let mut p = String::new();
    let _ = writeln!(p, "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001");
    let _ = writeln!(p, "From: {author}");
    let _ = writeln!(p, "Subject: [PATCH] module sources, as one patch");
    let _ = writeln!(p);
    let _ = writeln!(p, "The module sources as a reviewer reads them, so that checkpatch");
    let _ = writeln!(p, "judges them at the levels it uses for patches.");
    let _ = writeln!(p);
    let _ = writeln!(p, "Signed-off-by: {author}");
    let _ = writeln!(p, "---");
    for (path, bytes) in files {
        let text = String::from_utf8_lossy(bytes);
        let _ = writeln!(p, "diff --git a/{path} b/{path}");
        let _ = writeln!(p, "new file mode 100644");
        if text.is_empty() {
            continue;
        }
        let ends_nl = text.ends_with('\n');
        let mut lines: Vec<&str> = text.split('\n').collect();
        if ends_nl {
            lines.pop();
        }
        let _ = writeln!(p, "--- /dev/null");
        let _ = writeln!(p, "+++ b/{path}");
        let _ = writeln!(p, "@@ -0,0 +1,{} @@", lines.len());
        for l in &lines {
            let _ = writeln!(p, "+{l}");
        }
        if !ends_nl {
            let _ = writeln!(p, "\\ No newline at end of file");
        }
    }
    p
}

/// Section names in readelf -S -W output.
fn section_names(readelf: &str) -> Vec<String> {
    readelf
        .lines()
        .filter_map(|l| {
            let (_, rest) = l.split_once("] ")?;
            rest.split_whitespace().next().map(str::to_string)
        })
        .filter(|n| n.starts_with('.'))
        .collect()
}

/// Sections that hold code: .text and its variants, .init.text and the
/// like.
fn is_text_section(n: &str) -> bool {
    !n.starts_with(".rel") && (n == ".text" || n.starts_with(".text.") || n.ends_with(".text"))
}

/// Relocations against the given sections in readelf -r -W output,
/// without the file offsets and symbol indexes that move when any other
/// section does.
fn relocs_of(readelf_r: &str, sections: &[String]) -> Vec<String> {
    let wanted: BTreeSet<String> = sections.iter().map(|s| format!(".rela{s}")).collect();
    let mut v = Vec::new();
    let mut current = String::new();
    for line in readelf_r.lines() {
        if let Some(rest) = line.strip_prefix("Relocation section '") {
            current = rest.split('\'').next().unwrap_or("").to_string();
            continue;
        }
        if !wanted.contains(&current) {
            continue;
        }
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 5 || !t[0].chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        v.push(format!("{current} {} {} {}", t[0], t[2], t[4..].join(" ")));
    }
    v
}

/// ":123:" replaced by ":N:", so that a warning that moved down a line
/// is still the same warning.
fn strip_line_numbers(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b':' {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 1 && j < b.len() && b[j] == b':' {
                out.push_str(":N");
                i = j;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Warnings and errors of a documentation build, counted, the tree's own
/// path and the line numbers taken out so that two trees compare.
fn doc_warnings(log: &str, tree: &str) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for l in log.lines().filter(|l| {
        l.contains("WARNING") || l.contains("ERROR") || l.contains("warning:") || l.contains("error:")
    }) {
        *m.entry(strip_line_numbers(l.replace(tree, "SRC").trim()))
            .or_insert(0) += 1;
    }
    m
}

/// What the series has more of than the base.
fn new_entries(series: &BTreeMap<String, usize>, base: &BTreeMap<String, usize>) -> Vec<String> {
    series
        .iter()
        .filter_map(|(k, &n)| {
            let b = base.get(k).copied().unwrap_or(0);
            (n > b).then(|| format!("{k} ({n}, {b} in the base)"))
        })
        .collect()
}

/// The SPHINXDIRS a change to these paths needs; "." for the whole tree.
fn doc_dirs(changed: &[String]) -> Vec<String> {
    let mut v = BTreeSet::new();
    for p in changed {
        let Some(rest) = p.strip_prefix("Documentation/") else {
            continue;
        };
        if rest.starts_with("ABI/") {
            v.insert("admin-guide".to_string());
            continue;
        }
        match rest.split_once('/') {
            Some((dir, _)) => {
                v.insert(dir.to_string());
            }
            None => {
                if rest.ends_with(".rst") {
                    v.insert(".".to_string());
                }
            }
        }
    }
    v.into_iter().collect()
}

/// Function and frame size from checkstack.pl output.
fn checkstack_entries(out: &str) -> Vec<(String, u64)> {
    out.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let size = t.last()?.parse::<u64>().ok()?;
            if t.len() < 3 {
                return None;
            }
            Some((format!("{} {}", t[1], t[2].trim_end_matches(':')), size))
        })
        .collect()
}

fn author_mail(author: &str) -> String {
    author
        .split_once('<')
        .and_then(|(_, r)| r.split_once('>'))
        .map_or_else(|| author.to_string(), |(m, _)| m.to_string())
}

fn is_diagnostic(l: &str) -> bool {
    l.contains("warning:") || l.contains("error:") || l.contains("WARNING:") || l.contains("ERROR:")
}

fn count_tagged(text: &str, tag: &str, fs: &str) -> usize {
    let needle = format!(" fs/{fs}/");
    text.lines()
        .filter(|l| l.trim_start().starts_with(tag) && l.contains(&needle))
        .count()
}

/// The remotes named by revisions such as origin/master.
fn remotes_of(newer: &[String]) -> Vec<String> {
    let mut v: Vec<String> = newer
        .iter()
        .filter_map(|r| r.split_once('/').map(|(a, _)| a.to_string()))
        .collect();
    v.sort();
    v.dedup();
    v
}

fn python_minor(name: &str) -> Option<u32> {
    let v = name.strip_prefix("python3.")?;
    if v.is_empty() || !v.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

// ------------------------------------------------------------------
// Python for spdxcheck
// ------------------------------------------------------------------

fn imports_ply_git(epython: Option<&str>) -> bool {
    let mut c = Command::new("python3");
    c.args(["-c", "import ply, git"]);
    if let Some(e) = epython {
        c.env("EPYTHON", e);
    }
    c.output().is_ok_and(|o| o.status.success())
}

fn python_candidates() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        for d in std::env::split_paths(&path) {
            let Ok(rd) = std::fs::read_dir(d) else {
                continue;
            };
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if python_minor(&n).is_some() {
                    v.push(n);
                }
            }
        }
    }
    v.sort_by_key(|n| std::cmp::Reverse(python_minor(n).unwrap_or(0)));
    v.dedup();
    v
}

/// The EPYTHON under which python3 imports ply and git; None when python3
/// does as it is.
///
/// spdxcheck imports both, and checkpatch runs it through whatever
/// python3 is: on this station python-exec chose 3.13 while the modules
/// were built for 3.14, and spdxcheck died at its first import with
/// nothing among checkpatch's findings to show it.
fn python_env() -> Result<Option<String>> {
    static FOUND: OnceLock<std::result::Result<Option<String>, String>> = OnceLock::new();
    FOUND
        .get_or_init(|| {
            if imports_ply_git(None) {
                return Ok(None);
            }
            let tried = python_candidates();
            if let Some(c) = tried.iter().find(|c| imports_ply_git(Some(c.as_str()))) {
                return Ok(Some(c.clone()));
            }
            Err(format!(
                "no python3 imports ply and git (EPYTHON tried: {}), so spdxcheck cannot run",
                if tried.is_empty() {
                    "none".to_string()
                } else {
                    tried.join(", ")
                }
            ))
        })
        .clone()
        .map_err(|e| anyhow!(e))
}

// ------------------------------------------------------------------
// checkpatch, shared with the code analysis gate
// ------------------------------------------------------------------

struct CheckpatchRun {
    findings: Vec<Finding>,
    raw: String,
}

/// Everything checkpatch needs to run in full in `tree`; the EPYTHON it
/// runs under, if any.
///
/// Without a git tree, or without a python3 that imports ply and git,
/// checkpatch skips spdxcheck and says nothing about it.
fn preflight_checkpatch(tree: &Path) -> Result<Option<String>> {
    for s in ["scripts/checkpatch.pl", "scripts/spdxcheck.py"] {
        if !tree.join(s).is_file() {
            bail!("{s} is not in {}", tree.display());
        }
    }
    if !tree.join(".git").exists() {
        bail!(
            "{} is not a git tree: checkpatch would skip spdxcheck without a word",
            tree.display()
        );
    }
    if which("python3").is_none() {
        bail!("python3 is not on PATH: checkpatch would skip spdxcheck without a word");
    }
    python_env()
}

fn checkpatch(tree: &Path, patch: &Path, extra: &[&str]) -> Result<CheckpatchRun> {
    let mut cmd = Command::new(tree.join("scripts/checkpatch.pl"));
    cmd.current_dir(tree)
        .args(["--terse", "--show-types", "--showfile", "--no-summary"])
        .args(extra)
        .arg(patch);
    if let Some(e) = python_env()? {
        cmd.env("EPYTHON", e);
    }
    let o = output(&mut cmd)?;
    let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    if spdx_failed(&stderr) {
        bail!("spdxcheck did not run under checkpatch: {}", stderr.trim());
    }
    if !stderr.trim().is_empty() {
        bail!("checkpatch wrote to stderr: {}", stderr.trim());
    }
    let findings = parse_checkpatch(&stdout);
    if !o.status.success() && findings.is_empty() {
        bail!(
            "checkpatch exited with {} and reported nothing: {}",
            o.status,
            stdout.trim()
        );
    }
    Ok(CheckpatchRun {
        findings,
        raw: stdout,
    })
}

/// checkpatch on the module sources of `beamfs`, laid out as one patch
/// under fs/`fs`, in the kernel tree `ksrc`.
///
/// FILE_PATH_CHANGES is ignored: the patch is synthetic and adds every
/// file by construction. Every other ERROR or WARNING blocks. Kconfig and
/// Makefile are left out: those at the root of the repository build the
/// module out of tree, and the series carries its own.
///
/// # Errors
///
/// When checkpatch cannot run in full, spdxcheck included.
pub fn checkpatch_module(ksrc: &Path, beamfs: &Path, fs: &str, out: &Path) -> Result<ModuleCheck> {
    preflight_checkpatch(ksrc)?;
    let names: Vec<String> = dir_names(beamfs)
        .into_iter()
        .filter(|n| is_source(n))
        .collect();
    if names.is_empty() {
        bail!("no source in {}", beamfs.display());
    }
    let mut files = Vec::new();
    for n in &names {
        let p = beamfs.join(n);
        let bytes = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
        files.push((format!("fs/{fs}/{n}"), bytes));
    }
    let patch = out.join("checkpatch-module.patch");
    std::fs::write(&patch, module_patch(MODULE_AUTHOR, &files).as_bytes())
        .with_context(|| format!("write {}", patch.display()))?;
    let normal = checkpatch(ksrc, &patch, &["--ignore", "FILE_PATH_CHANGES"])?;
    let strict = checkpatch(ksrc, &patch, &["--strict", "--ignore", "FILE_PATH_CHANGES"])?;
    let blocking: Vec<String> = normal
        .findings
        .iter()
        .filter(|f| f.level != "CHECK")
        .map(|f| f.line.clone())
        .collect();
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for f in strict.findings.iter().filter(|f| f.level == "CHECK") {
        *counts.entry(f.kind.as_str()).or_insert(0) += 1;
    }
    let mut log = format!(
        "kernel tree : {}\nfiles       : {}\n\n=== checkpatch\n{}\n=== checkpatch --strict\n{}\n=== CHECK by type\n",
        ksrc.display(),
        names.len(),
        normal.raw,
        strict.raw
    );
    for (k, n) in &counts {
        let _ = writeln!(log, "{n:>5} {k}");
    }
    let log_path = out.join("checkpatch.log");
    std::fs::write(&log_path, log.as_bytes())
        .with_context(|| format!("write {}", log_path.display()))?;
    Ok(ModuleCheck {
        blocking,
        log: log_path,
    })
}

// ------------------------------------------------------------------
// The run
// ------------------------------------------------------------------

struct Ctx<'a> {
    cfg: &'a Config,
    tree: PathBuf,
    tip: String,
    base_sha: String,
    measured_sha: String,
    text_sha: Option<String>,
    commits: Vec<String>,
    patches: Vec<PathBuf>,
    cover: Option<PathBuf>,
    changed: Vec<String>,
    added: Vec<String>,
    main_symbol: Option<String>,
    bools: Vec<String>,
    cross: Option<&'static str>,
}

impl Ctx<'_> {
    fn logs(&self) -> PathBuf {
        self.cfg.out.join("logs")
    }

    fn fs_dir(&self) -> PathBuf {
        self.tree.join("fs").join(&self.cfg.fs)
    }
}

/// Check the series `cfg` names. 0 when every check passes, 3 otherwise.
///
/// # Errors
///
/// When the series cannot be read at all: a revision that does not
/// resolve, a base that is not an ancestor, an output directory in use.
pub fn run(cfg: &Config) -> Result<i32> {
    let started_at = chrono::Utc::now().to_rfc3339();
    println!("================================================================");
    println!(" beamfs-bench upstream - {} over {}", cfg.series, cfg.base);
    println!("================================================================");
    if !cfg.out.is_absolute() {
        bail!("{}: --out takes an absolute path", cfg.out.display());
    }
    if cfg.out.exists() {
        bail!(
            "{} exists already; each run writes a directory of its own",
            cfg.out.display()
        );
    }
    std::fs::create_dir_all(cfg.out.join("logs"))
        .with_context(|| format!("create {}", cfg.out.display()))?;

    let mut checks: Vec<Check> = Vec::new();
    if cfg.fetch {
        begin("fetch", "the remotes of the newer revisions");
        let c = check_fetch(cfg);
        print_check(&c);
        checks.push(c);
    }

    let tip = resolve(&cfg.linux, &cfg.series)?;
    let base_sha = resolve(&cfg.linux, &cfg.base)?;
    let measured_sha = resolve(&cfg.beamfs, &cfg.measured)?;
    let text_sha = cfg
        .same_text_as
        .as_deref()
        .map(|r| resolve(&cfg.beamfs, r))
        .transpose()?;
    let anc = output(
        Command::new("git")
            .arg("-C")
            .arg(&cfg.linux)
            .args(["merge-base", "--is-ancestor", &base_sha, &tip]),
    )?;
    if !anc.status.success() {
        bail!("{} is not an ancestor of {}", cfg.base, cfg.series);
    }
    let range = format!("{base_sha}..{tip}");
    let commits = lines_of(&git(&cfg.linux, &["rev-list", "--reverse", &range])?);
    if commits.is_empty() {
        bail!("{} has no commit over {}", cfg.series, cfg.base);
    }
    let changed = lines_of(&git(&cfg.linux, &["diff", "--name-only", &base_sha, &tip])?);
    let added = lines_of(&git(
        &cfg.linux,
        &["diff", "--diff-filter=A", "--name-only", &base_sha, &tip],
    )?);
    println!(
        "  series   : {} ({} commits, tip {})",
        cfg.series,
        commits.len(),
        short(&tip)
    );
    println!("  base     : {} ({})", cfg.base, short(&base_sha));
    println!("  measured : {} ({})", cfg.measured, short(&measured_sha));
    if let Some(t) = &text_sha {
        println!("  text of  : {}", short(t));
    }
    println!("  out      : {}", cfg.out.display());
    println!();

    let tree = Worktree::add(&cfg.linux, &cfg.out.join("tree"), &tip)?;
    let pdir = cfg.out.join("patches");
    git(
        &cfg.linux,
        &[
            "format-patch",
            "-q",
            "--cover-letter",
            "--cover-from-description=subject",
            &format!("--subject-prefix={}", cfg.subject_prefix),
            &format!("--base={base_sha}"),
            "-o",
            &path_str(&pdir),
            &format!("{base_sha}..{}", cfg.series),
        ],
    )?;
    let mut all: Vec<PathBuf> = std::fs::read_dir(&pdir)
        .with_context(|| format!("read {}", pdir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "patch"))
        .collect();
    all.sort();
    let cover = all
        .iter()
        .find(|p| file_name(p).starts_with("0000-"))
        .cloned();
    let patches: Vec<PathBuf> = all
        .into_iter()
        .filter(|p| !file_name(p).starts_with("0000-"))
        .collect();

    let entries = kconfig_entries(
        &read_lossy(&tree.path.join("fs").join(&cfg.fs).join("Kconfig")).unwrap_or_default(),
    );
    let main_symbol = entries
        .iter()
        .find(|e| e.kind == "tristate")
        .map(|e| e.name.clone());
    let bools: Vec<String> = entries
        .iter()
        .filter(|e| e.kind == "bool" && e.prompt)
        .map(|e| e.name.clone())
        .collect();
    let cross = if cfg.cross {
        CROSS_PREFIXES
            .into_iter()
            .find(|p| which(&format!("{p}gcc")).is_some())
    } else {
        None
    };

    let ctx = Ctx {
        cfg,
        tree: tree.path.clone(),
        tip: tip.clone(),
        base_sha: base_sha.clone(),
        measured_sha: measured_sha.clone(),
        text_sha: text_sha.clone(),
        commits,
        patches,
        cover,
        changed,
        added,
        main_symbol,
        bools,
        cross,
    };

    {
        let mut add = |c: Check| {
            print_check(&c);
            checks.push(c);
        };
        add(check_tools(&ctx));
        add(check_identity(&ctx));
        add(check_commits(&ctx));
        begin(
            "checkpatch",
            &format!("{} patches, with and without --strict", ctx.patches.len()),
        );
        add(check_checkpatch(&ctx));
        add(check_sizes(&ctx));
        add(check_prose(&ctx));
        add(check_maintainers(&ctx));
        add(check_kconfig(&ctx));
        add(check_interfaces(&ctx));
        check_builds(&ctx, &mut add);
        begin("docs", "htmldocs and refcheckdocs, on the series and on its base");
        add(check_docs(&ctx));
    }

    let patch_names: Vec<String> = ctx
        .cover
        .iter()
        .chain(ctx.patches.iter())
        .map(|p| file_name(p.as_path()))
        .collect();
    drop(tree);
    remove_scratch(&cfg.out);

    let pass = checks.iter().all(|c| c.status != Status::Fail);
    let summary = Summary {
        bench_version: env!("CARGO_PKG_VERSION"),
        started_at,
        finished_at: chrono::Utc::now().to_rfc3339(),
        linux: path_str(&cfg.linux),
        series: cfg.series.clone(),
        series_tip: tip,
        base: cfg.base.clone(),
        base_sha,
        measured: cfg.measured.clone(),
        measured_sha,
        same_text_as: text_sha,
        newer: cfg.newer.clone(),
        patches: patch_names,
        checks,
        pass,
    };
    let json_path = cfg.out.join("upstream-summary.json");
    std::fs::write(&json_path, serde_json::to_string_pretty(&summary)?.as_bytes())
        .with_context(|| format!("write {}", json_path.display()))?;
    let report_path = cfg.out.join("upstream-report.txt");
    std::fs::write(&report_path, render(&summary).as_bytes())
        .with_context(|| format!("write {}", report_path.display()))?;
    if crate::pipeline::gpg_key_cached() {
        match crate::pipeline::sign_manifest(&["gpg"], &json_path, crate::pipeline::SIGN_TIMEOUT) {
            Ok(asc) => println!("  summary signed : {}", asc.display()),
            Err(e) => eprintln!(
                "  summary NOT signed: {e}; gpg --detach-sign --armor {}",
                json_path.display()
            ),
        }
    } else {
        eprintln!(
            "  summary NOT signed: no key in gpg-agent's cache; gpg --detach-sign --armor {}",
            json_path.display()
        );
    }
    let failed = summary
        .checks
        .iter()
        .filter(|c| c.status == Status::Fail)
        .count();
    println!();
    println!("  patches : {}", pdir.display());
    println!("  summary : {}", json_path.display());
    println!("  report  : {}", report_path.display());
    println!("================================================================");
    if pass {
        println!(" beamfs-bench upstream: every check passed");
    } else {
        println!(" beamfs-bench upstream: {failed} check(s) failed");
    }
    println!("================================================================");
    Ok(if pass { 0 } else { 3 })
}

fn render(s: &Summary) -> String {
    let mut r = String::new();
    let _ = writeln!(r, "beamfs-bench {} upstream", s.bench_version);
    let _ = writeln!(r, "series   {} {}", s.series, s.series_tip);
    let _ = writeln!(r, "base     {} {}", s.base, s.base_sha);
    let _ = writeln!(r, "measured {} {}", s.measured, s.measured_sha);
    if let Some(t) = &s.same_text_as {
        let _ = writeln!(r, "text of  {t}");
    }
    let _ = writeln!(r, "newer    {}", s.newer.join(", "));
    let _ = writeln!(r, "started  {}", s.started_at);
    let _ = writeln!(r, "finished {}", s.finished_at);
    let _ = writeln!(r);
    for c in &s.checks {
        r.push_str(&check_lines(c));
    }
    let _ = writeln!(r);
    let _ = writeln!(r, "{}", if s.pass { "PASS" } else { "FAIL" });
    r
}

/// Build trees and documentation output are large and say nothing the
/// logs do not; the worktrees are removed by their guards.
fn remove_scratch(out: &Path) {
    for n in dir_names(out) {
        if n.starts_with("build-") || n.starts_with("doc-") || n == "text-scratch" {
            let _ = std::fs::remove_dir_all(out.join(n));
        }
    }
}

fn discard(ctx: &Ctx, dir: &str) {
    let _ = std::fs::remove_dir_all(ctx.cfg.out.join(dir));
}

// ------------------------------------------------------------------
// The checks
// ------------------------------------------------------------------

fn check_fetch(cfg: &Config) -> Check {
    let t0 = Instant::now();
    let listing = git(&cfg.linux, &["remote"]).unwrap_or_default();
    let known: BTreeSet<&str> = listing.lines().map(str::trim).collect();
    let mut problems = Vec::new();
    let mut fetched = Vec::new();
    for r in remotes_of(&cfg.newer) {
        if !known.contains(r.as_str()) {
            if r.contains("next") {
                problems.push(format!("no remote {r}; git remote add {r} {LINUX_NEXT}"));
            }
            continue;
        }
        match git(&cfg.linux, &["fetch", "-q", &r]) {
            Ok(_) => fetched.push(r),
            Err(e) => problems.push(format!("{e:#}")),
        }
    }
    let what = if fetched.is_empty() {
        "nothing to fetch".to_string()
    } else {
        format!("fetched {}", fetched.join(", "))
    };
    finish("fetch", t0, problems, what, Vec::new())
}

fn check_tools(ctx: &Ctx) -> Check {
    let t0 = Instant::now();
    let mut problems = Vec::new();
    let mut notes = Vec::new();
    match preflight_checkpatch(&ctx.tree) {
        Ok(Some(e)) => notes.push(format!("spdxcheck runs under EPYTHON={e}")),
        Ok(None) => notes.push("spdxcheck runs under python3 as it is".to_string()),
        Err(e) => problems.push(format!("{e:#}")),
    }
    for s in ["scripts/get_maintainer.pl", "scripts/config"] {
        if !ctx.tree.join(s).is_file() {
            problems.push(format!("{s} is not in the tree"));
        }
    }
    for (what, candidates) in [("kernel-doc", &KERNEL_DOC[..]), ("checkstack.pl", &CHECKSTACK[..])] {
        match tree_script(&ctx.tree, candidates) {
            Some(p) => notes.push(format!("{what}: {}", p.display())),
            None => problems.push(format!("{what} is in none of {}", candidates.join(", "))),
        }
    }
    for t in [
        "make",
        "gcc",
        "clang",
        "perl",
        "git",
        "objcopy",
        "objdump",
        "readelf",
        "sparse",
        "sphinx-build",
    ] {
        if which(t).is_none() {
            problems.push(format!("{t} is not on PATH"));
        }
    }
    if ctx.cfg.cross {
        match ctx.cross {
            Some(p) => notes.push(format!("arm64 built with {p}gcc")),
            None => problems.push(
                "no aarch64 cross compiler on PATH (aarch64-unknown-linux-gnu-gcc or \
                 aarch64-linux-gnu-gcc): crossdev --stable -t aarch64-unknown-linux-gnu, \
                 or --no-cross to leave arm64 to the bitbake chain"
                    .to_string(),
            ),
        }
    } else {
        notes.push("--no-cross: arm64 is left to the bitbake chain".to_string());
    }
    finish(
        "tools",
        t0,
        problems,
        "checkpatch with spdxcheck, get_maintainer, kernel-doc, checkstack, gcc, clang, \
         sparse, binutils, sphinx-build"
            .to_string(),
        notes,
    )
}

fn check_identity(ctx: &Ctx) -> Check {
    let t0 = Instant::now();
    let fs = &ctx.cfg.fs;
    let dir = ctx.fs_dir();
    let listing = match git(&ctx.cfg.beamfs, &["ls-tree", "--name-only", &ctx.measured_sha]) {
        Ok(s) => s,
        Err(e) => {
            return finish("identity", t0, vec![format!("{e:#}")], String::new(), Vec::new())
        }
    };
    let sources: BTreeSet<String> = listing
        .lines()
        .filter(|n| is_source(n))
        .map(str::to_string)
        .collect();
    let present: BTreeSet<String> = dir_names(&dir).into_iter().collect();
    if present.is_empty() {
        return finish(
            "identity",
            t0,
            vec![format!("{} is empty or missing", dir.display())],
            String::new(),
            Vec::new(),
        );
    }
    let mut problems = Vec::new();
    for n in &sources {
        let want = git_bytes(&ctx.cfg.beamfs, &["show", &format!("{}:{n}", ctx.measured_sha)]);
        match (want, std::fs::read(dir.join(n))) {
            (Ok(w), Ok(h)) if w == h => {}
            (Ok(_), Ok(_)) => problems.push(format!(
                "fs/{fs}/{n} differs from {}",
                short(&ctx.measured_sha)
            )),
            (Err(e), _) => problems.push(format!("{n}: {e:#}")),
            (_, Err(e)) => problems.push(format!("fs/{fs}/{n}: {e}")),
        }
    }
    for n in &present {
        if !sources.contains(n) && n != "Kconfig" && n != "Makefile" {
            problems.push(format!(
                "fs/{fs}/{n} is not a source of {}",
                short(&ctx.measured_sha)
            ));
        }
    }
    finish(
        "identity",
        t0,
        problems,
        format!(
            "{} sources identical to {}; Kconfig and Makefile are the series' own",
            sources.len(),
            short(&ctx.measured_sha)
        ),
        Vec::new(),
    )
}

fn check_commits(ctx: &Ctx) -> Check {
    let t0 = Instant::now();
    let total = ctx.commits.len();
    let mut problems = Vec::new();
    for (i, sha) in ctx.commits.iter().enumerate() {
        let n = i + 1;
        let raw = match git(
            &ctx.cfg.linux,
            &["show", "-s", "--format=%G?%x00%an <%ae>%x00%s%x00%B", sha],
        ) {
            Ok(s) => s,
            Err(e) => {
                problems.push(format!("{n}: {e:#}"));
                continue;
            }
        };
        let parts: Vec<&str> = raw.splitn(4, '\0').collect();
        if parts.len() < 4 {
            problems.push(format!("{n}: cannot read commit {}", short(sha)));
            continue;
        }
        let (sig, author, subject, body) = (parts[0], parts[1], parts[2], parts[3]);
        if sig != "G" {
            problems.push(format!("{n} {}: signature {sig}, G required", short(sha)));
        }
        if author != ctx.cfg.author {
            problems.push(format!("{n}: author {author}"));
        }
        let mail = mail_subject(&ctx.cfg.subject_prefix, n, total, subject);
        let len = mail.chars().count();
        if len > SUBJECT_MAX {
            problems.push(format!("{n}: subject of {len} characters: {mail}"));
        }
        for f in message_findings(body, &ctx.cfg.author, &ctx.cfg.assisted_by) {
            problems.push(format!("{n}: {f}"));
        }
    }
    finish(
        "commits",
        t0,
        problems,
        format!("{total} commits signed and attributed as required, subjects within {SUBJECT_MAX}"),
        Vec::new(),
    )
}

/// Whether get_maintainer names the author for every file the series adds.
fn maintainers_cover(ctx: &Ctx) -> Result<()> {
    let mail = author_mail(&ctx.cfg.author);
    let mut uncovered = Vec::new();
    for f in &ctx.added {
        let o = output(
            Command::new(ctx.tree.join("scripts/get_maintainer.pl"))
                .current_dir(&ctx.tree)
                .args(["--nogit", "--nogit-fallback", "--norolestats", "-f"])
                .arg(f),
        )?;
        if !String::from_utf8_lossy(&o.stdout).contains(&mail) {
            uncovered.push(f.clone());
        }
    }
    if uncovered.is_empty() {
        Ok(())
    } else {
        bail!(
            "no MAINTAINERS entry names {mail} for {}",
            uncovered.join(", ")
        )
    }
}

struct PatchRun {
    name: String,
    normal: Result<CheckpatchRun>,
    strict: Result<CheckpatchRun>,
}

fn check_checkpatch(ctx: &Ctx) -> Check {
    let t0 = Instant::now();
    let runs: Vec<PatchRun> = std::thread::scope(|s| {
        let handles: Vec<_> = ctx
            .patches
            .iter()
            .map(|p| {
                let tree = ctx.tree.as_path();
                s.spawn(move || PatchRun {
                    name: file_name(p),
                    normal: checkpatch(tree, p, &[]),
                    strict: checkpatch(tree, p, &["--strict"]),
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| PatchRun {
                    name: String::new(),
                    normal: Err(anyhow!("checkpatch thread panicked")),
                    strict: Err(anyhow!("checkpatch thread panicked")),
                })
            })
            .collect()
    });
    let mut problems: Vec<String> = Vec::new();
    let mut path_changes = 0usize;
    let mut strict: BTreeMap<String, u32> = BTreeMap::new();
    let mut log = String::new();
    for r in &runs {
        match &r.normal {
            Ok(c) => {
                let _ = writeln!(log, "===== {}\n{}", r.name, c.raw);
                for f in c.findings.iter().filter(|f| f.level != "CHECK") {
                    if f.kind == "FILE_PATH_CHANGES" {
                        path_changes += 1;
                    } else {
                        problems.push(format!("{}: {}", r.name, f.line));
                    }
                }
            }
            Err(e) => problems.push(format!("{}: {e:#}", r.name)),
        }
        match &r.strict {
            Ok(c) => {
                let _ = writeln!(log, "===== {} --strict\n{}", r.name, c.raw);
                for f in c.findings.iter().filter(|f| f.level == "CHECK") {
                    *strict.entry(f.kind.clone()).or_insert(0) += 1;
                    if ctx.cfg.strict_blocking {
                        problems.push(format!("{}: {}", r.name, f.line));
                    }
                }
            }
            Err(e) => problems.push(format!("{} --strict: {e:#}", r.name)),
        }
    }
    let log_path = ctx.logs().join("checkpatch.txt");
    let _ = std::fs::write(&log_path, log.as_bytes());
    let mut notes = Vec::new();
    if path_changes > 0 {
        match maintainers_cover(ctx) {
            Ok(()) => notes.push(format!(
                "FILE_PATH_CHANGES on {path_changes} patch(es), answered: the series' \
                 MAINTAINERS entry covers every file it adds"
            )),
            Err(e) => problems.push(format!(
                "FILE_PATH_CHANGES on {path_changes} patch(es), not answered: {e:#}"
            )),
        }
    }
    let total: u32 = strict.values().sum();
    notes.push(format!(
        "--strict: {total} CHECK{}",
        if ctx.cfg.strict_blocking {
            ", blocking"
        } else {
            ", reported"
        }
    ));
    for (k, n) in &strict {
        notes.push(format!("{n:>6} {k}"));
    }
    notes.push(format!("log: {}", log_path.display()));
    finish(
        "checkpatch",
        t0,
        problems,
        format!("{} patches: 0 errors, 0 warnings", ctx.patches.len()),
        notes,
    )
}

fn check_sizes(ctx: &Ctx) -> Check {
    let t0 = Instant::now();
    let mut problems = Vec::new();
    let mut largest = (0u64, String::new());
    for p in ctx.cover.iter().chain(ctx.patches.iter()) {
        let n = std::fs::metadata(p).map_or(u64::MAX, |m| m.len());
        let name = file_name(p);
        if n >= ctx.cfg.max_mail_bytes {
            problems.push(format!("{name}: {n} bytes"));
        }
        if n > largest.0 {
            largest = (n, name);
        }
    }
    finish(
        "sizes",
        t0,
        problems,
        format!(
            "largest {} bytes ({}), under {}",
            largest.0, largest.1, ctx.cfg.max_mail_bytes
        ),
        Vec::new(),
    )
}

fn check_prose(ctx: &Ctx) -> Check {
    let t0 = Instant::now();
    let mut problems = Vec::new();
    match ctx.cover.as_deref().map(|p| (p, std::fs::read_to_string(p))) {
        None => problems.push("no cover letter".to_string()),
        Some((p, Err(e))) => problems.push(format!("{}: {e}", p.display())),
        Some((_, Ok(text))) => {
            for x in placeholders(&text) {
                problems.push(format!("cover letter: placeholder left: {x}"));
            }
            for x in forbidden_chars(&text) {
                problems.push(format!("cover letter: {x}"));
            }
            if !text.lines().any(|l| l.starts_with("base-commit: ")) {
                problems.push("cover letter: no base-commit line".to_string());
            }
            match text.lines().find_map(|l| l.strip_prefix("Subject: ")) {
                Some(s) if s.chars().count() <= SUBJECT_MAX => {}
                Some(s) => problems.push(format!(
                    "cover letter: subject of {} characters: {s}",
                    s.chars().count()
                )),
                None => problems.push("cover letter: no Subject line".to_string()),
            }
        }
    }
    for f in ctx.changed.iter().filter(|f| f.starts_with("Documentation/")) {
        if let Some(text) = read_lossy(&ctx.tree.join(f)) {
            for x in forbidden_chars(&text) {
                problems.push(format!("{f}: {x}"));
            }
        }
    }
    let dir = ctx.fs_dir();
    for n in dir_names(&dir) {
        if let Some(text) = read_lossy(&dir.join(&n)) {
            for i in non_ascii_lines(&text) {
                problems.push(format!("fs/{}/{n}:{i}: not ASCII", ctx.cfg.fs));
            }
        }
    }
    finish(
        "prose",
        t0,
        problems,
        "cover letter complete, no typographic dash or quote, sources in ASCII".to_string(),
        Vec::new(),
    )
}

fn check_maintainers(ctx: &Ctx) -> Check {
    let t0 = Instant::now();
    let mut problems = Vec::new();
    let mut notes = Vec::new();
    let mut touches = Vec::new();
    let mut first_add = None;
    for (i, sha) in ctx.commits.iter().enumerate() {
        let names = git(
            &ctx.cfg.linux,
            &["diff-tree", "--no-commit-id", "--name-only", "-r", sha],
        )
        .unwrap_or_default();
        if names.lines().any(|l| l == "MAINTAINERS") {
            touches.push(i + 1);
        }
        if first_add.is_none() {
            let added = git(
                &ctx.cfg.linux,
                &[
                    "diff-tree",
                    "--no-commit-id",
                    "--name-only",
                    "--diff-filter=A",
                    "-r",
                    sha,
                ],
            )
            .unwrap_or_default();
            if !added.trim().is_empty() {
                first_add = Some(i + 1);
            }
        }
    }
    match (first_add, touches.first()) {
        (Some(a), Some(&m)) if m <= a => {
            notes.push(format!(
                "MAINTAINERS entry in patch {m}, before or with the first patch that adds files ({a})"
            ));
        }
        (Some(a), Some(&m)) => problems.push(format!(
            "MAINTAINERS changes in patch {m}, after patch {a}, the first that adds files"
        )),
        (Some(_), None) => {
            problems.push("the series adds files and no patch touches MAINTAINERS".to_string());
        }
        (None, _) => notes.push("the series adds no file".to_string()),
    }
    let gm = ctx.tree.join("scripts/get_maintainer.pl");
    match output(
        Command::new(&gm)
            .current_dir(&ctx.tree)
            .arg("--self-test=patterns"),
    ) {
        Ok(o) => {
            let s = lossy(&o);
            let in_fs = format!("fs/{}/", ctx.cfg.fs);
            let in_doc = format!("filesystems/{}", ctx.cfg.fs);
            for l in s.lines().filter(|l| l.contains(&in_fs) || l.contains(&in_doc)) {
                problems.push(format!("self-test: {l}"));
            }
        }
        Err(e) => problems.push(format!("{e:#}")),
    }
    let mut cmd = Command::new(&gm);
    cmd.current_dir(&ctx.tree).args(&ctx.patches);
    match output(&mut cmd) {
        Ok(o) => {
            for l in String::from_utf8_lossy(&o.stdout).lines() {
                notes.push(format!("to: {l}"));
            }
        }
        Err(e) => problems.push(format!("{e:#}")),
    }
    finish(
        "maintainers",
        t0,
        problems,
        "entry at the head of the series, patterns valid".to_string(),
        notes,
    )
}

fn check_kconfig(ctx: &Ctx) -> Check {
    let t0 = Instant::now();
    let fs = &ctx.cfg.fs;
    let mut problems = Vec::new();
    let mut notes = Vec::new();
    let text = read_lossy(&ctx.fs_dir().join("Kconfig")).unwrap_or_default();
    let entries = kconfig_entries(&text);
    if entries.is_empty() {
        problems.push(format!("no config entry in fs/{fs}/Kconfig"));
    }
    for e in &entries {
        if e.prompt && e.help_lines == 0 {
            problems.push(format!("{}: no help text", e.name));
        }
        for d in &e.defaults {
            let v = d.split_whitespace().next().unwrap_or("");
            if v == "y" || v == "m" {
                problems.push(format!("{}: default {d}; a new option defaults to off", e.name));
            }
        }
        notes.push(format!(
            "{} {}, {} line(s) of help",
            e.name,
            if e.kind.is_empty() { "?" } else { e.kind.as_str() },
            e.help_lines
        ));
    }
    match &ctx.main_symbol {
        Some(main) => {
            let src = format!("source \"fs/{fs}/Kconfig\"");
            let parent = read_lossy(&ctx.tree.join("fs/Kconfig")).unwrap_or_default();
            if !parent.lines().any(|l| l.trim() == src) {
                problems.push(format!("fs/Kconfig does not {src}"));
            }
            let obj = format!("obj-$(CONFIG_{main})");
            let dir = format!("{fs}/");
            let mk = read_lossy(&ctx.tree.join("fs/Makefile")).unwrap_or_default();
            if !mk.lines().any(|l| l.contains(&obj) && l.contains(&dir)) {
                problems.push(format!("fs/Makefile has no {obj} line for {dir}"));
            }
        }
        None => problems.push(format!("no tristate symbol in fs/{fs}/Kconfig")),
    }
    finish(
        "kconfig",
        t0,
        problems,
        format!(
            "{} option(s) with help, off by default, wired into fs/Kconfig and fs/Makefile",
            entries.len()
        ),
        notes,
    )
}

fn check_interfaces(ctx: &Ctx) -> Check {
    let t0 = Instant::now();
    let fs = &ctx.cfg.fs;
    let dir = ctx.fs_dir();
    let mut src = String::new();
    for n in dir_names(&dir).iter().filter(|n| is_source(n)) {
        if let Some(t) = read_lossy(&dir.join(n)) {
            src.push_str(&t);
            src.push('\n');
        }
    }
    let mut doc_text = String::new();
    let mut abi_text = String::new();
    for f in ctx.changed.iter().filter(|f| f.starts_with("Documentation/")) {
        if let Some(t) = read_lossy(&ctx.tree.join(f)) {
            if f.starts_with("Documentation/ABI/") {
                abi_text.push_str(&t);
            }
            doc_text.push_str(&t);
        }
    }
    let mut problems = Vec::new();
    let mut notes = Vec::new();
    let mut user_api: Vec<&str> = Vec::new();

    let params = module_params(&src);
    let descs = param_descriptions(&src);
    for p in &params {
        if !descs.contains(p) {
            problems.push(format!("module parameter {p} has no MODULE_PARM_DESC"));
        }
    }
    if !params.is_empty() {
        let list: Vec<&str> = params.iter().map(String::as_str).collect();
        notes.push(format!("module parameters: {}", list.join(", ")));
    }

    let attrs = sysfs_attributes(&src);
    let sysfs = has_any(
        &src,
        &[
            "kobject_init_and_add(",
            "kobject_create_and_add(",
            "sysfs_create_group(",
            "sysfs_create_groups(",
            "sysfs_create_file(",
            "ATTRIBUTE_GROUPS(",
        ],
    );
    if sysfs || !attrs.is_empty() {
        user_api.push("sysfs");
        let sys = format!("/sys/fs/{fs}/");
        if abi_text.contains(&sys) {
            for a in &attrs {
                if !mentions_component(&abi_text, a) {
                    problems.push(format!(
                        "sysfs attribute {a} is not in the Documentation/ABI entry"
                    ));
                }
            }
        } else {
            problems.push(format!(
                "the sysfs interface under {sys} has no entry in Documentation/ABI"
            ));
        }
        if !attrs.is_empty() {
            let list: Vec<&str> = attrs.iter().map(String::as_str).collect();
            notes.push(format!("sysfs attributes: {}", list.join(", ")));
        }
    }
    if has_any(&src, &["kobject_uevent_env(", "kobject_uevent("]) {
        user_api.push("uevent");
    }
    if has_any(
        &src,
        &["proc_create(", "proc_create_data(", "proc_create_single(", "proc_mkdir("],
    ) {
        user_api.push("procfs");
        if !doc_text.contains("/proc/") {
            problems.push("a /proc entry that no documentation in the series describes".to_string());
        }
    }
    if has_any(&src, &["_IO(", "_IOR(", "_IOW(", "_IOWR("]) {
        user_api.push("ioctl");
        if !ctx
            .changed
            .iter()
            .any(|f| f.as_str() == "Documentation/userspace-api/ioctl/ioctl-number.rst")
        {
            problems.push(
                "ioctls, and Documentation/userspace-api/ioctl/ioctl-number.rst unchanged"
                    .to_string(),
            );
        }
    }
    if has_any(&src, &["__setup(", "early_param("]) {
        user_api.push("boot parameters");
        if !ctx
            .changed
            .iter()
            .any(|f| f.as_str() == "Documentation/admin-guide/kernel-parameters.txt")
        {
            problems.push(
                "boot parameters, and Documentation/admin-guide/kernel-parameters.txt unchanged"
                    .to_string(),
            );
        }
    }
    if !user_api.is_empty() {
        notes.push(format!(
            "userspace interfaces ({}): Cc linux-api@vger.kernel.org",
            user_api.join(", ")
        ));
    }
    finish(
        "interfaces",
        t0,
        problems,
        "parameters described, userspace interfaces documented".to_string(),
        notes,
    )
}

// ------------------------------------------------------------------
// Builds
// ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// The module itself is built.
    Module,
    /// The filesystem's symbols are in System.map.
    Builtin,
    /// The objects of the filesystem are compiled, nothing is linked.
    Objects,
    /// The filesystem cannot be selected.
    Absent,
}

#[derive(Debug, Clone)]
struct Variant {
    name: &'static str,
    what: String,
    dir: String,
    arch: &'static str,
    vars: Vec<String>,
    base: &'static str,
    set: Vec<(String, char)>,
    require: Vec<(String, char)>,
    target: Option<String>,
    expect: Expect,
    keep: bool,
}

fn make(tree: &Path, o: &Path, v: &Variant, args: &[String]) -> Result<(bool, String)> {
    let mut c = Command::new("make");
    c.arg("-C")
        .arg(tree)
        .arg(format!("O={}", o.display()))
        .arg(format!("ARCH={}", v.arch))
        .args(&v.vars)
        .args(args);
    let out = output(&mut c)?;
    Ok((out.status.success(), lossy(&out)))
}

/// One make run: its diagnostics and its failure become problems.
fn make_step(
    tree: &Path,
    o: &Path,
    v: &Variant,
    args: &[String],
    log: &mut String,
    problems: &mut Vec<String>,
) -> String {
    match make(tree, o, v, args) {
        Ok((ok, text)) => {
            for l in text.lines().filter(|l| is_diagnostic(l)) {
                problems.push(l.trim().to_string());
            }
            if !ok {
                problems.push(format!("make {} failed", args.join(" ")));
            }
            log.push_str(&text);
            text
        }
        Err(e) => {
            problems.push(format!("{e:#}"));
            String::new()
        }
    }
}

fn build_inner(ctx: &Ctx, tree: &Path, v: &Variant) -> (Vec<String>, Vec<String>) {
    let fs = &ctx.cfg.fs;
    let o = ctx.cfg.out.join(&v.dir);
    let mut problems: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut log = String::new();
    if let Err(e) = std::fs::create_dir_all(&o) {
        problems.push(format!("{}: {e}", o.display()));
        return (problems, notes);
    }
    make_step(tree, &o, v, &[v.base.to_string()], &mut log, &mut problems);
    if !v.set.is_empty() {
        let mut sc = Command::new(tree.join("scripts/config"));
        sc.arg("--file").arg(o.join(".config"));
        for (s, val) in &v.set {
            let flag = match *val {
                'y' => "--enable",
                'm' => "--module",
                _ => "--disable",
            };
            sc.arg(flag).arg(s);
        }
        match output(&mut sc) {
            Ok(out) if out.status.success() => {}
            Ok(out) => problems.push(format!("scripts/config: {}", lossy(&out).trim())),
            Err(e) => problems.push(format!("{e:#}")),
        }
        make_step(tree, &o, v, &["olddefconfig".to_string()], &mut log, &mut problems);
    }
    let config = std::fs::read_to_string(o.join(".config")).unwrap_or_default();
    for (s, want) in &v.require {
        let got = config_value(&config, s);
        if got != *want {
            problems.push(format!("CONFIG_{s} came out {got}, {want} was asked for"));
        }
    }
    let mut args = vec![format!("-j{}", jobs())];
    if let Some(t) = &v.target {
        args.push(t.clone());
    }
    let text = make_step(tree, &o, v, &args, &mut log, &mut problems);
    let c_files = dir_names(&tree.join("fs").join(fs))
        .iter()
        .filter(|n| n.ends_with(".c"))
        .count();
    if v.expect != Expect::Absent {
        let n = count_tagged(&text, "CC", fs);
        if n < c_files {
            problems.push(format!(
                "{n} objects compiled under fs/{fs} for {c_files} sources"
            ));
        } else {
            notes.push(format!("{n} objects compiled under fs/{fs}"));
        }
    }
    match v.expect {
        Expect::Module => {
            let ko = o.join("fs").join(fs).join(format!("{fs}.ko"));
            match std::fs::metadata(&ko) {
                Ok(m) => notes.push(format!("{fs}.ko, {} bytes", m.len())),
                Err(_) => problems.push(format!("{} was not built", ko.display())),
            }
        }
        Expect::Builtin => {
            let map = std::fs::read_to_string(o.join("System.map")).unwrap_or_default();
            let sym = format!(" {fs}_");
            let n = map.lines().filter(|l| l.contains(&sym)).count();
            if n == 0 {
                problems.push(format!("no {fs}_ symbol in System.map"));
            } else {
                notes.push(format!("{n} {fs}_ symbols in vmlinux"));
            }
        }
        Expect::Objects => {}
        Expect::Absent => {
            if let Some(main) = &ctx.main_symbol {
                if config_value(&config, main) != 'n' {
                    problems.push(format!("CONFIG_{main} is set where it cannot be"));
                }
            }
        }
    }
    let log_path = ctx.logs().join(format!("{}.txt", v.dir));
    let _ = std::fs::write(&log_path, log.as_bytes());
    notes.push(format!("log: {}", log_path.display()));
    (problems, notes)
}

fn build(ctx: &Ctx, tree: &Path, v: &Variant) -> Check {
    let t0 = Instant::now();
    let (problems, notes) = build_inner(ctx, tree, v);
    finish(v.name, t0, problems, format!("{}: no warning", v.what), notes)
}

/// Object files of the filesystem in a build directory, the composite
/// object and the module stub left out.
fn fs_objects(objdir: &Path, fs: &str) -> Vec<PathBuf> {
    let composite = format!("{fs}.o");
    dir_names(objdir)
        .into_iter()
        .filter(|n| n.ends_with(".o") && *n != composite && !n.ends_with(".mod.o"))
        .map(|n| objdir.join(n))
        .collect()
}

fn check_builds(ctx: &Ctx, add: &mut dyn FnMut(Check)) {
    let t0 = Instant::now();
    let fs = ctx.cfg.fs.clone();
    let Some(main) = ctx.main_symbol.clone() else {
        add(finish(
            "build",
            t0,
            vec![format!("no tristate symbol in fs/{fs}/Kconfig")],
            String::new(),
            Vec::new(),
        ));
        return;
    };
    let y = |s: &str| (s.to_string(), 'y');
    let n = |s: &str| (s.to_string(), 'n');
    let bools_on: Vec<(String, char)> = ctx.bools.iter().map(|b| (b.clone(), 'y')).collect();
    let bools_off: Vec<(String, char)> = ctx.bools.iter().map(|b| (b.clone(), 'n')).collect();

    let mut full_set = vec![
        y("BLOCK"),
        y("MISC_FILESYSTEMS"),
        y("SMP"),
        y("PREEMPT"),
        n("PREEMPT_NONE"),
        n("PREEMPT_VOLUNTARY"),
        y("DEBUG_FS"),
        y("FTRACE"),
        y("ENABLE_DEFAULT_TRACERS"),
        y(&main),
    ];
    full_set.extend(bools_on.iter().cloned());
    let mut full_req = vec![
        y("BLOCK"),
        y(&main),
        y("SMP"),
        y("PREEMPTION"),
        y("SYSFS"),
        y("PROC_FS"),
        y("DEBUG_FS"),
        y("TRACEPOINTS"),
    ];
    full_req.extend(bools_on.iter().cloned());

    let mut module_req = vec![(main.clone(), 'm'), y("MODULES")];
    module_req.extend(bools_off.iter().cloned());
    let module = Variant {
        name: "build_module",
        what: format!("x86_64 tinyconfig, {fs} as a module, its options off, no SMP, no preemption"),
        dir: "build-x86_64-m".to_string(),
        arch: "x86_64",
        vars: Vec::new(),
        base: "tinyconfig",
        set: vec![
            y("BLOCK"),
            y("MISC_FILESYSTEMS"),
            y("MODULES"),
            y("MODULE_UNLOAD"),
            (main.clone(), 'm'),
        ],
        require: module_req,
        target: None,
        expect: Expect::Module,
        keep: true,
    };
    let builtin = Variant {
        name: "build_builtin",
        what: format!(
            "x86_64 tinyconfig, {fs} built in with every option, SMP, preemption, tracing, debugfs"
        ),
        dir: "build-x86_64-y".to_string(),
        arch: "x86_64",
        vars: Vec::new(),
        base: "tinyconfig",
        set: full_set.clone(),
        require: full_req.clone(),
        target: None,
        expect: Expect::Builtin,
        keep: true,
    };
    let mut debug_set = full_set.clone();
    debug_set.extend(
        [
            "DEBUG_KERNEL",
            "PROVE_LOCKING",
            "DEBUG_ATOMIC_SLEEP",
            "DEBUG_PREEMPT",
            "SLUB_DEBUG",
            "DEBUG_PAGEALLOC",
            "DEBUG_OBJECTS",
            "DEBUG_OBJECTS_RCU_HEAD",
            "PROVE_RCU",
            "DEBUG_MUTEXES",
            "DEBUG_SPINLOCK",
        ]
        .map(y),
    );
    let mut debug_req = full_req.clone();
    debug_req.extend(
        [
            "PROVE_LOCKING",
            "DEBUG_ATOMIC_SLEEP",
            "DEBUG_PAGEALLOC",
            "DEBUG_OBJECTS_RCU_HEAD",
        ]
        .map(y),
    );
    let debug = Variant {
        name: "build_debug",
        what: "the same under lockdep and the memory and object debugging options".to_string(),
        dir: "build-x86_64-debug".to_string(),
        arch: "x86_64",
        vars: Vec::new(),
        base: "tinyconfig",
        set: debug_set,
        require: debug_req,
        target: None,
        expect: Expect::Builtin,
        keep: false,
    };
    let mut min_req = vec![y(&main), n("SYSFS"), n("PROC_FS"), n("DEBUG_FS")];
    min_req.extend(bools_off.iter().cloned());
    let minimal = Variant {
        name: "build_minimal",
        what: format!("x86_64 tinyconfig, {fs} built in, without sysfs, procfs and debugfs"),
        dir: "build-x86_64-min".to_string(),
        arch: "x86_64",
        vars: Vec::new(),
        base: "tinyconfig",
        set: vec![
            y("EXPERT"),
            y("BLOCK"),
            y("MISC_FILESYSTEMS"),
            n("SYSFS"),
            n("PROC_FS"),
            n("DEBUG_FS"),
            y(&main),
        ],
        require: min_req,
        target: None,
        expect: Expect::Builtin,
        keep: false,
    };
    let clang = Variant {
        name: "build_clang",
        what: format!("x86_64 tinyconfig with clang, {fs} built in with every option"),
        dir: "build-x86_64-clang".to_string(),
        arch: "x86_64",
        vars: vec!["CC=clang".to_string()],
        base: "tinyconfig",
        set: full_set.clone(),
        require: full_req.clone(),
        target: None,
        expect: Expect::Builtin,
        keep: true,
    };
    let allno = Variant {
        name: "build_allno",
        what: format!("x86_64 allnoconfig, where {fs} cannot be selected"),
        dir: "build-x86_64-allno".to_string(),
        arch: "x86_64",
        vars: Vec::new(),
        base: "allnoconfig",
        set: Vec::new(),
        require: vec![n(&main)],
        target: None,
        expect: Expect::Absent,
        keep: false,
    };
    let mut allmod_req = vec![(main.clone(), 'm')];
    allmod_req.extend(bools_on.iter().cloned());
    let allmod = Variant {
        name: "build_allmod",
        what: format!("x86_64 allmodconfig, fs/{fs} compiled, CONFIG_WERROR on"),
        dir: "build-x86_64-allmod".to_string(),
        arch: "x86_64",
        vars: Vec::new(),
        base: "allmodconfig",
        set: vec![n("RUST")],
        require: allmod_req,
        target: Some(format!("fs/{fs}/")),
        expect: Expect::Objects,
        keep: false,
    };

    for v in [&module, &builtin, &debug, &minimal, &clang, &allno, &allmod] {
        begin(v.name, &v.what);
        add(build(ctx, &ctx.tree, v));
        if !v.keep {
            discard(ctx, &v.dir);
        }
    }

    let t1 = Instant::now();
    match (ctx.cfg.cross, ctx.cross) {
        (false, _) => add(skip(
            "build_arm64",
            t1,
            "--no-cross: arm64 is built by the bitbake chain".to_string(),
        )),
        (true, None) => add(finish(
            "build_arm64",
            t1,
            vec!["no aarch64 cross compiler on PATH".to_string()],
            String::new(),
            Vec::new(),
        )),
        (true, Some(prefix)) => {
            let arm64 = Variant {
                name: "build_arm64",
                what: format!("arm64 tinyconfig, {fs} built in with every option"),
                dir: "build-arm64-y".to_string(),
                arch: "arm64",
                vars: vec![format!("CROSS_COMPILE={prefix}")],
                base: "tinyconfig",
                set: full_set.clone(),
                require: full_req.clone(),
                target: None,
                expect: Expect::Builtin,
                keep: false,
            };
            begin(arm64.name, &arm64.what);
            add(build(ctx, &ctx.tree, &arm64));
            discard(ctx, &arm64.dir);
        }
    }

    if ctx.text_sha.is_some() {
        begin("text", "the module rebuilt from the reference sources");
    }
    add(check_text(ctx, &module));
    add(check_checkstack(ctx, &builtin));
    begin("build_w1", "the objects of the filesystem rebuilt with W=1, gcc and clang");
    add(check_w1(ctx, &[&module, &builtin, &clang]));
    add(check_sparse(ctx, &builtin));
    add(check_kernel_doc(ctx));
    begin("newer", &format!("merge and build on {}", ctx.cfg.newer.join(", ")));
    add(check_newer(ctx, &builtin));
}

fn text_sections(obj: &Path) -> Result<Vec<String>> {
    let o = output(Command::new("readelf").args(["-S", "-W"]).arg(obj))?;
    if !o.status.success() {
        bail!(
            "readelf -S {}: {}",
            obj.display(),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(section_names(&String::from_utf8_lossy(&o.stdout))
        .into_iter()
        .filter(|n| is_text_section(n))
        .collect())
}

fn section_bytes(obj: &Path, name: &str, tmp: &Path) -> Result<Vec<u8>> {
    let dst = tmp.join("section.bin");
    let _ = std::fs::remove_file(&dst);
    let o = output(
        Command::new("objcopy")
            .args(["-O", "binary", "-j", name])
            .arg(obj)
            .arg(&dst),
    )?;
    if !o.status.success() {
        bail!(
            "objcopy -j {name} {}: {}",
            obj.display(),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(std::fs::read(dst).unwrap_or_default())
}

fn relocations(obj: &Path, sections: &[String]) -> Result<Vec<String>> {
    let o = output(Command::new("readelf").args(["-r", "-W"]).arg(obj))?;
    if !o.status.success() {
        bail!(
            "readelf -r {}: {}",
            obj.display(),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(relocs_of(&String::from_utf8_lossy(&o.stdout), sections))
}

fn same_text(a: &Path, b: &Path, tmp: &Path) -> Result<Vec<String>> {
    let mut diffs = Vec::new();
    let sa = text_sections(a)?;
    let sb = text_sections(b)?;
    if sa != sb {
        diffs.push(format!("sections {sa:?} against {sb:?}"));
        return Ok(diffs);
    }
    for s in &sa {
        if section_bytes(a, s, tmp)? != section_bytes(b, s, tmp)? {
            diffs.push(format!("{s} differs"));
        }
    }
    if relocations(a, &sa)? != relocations(b, &sb)? {
        diffs.push("relocations against the code differ".to_string());
    }
    Ok(diffs)
}

fn check_text(ctx: &Ctx, v: &Variant) -> Check {
    let t0 = Instant::now();
    let Some(rev) = ctx.text_sha.as_deref() else {
        return skip("text", t0, "no --same-text-as".to_string());
    };
    let fs = &ctx.cfg.fs;
    let built = ctx.cfg.out.join(&v.dir);
    if !built.join(".config").is_file() {
        return finish(
            "text",
            t0,
            vec![format!("the {} build did not run", v.name)],
            String::new(),
            Vec::new(),
        );
    }
    let wt = match Worktree::add(&ctx.cfg.linux, &ctx.cfg.out.join("tree-ref"), &ctx.tip) {
        Ok(w) => w,
        Err(e) => return finish("text", t0, vec![format!("{e:#}")], String::new(), Vec::new()),
    };
    let mut problems = Vec::new();
    let dir = wt.path.join("fs").join(fs);
    match git(&ctx.cfg.beamfs, &["ls-tree", "--name-only", rev]) {
        Ok(listing) => {
            for n in listing.lines().filter(|n| is_source(n)) {
                let dst = dir.join(n);
                if !dst.is_file() {
                    problems.push(format!("{n} is in {} and not in the series", short(rev)));
                    continue;
                }
                match git_bytes(&ctx.cfg.beamfs, &["show", &format!("{rev}:{n}")]) {
                    Ok(b) => {
                        if let Err(e) = std::fs::write(&dst, b) {
                            problems.push(format!("{}: {e}", dst.display()));
                        }
                    }
                    Err(e) => problems.push(format!("{e:#}")),
                }
            }
        }
        Err(e) => problems.push(format!("{e:#}")),
    }
    let mut r = v.clone();
    r.dir = format!("build-ref-{}", v.dir.trim_start_matches("build-"));
    let ob = ctx.cfg.out.join(&r.dir);
    if let Err(e) = std::fs::create_dir_all(&ob)
        .and_then(|()| std::fs::copy(built.join(".config"), ob.join(".config")).map(|_| ()))
    {
        problems.push(format!("{}: {e}", ob.display()));
    }
    let mut log = String::new();
    make_step(&wt.path, &ob, &r, &["olddefconfig".to_string()], &mut log, &mut problems);
    make_step(&wt.path, &ob, &r, &[format!("-j{}", jobs())], &mut log, &mut problems);
    let _ = std::fs::write(ctx.logs().join(format!("{}.txt", r.dir)), log.as_bytes());

    let objects = fs_objects(&built.join("fs").join(fs), fs);
    let tmp = ctx.cfg.out.join("text-scratch");
    let _ = std::fs::create_dir_all(&tmp);
    let mut same = 0usize;
    for a in &objects {
        let Some(name) = a.file_name() else { continue };
        let b = ob.join("fs").join(fs).join(name);
        match same_text(a, &b, &tmp) {
            Ok(diffs) if diffs.is_empty() => same += 1,
            Ok(diffs) => {
                for d in diffs {
                    problems.push(format!("{}: {d}", name.to_string_lossy()));
                }
            }
            Err(e) => problems.push(format!("{}: {e:#}", name.to_string_lossy())),
        }
    }
    if objects.is_empty() {
        problems.push(format!(
            "no object under {}",
            built.join("fs").join(fs).display()
        ));
    }
    drop(wt);
    discard(ctx, &r.dir);
    finish(
        "text",
        t0,
        problems,
        format!(
            "{same} objects: code sections and their relocations identical to {}",
            short(rev)
        ),
        Vec::new(),
    )
}

fn check_checkstack(ctx: &Ctx, v: &Variant) -> Check {
    let t0 = Instant::now();
    let fs = &ctx.cfg.fs;
    let objdir = ctx.cfg.out.join(&v.dir).join("fs").join(fs);
    let objects = fs_objects(&objdir, fs);
    if objects.is_empty() {
        return finish(
            "checkstack",
            t0,
            vec![format!("no object under {}", objdir.display())],
            String::new(),
            Vec::new(),
        );
    }
    let Some(script) = tree_script(&ctx.tree, &CHECKSTACK) else {
        return finish(
            "checkstack",
            t0,
            vec!["checkstack.pl is not in the tree".to_string()],
            String::new(),
            Vec::new(),
        );
    };
    let tmp = ctx.cfg.out.join("text-scratch");
    let dump = tmp.join("objdump.txt");
    let arch = if v.arch == "x86_64" { "x86" } else { v.arch };
    let measure = || -> Result<String> {
        std::fs::create_dir_all(tmp.as_path())?;
        let f = std::fs::File::create(dump.as_path())?;
        let st = Command::new("objdump")
            .arg("-d")
            .args(&objects)
            .stdout(f)
            .status()
            .context("objdump")?;
        if !st.success() {
            bail!("objdump -d exited with {st}");
        }
        let o = Command::new("perl")
            .arg(script.as_path())
            .arg(arch)
            .stdin(std::fs::File::open(dump.as_path())?)
            .output()
            .context("checkstack.pl")?;
        if !o.status.success() {
            bail!("checkstack.pl: {}", String::from_utf8_lossy(&o.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let limit = ctx.cfg.stack_limit;
    let (problems, notes) = match measure() {
        Ok(text) => {
            let _ = std::fs::write(ctx.logs().join("checkstack.txt"), text.as_bytes());
            let mut entries = checkstack_entries(&text);
            entries.sort_by_key(|e| std::cmp::Reverse(e.1));
            let problems: Vec<String> = entries
                .iter()
                .filter(|e| e.1 > limit)
                .map(|(f, n)| format!("{f}: {n} bytes of stack"))
                .collect();
            let notes: Vec<String> = entries
                .iter()
                .take(5)
                .map(|(f, n)| format!("{n:>6} {f}"))
                .collect();
            (problems, notes)
        }
        Err(e) => (vec![format!("{e:#}")], Vec::new()),
    };
    finish(
        "checkstack",
        t0,
        problems,
        format!(
            "{} objects of {}: no frame over {limit} bytes",
            objects.len(),
            v.name
        ),
        notes,
    )
}

/// make on the filesystem's directory alone, in an existing build
/// directory, with `extra`.
fn rebuild_fs(ctx: &Ctx, v: &Variant, extra: &str, tag: &str) -> (Vec<String>, usize, String) {
    let o = ctx.cfg.out.join(&v.dir);
    let mut problems = Vec::new();
    if !o.join(".config").is_file() {
        problems.push("the build did not run".to_string());
        return (problems, 0, String::new());
    }
    let args = [
        extra.to_string(),
        format!("-j{}", jobs()),
        format!("fs/{}/", ctx.cfg.fs),
    ];
    let mut log = String::new();
    let text = make_step(&ctx.tree, &o, v, &args, &mut log, &mut problems);
    (problems, count_tagged(&text, tag, &ctx.cfg.fs), log)
}

fn c_sources(ctx: &Ctx) -> usize {
    dir_names(&ctx.fs_dir())
        .iter()
        .filter(|n| n.ends_with(".c"))
        .count()
}

fn check_w1(ctx: &Ctx, vs: &[&Variant]) -> Check {
    let t0 = Instant::now();
    let c_files = c_sources(ctx);
    let mut problems = Vec::new();
    let mut notes = Vec::new();
    let mut log = String::new();
    for v in vs {
        let (p, n, l) = rebuild_fs(ctx, v, "W=1", "CC");
        problems.extend(p.into_iter().map(|x| format!("{}: {x}", v.name)));
        if n < c_files {
            problems.push(format!(
                "{}: {n} objects recompiled with W=1 for {c_files} sources",
                v.name
            ));
        } else {
            notes.push(format!("{}: {n} objects recompiled", v.name));
        }
        log.push_str(&l);
    }
    let log_path = ctx.logs().join("build-w1.txt");
    let _ = std::fs::write(&log_path, log.as_bytes());
    notes.push(format!("log: {}", log_path.display()));
    finish(
        "build_w1",
        t0,
        problems,
        format!("W=1 adds no warning in fs/{}", ctx.cfg.fs),
        notes,
    )
}

fn check_sparse(ctx: &Ctx, v: &Variant) -> Check {
    let t0 = Instant::now();
    let c_files = c_sources(ctx);
    let (mut problems, n, log) = rebuild_fs(ctx, v, "C=2", "CHECK");
    if n < c_files {
        problems.push(format!("sparse checked {n} files of {c_files}"));
    }
    let log_path = ctx.logs().join("sparse.txt");
    let _ = std::fs::write(&log_path, log.as_bytes());
    finish(
        "sparse",
        t0,
        problems,
        format!("{n} files of {}, no sparse warning", v.name),
        vec![format!("log: {}", log_path.display())],
    )
}

fn check_kernel_doc(ctx: &Ctx) -> Check {
    let t0 = Instant::now();
    let fs = &ctx.cfg.fs;
    let Some(script) = tree_script(&ctx.tree, &KERNEL_DOC) else {
        return finish(
            "kernel_doc",
            t0,
            vec!["kernel-doc is not in the tree".to_string()],
            String::new(),
            Vec::new(),
        );
    };
    let files: Vec<String> = dir_names(&ctx.fs_dir())
        .into_iter()
        .filter(|n| is_source(n))
        .map(|n| format!("fs/{fs}/{n}"))
        .collect();
    let mut cmd = Command::new(script);
    cmd.current_dir(&ctx.tree).arg("-none").args(&files);
    let mut problems = Vec::new();
    match output(&mut cmd) {
        Ok(o) => {
            for l in lossy(&o).lines().filter(|l| !l.trim().is_empty()) {
                problems.push(l.trim().to_string());
            }
            if !o.status.success() && problems.is_empty() {
                problems.push(format!("kernel-doc exited with {}", o.status));
            }
        }
        Err(e) => problems.push(format!("{e:#}")),
    }
    finish(
        "kernel_doc",
        t0,
        problems,
        format!("{} sources and headers, no kernel-doc warning", files.len()),
        Vec::new(),
    )
}

fn check_newer(ctx: &Ctx, template: &Variant) -> Check {
    let t0 = Instant::now();
    if ctx.cfg.newer.is_empty() {
        return skip("newer", t0, "no --newer revision".to_string());
    }
    let linux = &ctx.cfg.linux;
    let mut problems = Vec::new();
    let mut notes = Vec::new();
    for (i, rev) in ctx.cfg.newer.iter().enumerate() {
        let sha = match resolve(linux, rev) {
            Ok(s) => s,
            Err(e) => {
                let hint = match rev.split_once('/') {
                    Some((r, _)) if r.contains("next") => {
                        format!("; git remote add {r} {LINUX_NEXT}")
                    }
                    _ => String::new(),
                };
                problems.push(format!("{e:#}{hint}"));
                continue;
            }
        };
        let desc = git(linux, &["describe", "--tags", "--always", &sha])
            .unwrap_or_else(|_| short(&sha).to_string());
        let merged = match output(
            Command::new("git")
                .arg("-C")
                .arg(linux)
                .args(["merge-tree", "--write-tree", &sha, &ctx.tip]),
        ) {
            Ok(o) => o,
            Err(e) => {
                problems.push(format!("{e:#}"));
                continue;
            }
        };
        let text = String::from_utf8_lossy(&merged.stdout).into_owned();
        if !merged.status.success() {
            problems.push(format!(
                "{rev} ({desc}): the series does not merge: {}",
                text.trim()
            ));
            continue;
        }
        let tree_oid = text.lines().next().unwrap_or("").trim().to_string();
        let commit = match git(
            linux,
            &[
                "commit-tree",
                "--no-gpg-sign",
                "-p",
                &sha,
                "-p",
                &ctx.tip,
                "-m",
                "beamfs-bench upstream: merge check",
                &tree_oid,
            ],
        ) {
            Ok(c) => c,
            Err(e) => {
                problems.push(format!("{rev} ({desc}): {e:#}"));
                continue;
            }
        };
        let wt = match Worktree::add(linux, &ctx.cfg.out.join(format!("tree-newer-{i}")), &commit)
        {
            Ok(w) => w,
            Err(e) => {
                problems.push(format!("{rev} ({desc}): {e:#}"));
                continue;
            }
        };
        let mut v = template.clone();
        v.dir = format!("build-newer-{i}");
        let (p, _) = build_inner(ctx, &wt.path, &v);
        if p.is_empty() {
            notes.push(format!("{rev} ({desc}): merges, builds, no warning"));
        }
        problems.extend(p.into_iter().map(|x| format!("{rev} ({desc}): {x}")));
        drop(wt);
        discard(ctx, &v.dir);
    }
    finish(
        "newer",
        t0,
        problems,
        format!(
            "merges into and builds on {}, {}",
            ctx.cfg.newer.join(", "),
            template.what
        ),
        notes,
    )
}

fn htmldocs(
    tree: &Path,
    o: &Path,
    dirs: Option<&str>,
    log: &Path,
) -> Result<BTreeMap<String, usize>> {
    std::fs::create_dir_all(o).with_context(|| format!("create {}", o.display()))?;
    let mut c = Command::new("make");
    c.arg("-C").arg(tree).arg(format!("O={}", o.display()));
    if let Some(d) = dirs {
        c.arg(format!("SPHINXDIRS={d}"));
    }
    c.arg("htmldocs");
    let out = output(&mut c)?;
    let text = lossy(&out);
    std::fs::write(log, text.as_bytes()).with_context(|| format!("write {}", log.display()))?;
    if !out.status.success() {
        bail!(
            "make htmldocs failed in {}, see {}",
            tree.display(),
            log.display()
        );
    }
    Ok(doc_warnings(&text, &path_str(tree)))
}

/// make refcheckdocs: references to files that do not exist.
fn refcheck(tree: &Path, o: &Path) -> Result<BTreeMap<String, usize>> {
    std::fs::create_dir_all(o).with_context(|| format!("create {}", o.display()))?;
    let out = output(
        Command::new("make")
            .arg("-C")
            .arg(tree)
            .arg(format!("O={}", o.display()))
            .arg("refcheckdocs"),
    )?;
    let text = lossy(&out);
    if !out.status.success() {
        bail!(
            "make refcheckdocs failed in {}: {}",
            tree.display(),
            text.trim()
        );
    }
    let root = path_str(tree);
    let mut m = BTreeMap::new();
    for l in text
        .lines()
        .filter(|l| l.to_ascii_lowercase().contains("warning"))
    {
        *m.entry(l.replace(&root, "SRC").trim().to_string())
            .or_insert(0) += 1;
    }
    Ok(m)
}

fn check_docs(ctx: &Ctx) -> Check {
    let t0 = Instant::now();
    let dirs = doc_dirs(&ctx.changed);
    if dirs.is_empty() {
        return skip("docs", t0, "the series changes no documentation".to_string());
    }
    let sphinx = if dirs.iter().any(|d| d == ".") {
        None
    } else {
        Some(dirs.join(" "))
    };
    let base = match Worktree::add(&ctx.cfg.linux, &ctx.cfg.out.join("tree-base"), &ctx.base_sha)
    {
        Ok(w) => w,
        Err(e) => return finish("docs", t0, vec![format!("{e:#}")], String::new(), Vec::new()),
    };
    let series_out = ctx.cfg.out.join("doc-series");
    let base_out = ctx.cfg.out.join("doc-base");
    let mut problems = Vec::new();
    let mut notes = vec![format!(
        "SPHINXDIRS: {}",
        sphinx.as_deref().unwrap_or("the whole tree")
    )];
    let s = htmldocs(
        &ctx.tree,
        &series_out,
        sphinx.as_deref(),
        &ctx.logs().join("htmldocs-series.txt"),
    );
    let b = htmldocs(
        &base.path,
        &base_out,
        sphinx.as_deref(),
        &ctx.logs().join("htmldocs-base.txt"),
    );
    match (s, b) {
        (Ok(s), Ok(b)) => {
            problems.extend(
                new_entries(&s, &b)
                    .into_iter()
                    .map(|w| format!("htmldocs: {w}")),
            );
            notes.push(format!(
                "htmldocs: {} warning(s) in the base, {} with the series",
                b.values().sum::<usize>(),
                s.values().sum::<usize>()
            ));
        }
        (Err(e), _) | (_, Err(e)) => problems.push(format!("{e:#}")),
    }
    match (
        refcheck(&ctx.tree, &series_out),
        refcheck(&base.path, &base_out),
    ) {
        (Ok(s), Ok(b)) => problems.extend(
            new_entries(&s, &b)
                .into_iter()
                .map(|w| format!("refcheckdocs: {w}")),
        ),
        (Err(e), _) | (_, Err(e)) => problems.push(format!("{e:#}")),
    }
    drop(base);
    finish(
        "docs",
        t0,
        problems,
        "no documentation warning and no broken file reference the base does not have"
            .to_string(),
        notes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subject_carries_its_prefix() {
        assert_eq!(
            mail_subject("RFC PATCH", 1, 18, "beamfs: x"),
            "[RFC PATCH 01/18] beamfs: x"
        );
        assert_eq!(mail_subject("PATCH", 3, 9, "y"), "[PATCH 3/9] y");
        assert_eq!(mail_subject("RFC PATCH", 0, 18, "c"), "[RFC PATCH 00/18] c");
        // A subject exactly at the limit, prefix included.
        let s = mail_subject("RFC PATCH", 2, 18, "beamfs: add in-core header and tracepoints");
        assert_eq!(s.chars().count(), SUBJECT_MAX);
    }

    #[test]
    fn a_message_is_held_to_its_trailers() {
        let a = "Aurelien DESBRIERES <aurelien@hackers.camp>";
        let good = "beamfs: x\n\nBody.\n\nAssisted-by: LLM\nSigned-off-by: Aurelien DESBRIERES <aurelien@hackers.camp>\n";
        assert!(message_findings(good, a, "LLM").is_empty());
        let bad = "beamfs: x\n\nCo-Authored-By: Someone <x@y>\nClaude-Session: https://example.invalid/s\n";
        let f = message_findings(bad, a, "LLM");
        assert!(f.iter().any(|s| s.contains("Signed-off-by")));
        assert!(f.iter().any(|s| s.contains("Assisted-by")));
        assert!(f.iter().any(|s| s.contains("Co-Authored-By")));
        assert!(f.iter().any(|s| s.contains("session link")));
        let dash = "x\u{2014}y\n\nSigned-off-by: A <a@b>\n";
        assert_eq!(message_findings(dash, "A <a@b>", "").len(), 1);
    }

    #[test]
    fn checkpatch_lines_are_read() {
        let out = "fs/beamfs/beamfs_format.h:177: WARNING:LONG_LINE_COMMENT: line length of 103 exceeds 100 columns\n\
                   fs/beamfs/beamfs.h:51: CHECK:UNCOMMENTED_DEFINITION: spinlock_t definition without comment\n\
                   fs/beamfs/beamfs_format.h:8: WARNING:FILE_PATH_CHANGES: added, moved or deleted file(s), does MAINTAINERS need updating?\n\
                   total: 0 errors, 2 warnings, 1206 lines checked\n";
        let f = parse_checkpatch(out);
        assert_eq!(f.len(), 3);
        assert_eq!(
            (f[0].level.as_str(), f[0].kind.as_str()),
            ("WARNING", "LONG_LINE_COMMENT")
        );
        assert_eq!(
            (f[1].level.as_str(), f[1].kind.as_str()),
            ("CHECK", "UNCOMMENTED_DEFINITION")
        );
        assert_eq!(f[2].kind, "FILE_PATH_CHANGES");
    }

    #[test]
    fn a_spdxcheck_that_cannot_start_is_noticed() {
        let tb = "Traceback (most recent call last):\n  File \"scripts/spdxcheck.py\", line 6\nModuleNotFoundError: No module named 'ply'\n";
        assert!(spdx_failed(tb));
        assert!(!spdx_failed(""));
    }

    #[test]
    fn placeholders_are_found_and_hunks_are_not() {
        assert_eq!(
            placeholders("text\n@@VALIDATION@@\n"),
            vec!["@@VALIDATION@@".to_string()]
        );
        assert_eq!(placeholders("*** SUBJECT HERE ***").len(), 1);
        assert!(placeholders("@@ -0,0 +1,3 @@\nmail@@host").is_empty());
    }

    #[test]
    fn kconfig_entries_are_read() {
        let k = "config BEAMFS_FS\n\ttristate \"x\"\n\tdepends on BLOCK\n\thelp\n\t  One.\n\n\t  Two.\n\n\
                 config BEAMFS_DEBUG_TREE\n\tbool \"y\"\n\tdefault n\n\thelp\n\t  Three.\n\n\
                 config BEAMFS_ORDERED_META\n\tbool \"z\"\n\tdefault y\n\n\
                 config BEAMFS_HIDDEN\n\tdef_bool y\n";
        let e = kconfig_entries(k);
        assert_eq!(e.len(), 4);
        assert_eq!(
            (e[0].kind.as_str(), e[0].prompt, e[0].help_lines),
            ("tristate", true, 2)
        );
        assert_eq!((e[1].kind.as_str(), e[1].help_lines), ("bool", 1));
        assert_eq!(e[1].defaults, vec!["n".to_string()]);
        assert_eq!(
            (e[2].help_lines, e[2].defaults.clone()),
            (0, vec!["y".to_string()])
        );
        assert_eq!((e[3].kind.as_str(), e[3].prompt), ("bool", false));
    }

    #[test]
    fn config_values_are_read() {
        let c = "CONFIG_A=y\nCONFIG_B=m\n# CONFIG_C is not set\nCONFIG_D=\"x\"\n";
        assert_eq!(config_value(c, "A"), 'y');
        assert_eq!(config_value(c, "B"), 'm');
        assert_eq!(config_value(c, "C"), 'n');
        assert_eq!(config_value(c, "D"), 'v');
        assert_eq!(config_value(c, "E"), 'n');
    }

    #[test]
    fn module_parameters_and_their_descriptions() {
        let src = "#define P(x) module_param(x, uint, 0644)\n\
                   module_param_named(scrub_interval_ms, beamfs_scrub_ms, uint, 0644);\n\
                   MODULE_PARM_DESC(scrub_interval_ms, \"ms\");\n\
                   module_param(clock_source, uint, 0444);\n";
        let p = module_params(src);
        assert_eq!(
            p.into_iter().collect::<Vec<_>>(),
            vec!["clock_source".to_string(), "scrub_interval_ms".to_string()]
        );
        let d = param_descriptions(src);
        assert!(d.contains("scrub_interval_ms") && !d.contains("clock_source"));
    }

    #[test]
    fn sysfs_attributes_are_found() {
        let src = "#define BEAMFS_RW_ATTR(_name) \\\n\
                   \tstatic struct kobj_attribute a_##_name = __ATTR(_name, 0644, s, t)\n\
                   static struct kobj_attribute x = __ATTR(interval, 0644, a, b);\n\
                   BEAMFS_RW_ATTR(alert_rate_limit);\n\
                   ATTRIBUTE_GROUPS(beamfs);\n";
        let a = sysfs_attributes(src);
        assert_eq!(
            a.into_iter().collect::<Vec<_>>(),
            vec!["alert_rate_limit".to_string(), "interval".to_string()]
        );
    }

    #[test]
    fn a_path_component_is_matched_whole() {
        let abi = "What: /sys/fs/beamfs/<dev>/interval\nWhat: /sys/fs/beamfs/<dev>/passes\n";
        assert!(mentions_component(abi, "interval"));
        assert!(mentions_component(abi, "passes"));
        assert!(!mentions_component(abi, "pass"));
        assert!(!mentions_component(abi, "cursor"));
    }

    #[test]
    fn the_module_patch_is_a_patch() {
        let p = module_patch(
            "A <a@b>",
            &[
                ("fs/x/a.c".to_string(), b"one\ntwo\n".to_vec()),
                ("fs/x/b.h".to_string(), b"no newline".to_vec()),
            ],
        );
        assert!(p.contains("+++ b/fs/x/a.c\n@@ -0,0 +1,2 @@\n+one\n+two\n"));
        assert!(p.contains("@@ -0,0 +1,1 @@\n+no newline\n\\ No newline at end of file\n"));
        assert!(p.contains("Signed-off-by: A <a@b>\n---\n"));
    }

    #[test]
    fn section_names_are_read() {
        let r = "  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al\n\
                 \x20 [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0\n\
                 \x20 [ 1] .text             PROGBITS        0000000000000000 000040 0003a2 00  AX  0   0 16\n\
                 \x20 [ 2] .rela.text        RELA            0000000000000000 001234 000120 18   I 20   1  8\n\
                 \x20 [ 3] .text.unlikely    PROGBITS        0000000000000000 0003e2 000010 00  AX  0   0  1\n\
                 \x20 [ 4] .init.text        PROGBITS        0000000000000000 0003f2 000010 00  AX  0   0  1\n";
        let names = section_names(r);
        assert_eq!(
            names,
            vec![".text", ".rela.text", ".text.unlikely", ".init.text"]
        );
        let code: Vec<&str> = names
            .iter()
            .map(String::as_str)
            .filter(|n| is_text_section(n))
            .collect();
        assert_eq!(code, vec![".text", ".text.unlikely", ".init.text"]);
    }

    #[test]
    fn relocations_are_compared_without_file_offsets() {
        let r = "Relocation section '.rela.text' at offset 0x1234 contains 2 entries:\n\
                 \x20   Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n\
                 0000000000000005  0000001a00000004 R_X86_64_PLT32         0000000000000000 printk - 4\n\
                 000000000000000c  0000000500000002 R_X86_64_PC32          0000000000000000 .rodata.str1.1 + 1c\n\
                 Relocation section '.rela.init.text' at offset 0x1300 contains 1 entry:\n\
                 0000000000000001  0000000700000004 R_X86_64_PLT32         0000000000000000 register_filesystem - 4\n\
                 Relocation section '.rela__bug_table' at offset 0x2000 contains 1 entry:\n\
                 0000000000000000  0000000200000002 R_X86_64_PC32          0000000000000000 .text + 10\n";
        let s = [".text".to_string(), ".init.text".to_string()];
        assert_eq!(
            relocs_of(r, &s),
            vec![
                ".rela.text 0000000000000005 R_X86_64_PLT32 printk - 4".to_string(),
                ".rela.text 000000000000000c R_X86_64_PC32 .rodata.str1.1 + 1c".to_string(),
                ".rela.init.text 0000000000000001 R_X86_64_PLT32 register_filesystem - 4"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn doc_warnings_lose_their_tree_and_their_line_numbers() {
        let w = doc_warnings(
            "/x/tree/Documentation/a.rst:3: WARNING: y\n/x/tree/Documentation/a.rst:9: WARNING: y\nnothing\n",
            "/x/tree",
        );
        assert_eq!(w.get("SRC/Documentation/a.rst:N: WARNING: y"), Some(&2));
        assert_eq!(w.len(), 1);
        let base: BTreeMap<String, usize> =
            [("SRC/Documentation/a.rst:N: WARNING: y".to_string(), 1)].into();
        assert_eq!(new_entries(&w, &base).len(), 1);
        assert!(new_entries(&base, &w).is_empty());
    }

    #[test]
    fn line_numbers_are_stripped_and_text_is_kept() {
        assert_eq!(strip_line_numbers("a.rst:12:34: x"), "a.rst:N:N: x");
        assert_eq!(strip_line_numbers("time 12:30 ok"), "time 12:30 ok");
    }

    #[test]
    fn the_documentation_decides_the_sphinx_dirs() {
        let c = [
            "Documentation/filesystems/beamfs.rst",
            "Documentation/filesystems/index.rst",
            "Documentation/ABI/testing/sysfs-fs-beamfs",
            "MAINTAINERS",
        ]
        .map(str::to_string);
        assert_eq!(doc_dirs(&c), vec!["admin-guide", "filesystems"]);
        assert!(doc_dirs(&["fs/beamfs/super.c".to_string()]).is_empty());
    }

    #[test]
    fn checkstack_lines_are_read() {
        let out = "0x0000000000000a3c beamfs_rs_decode [super.o]:\t\t560\n\
                   0x0000000000000b00 beamfs_alloc [alloc.o]:\t\tDynamic\n";
        assert_eq!(
            checkstack_entries(out),
            vec![("beamfs_rs_decode [super.o]".to_string(), 560)]
        );
    }

    #[test]
    fn the_author_mail_is_read() {
        assert_eq!(author_mail("A B <a@b.c>"), "a@b.c");
        assert_eq!(author_mail("bare"), "bare");
    }

    #[test]
    fn build_diagnostics_are_told_from_object_names() {
        assert!(is_diagnostic("fs/beamfs/super.c:12:3: warning: unused variable"));
        assert!(is_diagnostic("ERROR: modpost: \"x\" [fs/beamfs/beamfs.ko] undefined!"));
        assert!(!is_diagnostic("  CC      arch/x86/boot/compressed/error.o"));
    }

    #[test]
    fn compiled_objects_are_counted() {
        let t = "  CC      fs/beamfs/super.o\n  CC [M]  fs/beamfs/alloc.o\n  CHECK   fs/beamfs/super.c\n  CC      fs/ext4/super.o\n";
        assert_eq!(count_tagged(t, "CC", "beamfs"), 2);
        assert_eq!(count_tagged(t, "CHECK", "beamfs"), 1);
    }

    #[test]
    fn remotes_and_interpreters_are_named() {
        let n = ["origin/master", "next/master", "v7.3-rc6", "origin/x"].map(str::to_string);
        assert_eq!(remotes_of(&n), vec!["next", "origin"]);
        assert_eq!(python_minor("python3.14"), Some(14));
        assert_eq!(python_minor("python3"), None);
        assert_eq!(python_minor("python3.14-config"), None);
    }

    #[test]
    fn non_ascii_lines_are_numbered() {
        assert_eq!(non_ascii_lines("a\nAur\u{e9}lien\nb\n"), vec![2]);
    }
}
