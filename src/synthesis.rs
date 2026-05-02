//! synthesis.rs - generate synthesis.md + synthesis.json from a completed run.
//!
//! Output format byte-identical to Tir-multifs.sh phase 4. Reference target:
//! Documentation/runs/beamfs-bench-analyse-20260430-141008/{synthesis.md,synthesis.json}.
//!
//! Critical parity points:
//!   - synthesis.md table headers, column widths, padding match bash printf.
//!   - The Topology table keeps "BEAMFS" UPPERCASE (matches bash; will be
//!     normalized in a separate lowercase pass per beamfs-devel TODO 1).
//!   - The Head-to-head table row labels are lowercase fs names from FS_LIST.
//!   - synthesis.json keeps the leading empty string element matching the
//!     `echo "" > all-records.txt` blank line in bash.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn write_synthesis_md(
    run_dir: &Path,
    ts_human: &str,
    fs_list: &[(&str, &str)],
    probs: &[u32],
    per_fs_dir: &Path,
) -> Result<()> {
    let synth_path = run_dir.join("synthesis.md");
    let mut f = fs::File::create(&synth_path)
        .with_context(|| format!("create {:?}", synth_path))?;

    writeln!(f, "# beamfs-bench-multifs head-to-head report")?;
    writeln!(f)?;
    writeln!(f, "**Date**: {ts_human}")?;
    writeln!(f, "**Run dir**: `{}`", run_dir.display())?;
    writeln!(f)?;
    writeln!(f, "## Topology")?;
    writeln!(f)?;
    writeln!(f, "5 USB physical disks attached to beamfs-compute01 VM (cache='none' io='threads'); master is isolated orchestrator:")?;
    writeln!(f)?;
    writeln!(f, "| FS       | Device | USB by-id (truncated)             |")?;
    writeln!(f, "|----------|--------|-----------------------------------|")?;
    writeln!(f, "| ext4     | vdc    | Kingston DataTraveler ...DA006B   |")?;
    writeln!(f, "| ext3     | vdd    | Kingston DataTraveler ...D70052   |")?;
    writeln!(f, "| btrfs    | vde    | Kingston DataTraveler ...E60058   |")?;
    writeln!(f, "| squashfs | vdf    | Kingston DataTraveler ...0ED05    |")?;
    writeln!(f, "| beamfs   | vdg    | SanDisk Cruzer ...09503233        |")?;
    writeln!(f)?;
    writeln!(f, "Test layout per partition: 3 dirs (A/B/C) x 3 files of 3KB + HASHES.sha256.")?;
    writeln!(f, "Attack target: dir-B/file-B2.bin.")?;
    writeln!(f)?;
    writeln!(f, "## Head-to-head results")?;
    writeln!(f)?;

    // Parse all-records.txt to extract VERDICT and FLIP_DELTA per (fs, prob).
    let all_records_path = run_dir.join("all-records.txt");
    let records = fs::read_to_string(&all_records_path)
        .with_context(|| format!("read {:?}", all_records_path))?;

    // Build the table data first, then compute column widths, then render.
    // This makes the head-to-head table self-aligning: the column widths
    // adapt to the actual content (verdicts of variable length, flip counts
    // of variable digit count, modes lists with multiple entries) instead
    // of being hardcoded as in the legacy Tir-multifs.sh output.
    struct Row {
        fs: String,
        cells: Vec<String>,
        modes: String,
    }
    let mut rows: Vec<Row> = Vec::with_capacity(fs_list.len());
    for &(fs_name, _vd) in fs_list {
        let mut cells: Vec<String> = Vec::with_capacity(probs.len());
        let mut modes_seen: Vec<String> = Vec::new();
        for &prob in probs {
            let verdict = extract_verdict(&records, fs_name, prob).unwrap_or_else(|| "?".to_string());
            let flips = extract_flip_delta(&records, fs_name, prob).unwrap_or_else(|| "?".to_string());
            cells.push(format!("{verdict} ({flips} flip)"));
            if !modes_seen.iter().any(|m| m == &verdict) {
                modes_seen.push(verdict);
            }
        }
        rows.push(Row {
            fs: fs_name.to_string(),
            cells,
            modes: modes_seen.join(" "),
        });
    }

    // Header texts for the prob columns
    let prob_headers: Vec<String> = probs.iter()
        .map(|p| format!("prob {p} ppm"))
        .collect();

    // Compute per-column max width (header vs all rows)
    let fs_w = std::cmp::max(2, rows.iter().map(|r| r.fs.len()).max().unwrap_or(2));
    let mut prob_w: Vec<usize> = prob_headers.iter().map(|h| h.len()).collect();
    for r in &rows {
        for (i, c) in r.cells.iter().enumerate() {
            if i < prob_w.len() && c.len() > prob_w[i] {
                prob_w[i] = c.len();
            }
        }
    }
    let modes_w = std::cmp::max(
        "Modes obs.".len(),
        rows.iter().map(|r| r.modes.len()).max().unwrap_or(0),
    );

    // Render header row
    write!(f, "| {:<fs_w$} ", "FS")?;
    for (i, h) in prob_headers.iter().enumerate() {
        write!(f, "| {:<w$} ", h, w = prob_w[i])?;
    }
    writeln!(f, "| {:<modes_w$} |", "Modes obs.")?;

    // Render separator row (markdown table syntax: dashes per column)
    write!(f, "|{:-<sep_w$}", "", sep_w = fs_w + 2)?;
    for w in &prob_w {
        write!(f, "|{:-<sep_w$}", "", sep_w = w + 2)?;
    }
    writeln!(f, "|{:-<sep_w$}|", "", sep_w = modes_w + 2)?;

    // Render data rows
    for r in &rows {
        write!(f, "| {:<fs_w$} ", r.fs)?;
        for (i, c) in r.cells.iter().enumerate() {
            write!(f, "| {:<w$} ", c, w = prob_w[i])?;
        }
        writeln!(f, "| {:<modes_w$} |", r.modes)?;
    }

    writeln!(f)?;
    writeln!(f, "## Detailed per-FS results")?;
    writeln!(f)?;

    for &(fs_name, _vd) in fs_list {
        writeln!(f, "### {fs_name}")?;
        writeln!(f)?;
        let setup = fs::read_to_string(per_fs_dir.join(fs_name).join("setup.txt"))
            .with_context(|| format!("read setup.txt for {fs_name}"))?;
        writeln!(f, "**Setup**: {}", setup.trim_end())?;
        writeln!(f)?;
        writeln!(f, "**Per-prob results**:")?;
        writeln!(f, "```")?;
        let attacks = fs::read_to_string(per_fs_dir.join(fs_name).join("attacks.txt"))
            .with_context(|| format!("read attacks.txt for {fs_name}"))?;
        write!(f, "{attacks}")?;
        writeln!(f, "---")?;
        let verifies = fs::read_to_string(per_fs_dir.join(fs_name).join("verifies.txt"))
            .with_context(|| format!("read verifies.txt for {fs_name}"))?;
        write!(f, "{verifies}")?;
        writeln!(f, "```")?;
        writeln!(f)?;
    }

    Ok(())
}

pub fn write_synthesis_json(
    run_dir: &Path,
    ts_human: &str,
    all_records_path: &Path,
) -> Result<()> {
    let synth_path = run_dir.join("synthesis.json");
    let mut f = fs::File::create(&synth_path)
        .with_context(|| format!("create {:?}", synth_path))?;

    writeln!(f, "{{")?;
    writeln!(f, "  \"timestamp\": \"{ts_human}\",")?;
    writeln!(f, "  \"run_dir\": \"{}\",", run_dir.display())?;
    writeln!(f, "  \"topology\": \"5 USB physical (vdc-vdg), cache=none io=threads\",")?;
    writeln!(f, "  \"records\": [")?;

    let records = fs::read_to_string(all_records_path)
        .with_context(|| format!("read {:?}", all_records_path))?;
    // Mirror bash: read line-by-line, escape `"` to `\"`, emit
    //   `    "<line>"` separated by `,\n`. The first line in
    // all-records.txt is empty (from `echo "" > ...`), so the first
    // emitted entry is `""`.
    let lines: Vec<&str> = records.split('\n').collect();
    // Bash reads with `while IFS= read -r line; done < file`, which
    // stops at EOF without yielding an empty trailing line if the file
    // ends with `\n`. So we drop a trailing empty element if present.
    let lines = if lines.last() == Some(&"") {
        &lines[..lines.len() - 1]
    } else {
        &lines[..]
    };

    let mut first = true;
    for line in lines {
        if !first {
            writeln!(f, ",")?;
        } else {
            first = false;
        }
        let escaped = line.replace('\\', "\\\\").replace('"', "\\\"");
        write!(f, "    \"{escaped}\"")?;
    }
    writeln!(f)?;
    writeln!(f, "  ]")?;
    writeln!(f, "}}")?;

    Ok(())
}

// ============================================================
// bench-2 redesign (substep 10) : verdict derivation from
// factual fields emitted by worker.sh attack)/verify) actions.
//
// worker.sh now emits raw observations only:
//   ATTACK|FS=<fs>|PROB=<p>|CALL_DELTA=...|FLIP_DELTA=...
//          |TARGET=...|HASH_PRE=<sha>|HASH_POST=<sha|cat_failed|missing>
//          |CAT_RC=<n>|RS_CORRECTED=<k>
//          |DMESG_UNCORRECTABLE=<k>|DMESG_EIO=<k>
//   VERIFY|fs=<fs>|prob=<p>|VERDICT=<MOUNTED|FS_PANIC>|...
//
// The judgment (RS_RECOVERED, RS_PASSTHROUGH, etc.) is derived
// here, not in the worker. This matches the bitrot/metadata/crash
// scopes ("measurement instrument, not judgment engine").
//
// Decision table for fs == "beamfs":
//   mount_state == FS_PANIC                    -> FS_PANIC
//   CAT_RC != 0                                -> RS_FAILED
//   HASH_POST != HASH_PRE                      -> CORRUPTED_DATA
//   HASH_POST == HASH_PRE && RS_CORRECTED > 0  -> RS_RECOVERED
//   HASH_POST == HASH_PRE && RS_CORRECTED == 0 -> RS_PASSTHROUGH
//
// Decision table for fs != "beamfs" (no FEC):
//   mount_state == FS_PANIC                    -> FS_PANIC
//   CAT_RC != 0                                -> FS_PANIC
//   HASH_POST != HASH_PRE                      -> CORRUPTED_DATA
//   HASH_POST == HASH_PRE                      -> RECOVERED
// ============================================================

/// Extract a `KEY=value` field from an ATTACK record matching (fs, prob).
/// Stops at the next `|` separator, or end of line.
fn extract_attack_field(
    records: &str,
    fs_name: &str,
    prob: u32,
    field: &str,
) -> Option<String> {
    let needle_fs = format!("FS={fs_name}");
    let needle_prob = format!("PROB={prob}");
    let needle_field = format!("{field}=");
    for line in records.lines() {
        if line.starts_with("ATTACK|")
            && line.contains(&needle_fs)
            && line.contains(&needle_prob)
            && line.contains(&needle_field)
        {
            if let Some(idx) = line.find(&needle_field) {
                let rest = &line[idx + needle_field.len()..];
                let value: String = rest
                    .chars()
                    .take_while(|c| *c != '|')
                    .collect();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// Extract the raw VERDICT field from a VERIFY record matching (fs, prob).
/// Returns the worker.sh mount-state sentinel: "MOUNTED" or "FS_PANIC".
fn extract_verify_state(records: &str, fs_name: &str, prob: u32) -> Option<String> {
    let needle_fs = format!("fs={fs_name}");
    let needle_prob = format!("prob={prob}");
    for line in records.lines() {
        if line.starts_with("VERIFY|")
            && line.contains("VERDICT=")
            && line.contains(&needle_fs)
            && line.contains(&needle_prob)
        {
            if let Some(idx) = line.find("VERDICT=") {
                let rest = &line[idx + "VERDICT=".len()..];
                let v: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_uppercase() || *c == '_')
                    .collect();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Derive bench-2 verdict for FS=beamfs (FEC-protected).
fn derive_verdict_beamfs(
    mount_state: &str,
    cat_rc: i32,
    hash_pre: &str,
    hash_post: &str,
    rs_corrected: u32,
) -> &'static str {
    if mount_state == "FS_PANIC" {
        return "FS_PANIC";
    }
    if cat_rc != 0 {
        return "RS_FAILED";
    }
    if hash_pre == "missing" || hash_post == "missing" || hash_post == "cat_failed" {
        return "RS_FAILED";
    }
    if hash_post != hash_pre {
        return "CORRUPTED_DATA";
    }
    if rs_corrected > 0 {
        "RS_RECOVERED"
    } else {
        "RS_PASSTHROUGH"
    }
}

/// Derive bench-2 verdict for FS != beamfs (no FEC).
fn derive_verdict_legacy(
    mount_state: &str,
    cat_rc: i32,
    hash_pre: &str,
    hash_post: &str,
) -> &'static str {
    if mount_state == "FS_PANIC" {
        return "FS_PANIC";
    }
    if cat_rc != 0 {
        return "FS_PANIC";
    }
    if hash_pre == "missing" || hash_post == "missing" || hash_post == "cat_failed" {
        return "FS_PANIC";
    }
    if hash_post != hash_pre {
        "CORRUPTED_DATA"
    } else {
        "RECOVERED"
    }
}

fn extract_verdict(records: &str, fs_name: &str, prob: u32) -> Option<String> {
    let mount_state = extract_verify_state(records, fs_name, prob)?;
    let cat_rc: i32 = extract_attack_field(records, fs_name, prob, "CAT_RC")
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1);
    let hash_pre = extract_attack_field(records, fs_name, prob, "HASH_PRE")
        .unwrap_or_else(|| "missing".to_string());
    let hash_post = extract_attack_field(records, fs_name, prob, "HASH_POST")
        .unwrap_or_else(|| "missing".to_string());
    let rs_corrected: u32 = extract_attack_field(records, fs_name, prob, "RS_CORRECTED")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let verdict = if fs_name == "beamfs" {
        derive_verdict_beamfs(&mount_state, cat_rc, &hash_pre, &hash_post, rs_corrected)
    } else {
        derive_verdict_legacy(&mount_state, cat_rc, &hash_pre, &hash_post)
    };
    Some(verdict.to_string())
}

fn extract_flip_delta(records: &str, fs_name: &str, prob: u32) -> Option<String> {
    extract_attack_field(records, fs_name, prob, "FLIP_DELTA")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(attack: &str, verify: &str) -> String {
        format!("\n{attack}\n{verify}\n")
    }

    // -------- beamfs cases --------

    #[test]
    fn beamfs_rs_recovered() {
        // hash matches + RS_CORRECTED > 0 -> RS_RECOVERED
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=3|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=2|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_verdict(&r, "beamfs", 1_000_000).as_deref(), Some("RS_RECOVERED"));
    }

    #[test]
    fn beamfs_rs_passthrough() {
        // hash matches + RS_CORRECTED == 0 -> RS_PASSTHROUGH (no flip hit the file)
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000|CALL_DELTA=2|FLIP_DELTA=0|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=beamfs|prob=1000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_verdict(&r, "beamfs", 1000).as_deref(), Some("RS_PASSTHROUGH"));
    }

    #[test]
    fn beamfs_rs_failed_cat_eio() {
        // CAT_RC != 0 -> RS_FAILED (uncorrectable, EIO returned)
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=10|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=cat_failed|CAT_RC=1|RS_CORRECTED=0|DMESG_UNCORRECTABLE=1|DMESG_EIO=1",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=MOUNTED|DIFFS_PRE_POST=2|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=1|details=ok",
        );
        assert_eq!(extract_verdict(&r, "beamfs", 1_000_000).as_deref(), Some("RS_FAILED"));
    }

    #[test]
    fn beamfs_corrupted_data_silent() {
        // hash mismatch but cat OK -> CORRUPTED_DATA (silent corruption, FEC missed)
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=5|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=def|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=MOUNTED|DIFFS_PRE_POST=2|DIFFS_PRE_REMOUNT=2|N_FILES_CHANGED=1|details=ok",
        );
        assert_eq!(extract_verdict(&r, "beamfs", 1_000_000).as_deref(), Some("CORRUPTED_DATA"));
    }

    #[test]
    fn beamfs_fs_panic_on_remount() {
        // VERIFY VERDICT=FS_PANIC propagates regardless of attack record
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=99|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=cat_failed|CAT_RC=1|RS_CORRECTED=0|DMESG_UNCORRECTABLE=5|DMESG_EIO=3",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=FS_PANIC|details=remount failed",
        );
        assert_eq!(extract_verdict(&r, "beamfs", 1_000_000).as_deref(), Some("FS_PANIC"));
    }

    // -------- legacy FS cases --------

    #[test]
    fn legacy_recovered_no_flips() {
        let r = rec(
            "ATTACK|FS=ext4|PROB=1000|CALL_DELTA=2|FLIP_DELTA=0|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=ext4|prob=1000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_verdict(&r, "ext4", 1000).as_deref(), Some("RECOVERED"));
    }

    #[test]
    fn legacy_corrupted_data() {
        let r = rec(
            "ATTACK|FS=ext4|PROB=100000|CALL_DELTA=10|FLIP_DELTA=5|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=def|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=ext4|prob=100000|VERDICT=MOUNTED|DIFFS_PRE_POST=2|DIFFS_PRE_REMOUNT=2|N_FILES_CHANGED=1|details=ok",
        );
        assert_eq!(extract_verdict(&r, "ext4", 100_000).as_deref(), Some("CORRUPTED_DATA"));
    }

    #[test]
    fn legacy_fs_panic_on_panic() {
        let r = rec(
            "ATTACK|FS=btrfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=99|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=cat_failed|CAT_RC=1|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=2",
            "VERIFY|fs=btrfs|prob=1000000|VERDICT=FS_PANIC|details=remount failed",
        );
        assert_eq!(extract_verdict(&r, "btrfs", 1_000_000).as_deref(), Some("FS_PANIC"));
    }

    #[test]
    fn extract_attack_field_basic() {
        let r = "ATTACK|FS=beamfs|PROB=1000|HASH_PRE=abc123|HASH_POST=def456|CAT_RC=0|RS_CORRECTED=2";
        assert_eq!(extract_attack_field(r, "beamfs", 1000, "HASH_PRE").as_deref(), Some("abc123"));
        assert_eq!(extract_attack_field(r, "beamfs", 1000, "RS_CORRECTED").as_deref(), Some("2"));
        assert_eq!(extract_attack_field(r, "beamfs", 1000, "MISSING_FIELD"), None);
    }
}
