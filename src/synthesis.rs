//! synthesis.rs - generate synthesis.md + synthesis.json from a completed run.
//!
//! Derived from Tir-multifs.sh phase 4. Reference target:
//! Documentation/runs/beamfs-bench-analyse-20260430-141008/{synthesis.md,synthesis.json}.
//!
//! Parity with the bash script was the rule until 2026-09-19 and is no
//! longer: the Topology table is rendered from `fs_list` rather than from
//! the literal rows the script wrote, because those rows named, for every
//! one of the five filesystems, another one's device. A report that cannot
//! contradict its own records is worth more than one that matches a script
//! byte for byte. Do not restore the literals.
//!
//! Remaining parity points:
//!   - synthesis.md table headers, column widths, padding match bash printf.
//!   - The Head-to-head table row labels are lowercase fs names from `FS_LIST`.
//!   - synthesis.json keeps the leading empty string element matching the
//!     `echo "" > all-records.txt` blank line in bash.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

/// One filesystem's row in the head-to-head table. Column widths are
/// computed from the collected rows so the table self-aligns to actual
/// content rather than to hardcoded widths.
struct Row {
    fs: String,
    cells: Vec<String>,
    modes: String,
}

/// Same shape as Row, for the fine-grained verdict table.
struct DetailRow {
    fs: String,
    cells: Vec<String>,
    modes: String,
}

/// Row of the copy-on-write characterisation table; carries no modes
/// column, the relocation status being a single value per cell.
struct CowRow {
    fs: String,
    cells: Vec<String>,
}


pub fn write_synthesis_md(
    run_dir: &Path,
    ts_human: &str,
    fs_list: &[(&str, &str)],
    probs: &[u32],
    per_fs_dir: &Path,
) -> Result<()> {
    let synth_path = run_dir.join("synthesis.md");
    let mut f = fs::File::create(&synth_path)
        .with_context(|| format!("create {}", synth_path.display()))?;

    writeln!(f, "# beamfs-bench-multifs head-to-head report")?;
    writeln!(f)?;
    writeln!(f, "**Date**: {ts_human}")?;
    writeln!(f, "**Run dir**: `{}`", run_dir.display())?;
    writeln!(f)?;
    writeln!(f, "## Topology")?;
    writeln!(f)?;
    writeln!(f, "5 USB physical disks attached to beamfs-compute01 VM (cache='none' io='threads'); master is isolated orchestrator:")?;
    writeln!(f)?;
    // Rendered from fs_list, which is the mapping the run actually used.
    // These five rows were literals until 2026-09-19, and every one of
    // them named another filesystem's device: the report said beamfs ran
    // on vdg while the records said vdc. A table that cannot be wrong is
    // one that is not written twice.
    writeln!(f, "| FS       | Device |")?;
    writeln!(f, "|----------|--------|")?;
    for &(fs_name, vd) in fs_list {
        writeln!(f, "| {fs_name:<8} | {vd:<6} |")?;
    }
    writeln!(f)?;
    writeln!(f, "The by-id path and size of each disk are in the device validation table emitted at setup.")?;
    writeln!(f)?;
    writeln!(f, "Test layout per partition: 3 dirs (A/B/C) x 3 files of 3KB + HASHES.sha256.")?;
    writeln!(f, "Attack target: dir-B/file-B2.bin.")?;
    writeln!(f)?;
    writeln!(f, "## Head-to-head results")?;
    writeln!(f)?;

    // Parse all-records.txt to extract VERDICT and FLIP_DELTA per (fs, prob).
    let all_records_path = run_dir.join("all-records.txt");
    let records = fs::read_to_string(&all_records_path)
        .with_context(|| format!("read {}", all_records_path.display()))?;

    // Build the table data first, then compute column widths, then render.
    // This makes the head-to-head table self-aligning: the column widths
    // adapt to the actual content (verdicts of variable length, flip counts
    // of variable digit count, modes lists with multiple entries) instead
    // of being hardcoded as in the legacy Tir-multifs.sh output.
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
    let mut prob_w: Vec<usize> = prob_headers.iter().map(std::string::String::len).collect();
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

    // ============================================================
    // Phase A.1: Verdict detail section. Companion to the head-to-head
    // table above ; uses extract_verdict_detail to expose the
    // fine-grained verdict (KERNEL_PANIC, DETECTED_FAIL_CLOSED,
    // INACCESSIBLE, SILENT_CORRUPTION, RS_RECOVERED, RS_PASSTHROUGH,
    // RECOVERED, CORRUPTED_DATA) that exploits DMESG_UNCORRECTABLE
    // and DMESG_EIO signals.
    // ============================================================
    writeln!(f)?;
    writeln!(f, "## Verdict detail (Phase A.1)")?;
    writeln!(f)?;
    writeln!(f, "Fine-grained verdicts using DMESG_UNCORRECTABLE / DMESG_EIO signals. The legacy `verdict` column above remains unchanged for backward compatibility.")?;
    writeln!(f)?;

    let mut detail_rows: Vec<DetailRow> = Vec::with_capacity(fs_list.len());
    for &(fs_name, _vd) in fs_list {
        let mut cells: Vec<String> = Vec::with_capacity(probs.len());
        let mut modes_seen: Vec<String> = Vec::new();
        for &prob in probs {
            let v = extract_verdict_detail(&records, fs_name, prob).unwrap_or_else(|| "?".to_string());
            cells.push(v.clone());
            if !modes_seen.iter().any(|m| m == &v) {
                modes_seen.push(v);
            }
        }
        detail_rows.push(DetailRow {
            fs: fs_name.to_string(),
            cells,
            modes: modes_seen.join(" "),
        });
    }

    let dfs_w = std::cmp::max(2, detail_rows.iter().map(|r| r.fs.len()).max().unwrap_or(2));
    let mut dprob_w: Vec<usize> = prob_headers.iter().map(std::string::String::len).collect();
    for r in &detail_rows {
        for (i, c) in r.cells.iter().enumerate() {
            if i < dprob_w.len() && c.len() > dprob_w[i] {
                dprob_w[i] = c.len();
            }
        }
    }
    let dmodes_w = std::cmp::max(
        "Modes obs.".len(),
        detail_rows.iter().map(|r| r.modes.len()).max().unwrap_or(0),
    );

    write!(f, "| {:<dfs_w$} ", "FS")?;
    for (i, h) in prob_headers.iter().enumerate() {
        write!(f, "| {:<w$} ", h, w = dprob_w[i])?;
    }
    writeln!(f, "| {:<dmodes_w$} |", "Modes obs.")?;

    write!(f, "|{:-<sep_w$}", "", sep_w = dfs_w + 2)?;
    for w in &dprob_w {
        write!(f, "|{:-<sep_w$}", "", sep_w = w + 2)?;
    }
    writeln!(f, "|{:-<sep_w$}|", "", sep_w = dmodes_w + 2)?;

    for r in &detail_rows {
        write!(f, "| {:<dfs_w$} ", r.fs)?;
        for (i, c) in r.cells.iter().enumerate() {
            write!(f, "| {:<w$} ", c, w = dprob_w[i])?;
        }
        writeln!(f, "| {:<dmodes_w$} |", r.modes)?;
    }

    // ============================================================
    // Phase A.2: CoW characterization section. For each (FS, prob)
    // cell, reports FRAG_RELOCATED status (whether the target file's
    // physical extent moved between pre-attack and post-attack
    // states). CoW filesystems (btrfs, bcachefs) typically show
    // reloc=1 ; in-place filesystems (ext4, ext3, xfs) typically
    // show reloc=0 ; beamfs and squashfs always show 'na' as
    // filefrag is unsupported on those filesystems.
    //
    // The CoW characterization is informational, not a verdict; it
    // helps interpret the legacy verdict and verdict_detail columns
    // by exposing the underlying mechanism (e.g. btrfs's apparent
    // resilience may be partly due to CoW deflecting attacks away
    // from the target's original extent).
    // ============================================================
    writeln!(f)?;
    writeln!(f, "## CoW characterization (Phase A.2)")?;
    writeln!(f)?;
    writeln!(f, "Per-cell FRAG_RELOCATED status from filefrag pre/post diff. CoW filesystems relocate extents on each write ; in-place filesystems update the same physical block. Values: `0` = in-place update, `1` = CoW relocation, `na` = filefrag unsupported or error path.")?;
    writeln!(f)?;

    // Phase A.3: report the workload mode in effect for this run. Reads
    // from the first available cell (any (fs, prob) suffices because the
    // bench uses a single WORKLOAD_MODE per run by construction).
    let mut workload_mode_seen: Option<String> = None;
    for &(fs_name, _vd) in fs_list {
        for &prob in probs {
            if let Some(m) = extract_workload_mode(&records, fs_name, prob) {
                workload_mode_seen = Some(m);
                break;
            }
        }
        if workload_mode_seen.is_some() {
            break;
        }
    }
    let workload_label = workload_mode_seen.unwrap_or_else(|| "static (legacy record)".to_string());
    writeln!(f, "Workload mode for this run: `{workload_label}`. (`static` = FS quiescent during attack ; `write-active` = continuous fio randwrite on TARGET_FILE during attack.)")?;
    writeln!(f)?;


    let mut cow_rows: Vec<CowRow> = Vec::with_capacity(fs_list.len());
    for &(fs_name, _vd) in fs_list {
        let mut cells: Vec<String> = Vec::with_capacity(probs.len());
        for &prob in probs {
            let v = extract_frag_relocated(&records, fs_name, prob).unwrap_or_else(|| "?".to_string());
            // Phase A.4 : co-display ATTACKED_BYTES_UNIQUE alongside the
            // FRAG_RELOCATED status. The two metrics are complementary :
            // FRAG_RELOCATED says whether CoW occurred (qualitative) ;
            // bytes_unique says how many physical bytes were touched
            // (quantitative dose). Together they enable fair cross-FS
            // comparison normalized by attack surface, not bio count.
            let u = extract_attacked_bytes_unique(&records, fs_name, prob).unwrap_or_else(|| "?".to_string());
            cells.push(format!("reloc={v} bytes={u}"));
        }
        cow_rows.push(CowRow {
            fs: fs_name.to_string(),
            cells,
        });
    }

    let cfs_w = std::cmp::max(2, cow_rows.iter().map(|r| r.fs.len()).max().unwrap_or(2));
    let mut cprob_w: Vec<usize> = prob_headers.iter().map(std::string::String::len).collect();
    for r in &cow_rows {
        for (i, c) in r.cells.iter().enumerate() {
            if i < cprob_w.len() && c.len() > cprob_w[i] {
                cprob_w[i] = c.len();
            }
        }
    }

    write!(f, "| {:<cfs_w$} ", "FS")?;
    for (i, h) in prob_headers.iter().enumerate() {
        write!(f, "| {:<w$} ", h, w = cprob_w[i])?;
    }
    writeln!(f, "|")?;

    write!(f, "|{:-<sep_w$}", "", sep_w = cfs_w + 2)?;
    for w in &cprob_w {
        write!(f, "|{:-<sep_w$}", "", sep_w = w + 2)?;
    }
    writeln!(f, "|")?;

    for r in &cow_rows {
        write!(f, "| {:<cfs_w$} ", r.fs)?;
        for (i, c) in r.cells.iter().enumerate() {
            write!(f, "| {:<w$} ", c, w = cprob_w[i])?;
        }
        writeln!(f, "|")?;
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
        .with_context(|| format!("create {}", synth_path.display()))?;

    writeln!(f, "{{")?;
    writeln!(f, "  \"timestamp\": \"{ts_human}\",")?;
    writeln!(f, "  \"run_dir\": \"{}\",", run_dir.display())?;
    writeln!(f, "  \"topology\": \"5 USB physical (vdc-vdg), cache=none io=threads\",")?;
    writeln!(f, "  \"records\": [")?;

    let records = fs::read_to_string(all_records_path)
        .with_context(|| format!("read {}", all_records_path.display()))?;
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
        if first {
            first = false;
        } else {
            writeln!(f, ",")?;
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
/// Returns the worker.sh mount-state sentinel: "MOUNTED" or "`FS_PANIC`".
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
/// The counters were appended rather than folded into a struct, which
/// keeps five consecutive u32 parameters that the compiler cannot tell
/// apart. Grouping them is the right shape and is a change of six
/// signatures; it belongs in its own commit, not in the one that stops
/// a report calling an un-attacked volume a survivor.
#[allow(clippy::too_many_arguments)]
fn derive_verdict_beamfs(
    mount_state: &str,
    cat_rc: i32,
    hash_pre: &str,
    hash_post: &str,
    rs_corrected: u32,
    dmesg_uncorrectable: u32,
    call_delta: u32,
    flip_delta: u32,
) -> &'static str {
    if mount_state == "FS_PANIC" {
        return "FS_PANIC";
    }
    // A run where the injector never fired measured nothing. Saying
    // RS_PASSTHROUGH here would make an un-attacked volume look like one
    // that withstood the campaign -- the 2026-09-19 multifs run scored
    // beamfs RS_PASSTHROUGH on CALL_DELTA=0, FLIP_DELTA=0.
    if call_delta == 0 && flip_delta == 0 {
        return "NOT_EXERCISED";
    }
    if cat_rc != 0 {
        // fail-closed taxonomy: beamfs detected corruption and refused
        // the read. When the kernel logged an UNCORRECTABLE signal
        // (or the bench-side equivalent regex match such as
        // "corrupted (direct|indirect) pointer"), this is the intended
        // behaviour of a fail-closed FEC filesystem under saturation;
        // surface as RS_FAIL_CLOSED so R19 verdict_is_pass can accept it.
        // Otherwise (no kernel signal), it stays RS_FAILED -- the path
        // is broken but we cannot attribute it to a clean FEC detection.
        if dmesg_uncorrectable > 0 {
            return "RS_FAIL_CLOSED";
        }
        return "RS_FAILED";
    }
    if hash_pre == "missing" || hash_post == "missing" || hash_post == "cat_failed" {
        if dmesg_uncorrectable > 0 {
            return "RS_FAIL_CLOSED";
        }
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
    call_delta: u32,
    flip_delta: u32,
) -> &'static str {
    if mount_state == "FS_PANIC" {
        return "FS_PANIC";
    }
    // v0.12.3: no injection reached this filesystem, so nothing about its
    // resilience was measured. Reporting RECOVERED here would make a
    // never-attacked filesystem indistinguishable from one that withstood
    // the campaign; erofs and vfat served the target from cache and would
    // otherwise have been tabulated as survivors.
    if call_delta == 0 && flip_delta == 0 {
        return "NOT_EXERCISED";
    }
    if cat_rc != 0 {
        return "FS_PANIC";
    }
    if hash_pre == "missing" || hash_post == "missing" || hash_post == "cat_failed" {
        return "FS_PANIC";
    }
    if hash_post == hash_pre {
        "RECOVERED"
    } else {
        "CORRUPTED_DATA"
    }
}

// ============================================================
// Phase A.1 -- fine-grained verdict_detail (companion to verdict).
//
// The legacy `verdict` field above keeps 5 values (RS_RECOVERED,
// RS_PASSTHROUGH, RS_FAILED, CORRUPTED_DATA, FS_PANIC) for backward
// compatibility with archived forensics tarballs and the regression_check
// ladder.
//
// `verdict_detail` is a strict refinement that exploits dmesg signals
// (DMESG_UNCORRECTABLE, DMESG_EIO) already collected by worker.sh but
// previously ignored by the derivation. It distinguishes:
//
//   KERNEL_PANIC         : VERIFY VERDICT=FS_PANIC, mount completely broken
//   DETECTED_FAIL_CLOSED : cat_rc != 0 AND dmesg signals corruption
//                          (i.e. kernel detected and refused to serve)
//   INACCESSIBLE         : cat_rc != 0 AND dmesg silent
//                          (i.e. read failed but kernel did not log why)
//   SILENT_CORRUPTION    : hash mismatch AND cat_rc == 0 AND dmesg silent
//                          (i.e. wrong bytes returned, no error path)
//   RS_RECOVERED         : hash match AND rs_corrected > 0  (beamfs only)
//   RS_PASSTHROUGH       : hash match AND rs_corrected == 0 (beamfs only)
//   RECOVERED            : hash match (legacy FS, no FEC distinction)
//   CORRUPTED_DATA       : hash mismatch AND dmesg signals (detected, no FEC)
//
// Both `verdict` and `verdict_detail` are emitted to synthesis.json under
// per_fs_results[].modes_observed and per_fs_results[].modes_observed_detail
// respectively. This keeps existing consumers working while exposing the
// finer taxonomy to new analyses.
// ============================================================

/// Phase A.1: fine-grained verdict for FS=beamfs (FEC-protected).
/// Exploits dmesg signals to distinguish detected-fail-closed from
/// inaccessible-but-silent and from silent corruption.
/// The counters were appended rather than folded into a struct, which
/// keeps five consecutive u32 parameters that the compiler cannot tell
/// apart. Grouping them is the right shape and is a change of six
/// signatures; it belongs in its own commit, not in the one that stops
/// a report calling an un-attacked volume a survivor.
#[allow(clippy::too_many_arguments)]
fn derive_verdict_detail_beamfs(
    mount_state: &str,
    cat_rc: i32,
    hash_pre: &str,
    hash_post: &str,
    rs_corrected: u32,
    dmesg_uncorrectable: u32,
    dmesg_eio: u32,
    call_delta: u32,
    flip_delta: u32,
) -> &'static str {
    if mount_state == "FS_PANIC" {
        return "KERNEL_PANIC";
    }
    // A run where the injector never fired measured nothing. Saying
    // RS_PASSTHROUGH here would make an un-attacked volume look like one
    // that withstood the campaign -- the 2026-09-19 multifs run scored
    // beamfs RS_PASSTHROUGH on CALL_DELTA=0, FLIP_DELTA=0.
    if call_delta == 0 && flip_delta == 0 {
        return "NOT_EXERCISED";
    }
    let dmesg_signal = dmesg_uncorrectable > 0 || dmesg_eio > 0;
    if cat_rc != 0 {
        if dmesg_signal {
            return "DETECTED_FAIL_CLOSED";
        }
        return "INACCESSIBLE";
    }
    if hash_pre == "missing" || hash_post == "missing" || hash_post == "cat_failed" {
        // cat_rc == 0 but hash bookkeeping broke: this is an instrument fault
        // not a filesystem fault; classify under DETECTED_FAIL_CLOSED if
        // dmesg signals corruption, INACCESSIBLE otherwise.
        if dmesg_signal {
            return "DETECTED_FAIL_CLOSED";
        }
        return "INACCESSIBLE";
    }
    if hash_post != hash_pre {
        // Read returned different bytes than what was written. If the kernel
        // logged uncorrectable/EIO, the path was technically detected but
        // user-space still got bad bytes -- this is a kernel-side reporting
        // bug, not a silent corruption. We classify as DETECTED_FAIL_CLOSED
        // because the FEC layer signaled.
        if dmesg_signal {
            return "DETECTED_FAIL_CLOSED";
        }
        return "SILENT_CORRUPTION";
    }
    if rs_corrected > 0 {
        "RS_RECOVERED"
    } else {
        "RS_PASSTHROUGH"
    }
}

/// Phase A.1: fine-grained verdict for FS != beamfs (no FEC).
/// Without FEC, the only differentiation is between detected (FS panic
/// or kernel signal) and silent (hash mismatch with no kernel signal).
/// The counters were appended rather than folded into a struct, which
/// keeps five consecutive u32 parameters that the compiler cannot tell
/// apart. Grouping them is the right shape and is a change of six
/// signatures; it belongs in its own commit, not in the one that stops
/// a report calling an un-attacked volume a survivor.
#[allow(clippy::too_many_arguments)]
fn derive_verdict_detail_legacy(
    mount_state: &str,
    cat_rc: i32,
    hash_pre: &str,
    hash_post: &str,
    dmesg_uncorrectable: u32,
    dmesg_eio: u32,
    call_delta: u32,
    flip_delta: u32,
) -> &'static str {
    if mount_state == "FS_PANIC" {
        return "KERNEL_PANIC";
    }
    // A run where the injector never fired measured nothing. Saying
    // RS_PASSTHROUGH here would make an un-attacked volume look like one
    // that withstood the campaign -- the 2026-09-19 multifs run scored
    // beamfs RS_PASSTHROUGH on CALL_DELTA=0, FLIP_DELTA=0.
    if call_delta == 0 && flip_delta == 0 {
        return "NOT_EXERCISED";
    }
    let dmesg_signal = dmesg_uncorrectable > 0 || dmesg_eio > 0;
    if cat_rc != 0 {
        if dmesg_signal {
            return "DETECTED_FAIL_CLOSED";
        }
        return "INACCESSIBLE";
    }
    if hash_pre == "missing" || hash_post == "missing" || hash_post == "cat_failed" {
        if dmesg_signal {
            return "DETECTED_FAIL_CLOSED";
        }
        return "INACCESSIBLE";
    }
    if hash_post != hash_pre {
        if dmesg_signal {
            return "CORRUPTED_DATA";
        }
        return "SILENT_CORRUPTION";
    }
    "RECOVERED"
}

/// Bench-2 cluster scope : extract a field from an ATTACK record matching
/// (host, prob). Cluster format differs from multifs : prefix is "ATTACK|prob=N|"
/// not "ATTACK|FS=...|PROB=...|", and host is HOST=<name> not FS=<name>.
fn extract_cluster_attack_field(
    records: &str,
    host: &str,
    prob: u32,
    field: &str,
) -> Option<String> {
    let needle_prefix = format!("ATTACK|prob={prob}|CLUSTER|");
    let needle_host = format!("HOST={host}");
    let needle_prob_inline = format!("PROB={prob}");
    let needle_field = format!("{field}=");
    for line in records.lines() {
        if line.starts_with(&needle_prefix)
            && line.contains(&needle_host)
            && line.contains(&needle_prob_inline)
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

/// Bench-2 cluster scope : extract VERDICT (mount-state sentinel) from a
/// VERIFY record matching (host, prob). `cluster_verify` currently emits only
/// VERDICT=VERIFIED ; `FS_PANIC` is not yet emitted by the worker but the
/// extractor handles both cases for forward compatibility.
fn extract_cluster_verify_state(records: &str, host: &str, prob: u32) -> Option<String> {
    let needle_prefix = format!("VERIFY|prob={prob}|CLUSTER|");
    let needle_host = format!("HOST={host}");
    for line in records.lines() {
        if line.starts_with(&needle_prefix)
            && line.contains(&needle_host)
            && line.contains("VERDICT=")
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

/// Derive a 5-class verdict for a single (host, prob) cluster observation.
/// Cluster /data is always beamfs (Reed-Solomon FEC inline), so always
/// uses `derive_verdict_beamfs` ; legacy FS variant is multifs-only.
///
/// Returns one of : "`RS_RECOVERED`", "`RS_PASSTHROUGH`", "`RS_FAILED`",
/// "`FS_PANIC`", "`CORRUPTED_DATA`", "?" (insufficient data).
pub fn extract_cluster_verdict(records: &str, host: &str, prob: u32) -> String {
    let mount_state = extract_cluster_verify_state(records, host, prob)
        .unwrap_or_else(|| "MOUNTED".to_string());
    // cluster_verify emits VERIFIED on success ; remap to MOUNTED for the
    // shared derive_verdict_beamfs() call which expects the multifs sentinel.
    let mount_state = if mount_state == "VERIFIED" { "MOUNTED".to_string() } else { mount_state };
    let cat_rc: i32 = extract_cluster_attack_field(records, host, prob, "CAT_RC")
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);
    let hash_pre = extract_cluster_attack_field(records, host, prob, "HASH_PRE")
        .unwrap_or_else(|| "missing".to_string());
    let hash_post = extract_cluster_attack_field(records, host, prob, "HASH_POST")
        .unwrap_or_else(|| "missing".to_string());
    let rs_corrected: u32 = extract_cluster_attack_field(records, host, prob, "RS_CORRECTED")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let dmesg_uncorrectable: u32 = extract_cluster_attack_field(records, host, prob, "DMESG_UNCORRECTABLE")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // An attack the worker skipped leaves no ATTACK record, so every
    // field above falls back and the verdict came out RS_FAILED: the
    // filesystem blamed for a hook that never loaded. The counters say
    // whether anything was injected at all.
    let call_delta: u32 = extract_cluster_attack_field(records, host, prob, "CALL_DELTA")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let flip_delta: u32 = extract_cluster_attack_field(records, host, prob, "FLIP_DELTA")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    derive_verdict_beamfs(
        &mount_state, cat_rc, &hash_pre, &hash_post,
        rs_corrected, dmesg_uncorrectable, call_delta, flip_delta,
    ).to_string()
}

/// Phase A.1: fine-grained cluster verdict. Same sources as
/// `extract_cluster_verdict`, but additionally reads `DMESG_UNCORRECTABLE` and
/// `DMESG_EIO` to distinguish `DETECTED_FAIL_CLOSED` / INACCESSIBLE /
/// `SILENT_CORRUPTION` / `KERNEL_PANIC`. Cluster /data is always beamfs (FEC).
pub fn extract_cluster_verdict_detail(records: &str, host: &str, prob: u32) -> String {
    let mount_state = extract_cluster_verify_state(records, host, prob)
        .unwrap_or_else(|| "MOUNTED".to_string());
    let mount_state = if mount_state == "VERIFIED" { "MOUNTED".to_string() } else { mount_state };
    let cat_rc: i32 = extract_cluster_attack_field(records, host, prob, "CAT_RC")
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);
    let hash_pre = extract_cluster_attack_field(records, host, prob, "HASH_PRE")
        .unwrap_or_else(|| "missing".to_string());
    let hash_post = extract_cluster_attack_field(records, host, prob, "HASH_POST")
        .unwrap_or_else(|| "missing".to_string());
    let rs_corrected: u32 = extract_cluster_attack_field(records, host, prob, "RS_CORRECTED")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let dmesg_uncorrectable: u32 = extract_cluster_attack_field(records, host, prob, "DMESG_UNCORRECTABLE")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let dmesg_eio: u32 = extract_cluster_attack_field(records, host, prob, "DMESG_EIO")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let call_delta: u32 = extract_cluster_attack_field(records, host, prob, "CALL_DELTA")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let flip_delta: u32 = extract_cluster_attack_field(records, host, prob, "FLIP_DELTA")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    derive_verdict_detail_beamfs(
        &mount_state, cat_rc, &hash_pre, &hash_post,
        rs_corrected, dmesg_uncorrectable, dmesg_eio,
        call_delta, flip_delta,
    ).to_string()
}

pub fn extract_verdict(records: &str, fs_name: &str, prob: u32) -> Option<String> {
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
    let dmesg_uncorrectable: u32 = extract_attack_field(records, fs_name, prob, "DMESG_UNCORRECTABLE")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    // v0.12.3: injection volume, used to flag a filesystem the campaign
    // never actually attacked (see derive_verdict_legacy).
    let call_delta: u32 = extract_attack_field(records, fs_name, prob, "CALL_DELTA")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let flip_delta: u32 = extract_attack_field(records, fs_name, prob, "FLIP_DELTA")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let verdict = if fs_name == "beamfs" {
        derive_verdict_beamfs(&mount_state, cat_rc, &hash_pre, &hash_post, rs_corrected, dmesg_uncorrectable, call_delta, flip_delta)
    } else {
        derive_verdict_legacy(&mount_state, cat_rc, &hash_pre, &hash_post, call_delta, flip_delta)
    };
    Some(verdict.to_string())
}

/// Phase A.1: fine-grained verdict (multifs scope). Companion to
/// `extract_verdict`, exploits dmesg signals to distinguish `KERNEL_PANIC`,
/// `DETECTED_FAIL_CLOSED`, INACCESSIBLE, `SILENT_CORRUPTION` from the legacy
/// 5-class taxonomy.
pub fn extract_verdict_detail(records: &str, fs_name: &str, prob: u32) -> Option<String> {
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
    let dmesg_uncorrectable: u32 = extract_attack_field(records, fs_name, prob, "DMESG_UNCORRECTABLE")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let dmesg_eio: u32 = extract_attack_field(records, fs_name, prob, "DMESG_EIO")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let call_delta: u32 = extract_attack_field(records, fs_name, prob, "CALL_DELTA")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let flip_delta: u32 = extract_attack_field(records, fs_name, prob, "FLIP_DELTA")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let verdict = if fs_name == "beamfs" {
        derive_verdict_detail_beamfs(
            &mount_state, cat_rc, &hash_pre, &hash_post,
            rs_corrected, dmesg_uncorrectable, dmesg_eio,
            call_delta, flip_delta,
        )
    } else {
        derive_verdict_detail_legacy(
            &mount_state, cat_rc, &hash_pre, &hash_post,
            dmesg_uncorrectable, dmesg_eio,
            call_delta, flip_delta,
        )
    };
    Some(verdict.to_string())
}

/// Phase A.2: extract the `FRAG_RELOCATED` field from the ATTACK record
/// matching (fs, prob). Returns one of:
///   "0"  : in-place update, physical extent unchanged
///   "1"  : `CoW` relocation, physical extent moved
///   "na" : filefrag unsupported (beamfs / squashfs), or any error path
/// Returns None if the record is absent or the field is missing.
///
/// Companion to `extract_verdict_detail`; the `CoW` relocation is a mechanism,
/// not a verdict, so it is reported alongside but not folded into the
/// `verdict_detail` enum.
pub fn extract_frag_relocated(records: &str, fs_name: &str, prob: u32) -> Option<String> {
    extract_attack_field(records, fs_name, prob, "FRAG_RELOCATED")
}

/// Phase A.3: extract the `WORKLOAD_MODE` field from the ATTACK record.
/// Returns the workload mode under which the attack was performed:
///   "static"        : default, FS quiescent during attack
///   "write-active"  : continuous fio randwrite on `TARGET_FILE` during attack
/// Returns None if the field is absent (legacy records pre-A.3).
pub fn extract_workload_mode(records: &str, fs_name: &str, prob: u32) -> Option<String> {
    extract_attack_field(records, fs_name, prob, "WORKLOAD_MODE")
}

/// Phase A.4: extract the `ATTACKED_BYTES_UNIQUE` field from the ATTACK
/// record. This is the count of unique (sector, `byte_offset`) tuples
/// touched during the attack window, derived from the EMUFI `flip_log`
/// ring buffer.
///
/// This metric is the recommended denominator for fair cross-FS
/// comparison. It normalizes attack dose by physical bytes touched
/// rather than by bios issued (which varies by 5x between ext4 and
/// btrfs at identical `probability_ppm`).
///
/// Limitation : the `flip_log` ring buffer is 4096 entries ; under
/// saturation (probability=10^6 + workload-active) the ring wraps
/// and `ATTACKED_BYTES_UNIQUE` becomes a lower bound. EMUFI v1 §VII.C.a
/// documents this regime explicitly.
///
/// Returns "na" for FS where the `flip_log` is unavailable, or None
/// if the field is absent (legacy records pre-A.4).
pub fn extract_attacked_bytes_unique(records: &str, fs_name: &str, prob: u32) -> Option<String> {
    extract_attack_field(records, fs_name, prob, "ATTACKED_BYTES_UNIQUE")
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
    fn an_injector_that_never_fired_is_not_a_survivor() {
        // CALL_DELTA=0 AND FLIP_DELTA=0: emufi was never called and
        // delivered no bit. The file reads back identical because nothing
        // touched it, which says nothing about beamfs. The 2026-09-19
        // multifs run scored RS_PASSTHROUGH on exactly this.
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=0|FLIP_DELTA=0|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_verdict(&r, "beamfs", 1_000_000).as_deref(), Some("NOT_EXERCISED"));
        assert_eq!(
            extract_verdict_detail(&r, "beamfs", 1_000_000).as_deref(),
            Some("NOT_EXERCISED")
        );
    }

    #[test]
    fn a_legacy_fs_that_was_never_attacked_is_not_recovered() {
        // Same for the detailed verdict of a non-beamfs filesystem: the
        // legacy verdict already returned NOT_EXERCISED, phase A.1 still
        // said RECOVERED on the same record.
        let r = rec(
            "ATTACK|FS=ext4|PROB=1000|CALL_DELTA=0|FLIP_DELTA=0|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=ext4|prob=1000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_verdict(&r, "ext4", 1000).as_deref(), Some("NOT_EXERCISED"));
        assert_eq!(
            extract_verdict_detail(&r, "ext4", 1000).as_deref(),
            Some("NOT_EXERCISED")
        );
    }

    #[test]
    fn a_skipped_cluster_attack_does_not_blame_the_filesystem() {
        // What every node answered on 2026-09-19: the injector could not
        // load, cluster_attack emitted SKIP and no ATTACK record at all,
        // so every field fell back to its default and the verdict came
        // out RS_FAILED -- the pipeline failed, blaming beamfs for a
        // kernel hook that never registered.
        let r = "\nCLUSTER|HOST=beamfs-master|ATTACK=SKIP|reason=emufi_debugfs_unavailable\nCLUSTER|HOST=beamfs-master|VERDICT=VERIFIED|DIFFS=0|N_FILES_CHANGED=0|details=diff counted\n";
        assert_eq!(extract_cluster_verdict(r, "beamfs-master", 1000), "NOT_EXERCISED");
        assert_eq!(
            extract_cluster_verdict_detail(r, "beamfs-master", 1000),
            "NOT_EXERCISED"
        );
    }

    #[test]
    fn a_call_without_a_flip_is_still_a_measurement() {
        // CALL_DELTA > 0 with FLIP_DELTA == 0 is the injector running and
        // landing nothing on the file: that IS a measurement, and must
        // keep its old verdict. The guard is a conjunction for this reason.
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000|CALL_DELTA=2|FLIP_DELTA=0|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=beamfs|prob=1000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_verdict(&r, "beamfs", 1000).as_deref(), Some("RS_PASSTHROUGH"));
    }

    #[test]
    fn beamfs_rs_fail_closed_cat_eio() {
        // CAT_RC != 0 AND DMESG_UNCORRECTABLE > 0 -> RS_FAIL_CLOSED.
        // beamfs detected the corruption (via RS uncorrectable, CRC32
        // mismatch, or pointer-out-of-range) and refused the read.
        // This is a clean fail-closed state and is accepted as pass
        // by R19 verdict_is_pass.
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=10|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=cat_failed|CAT_RC=1|RS_CORRECTED=0|DMESG_UNCORRECTABLE=1|DMESG_EIO=1",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=MOUNTED|DIFFS_PRE_POST=2|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=1|details=ok",
        );
        assert_eq!(extract_verdict(&r, "beamfs", 1_000_000).as_deref(), Some("RS_FAIL_CLOSED"));
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

    // ============================================================
    // B.4 (M1 C3) : cluster verdict extraction tests
    // ============================================================

    #[test]
    fn cluster_attack_field_extraction() {
        let r = "ATTACK|prob=1000000|CLUSTER|HOST=beamfs-master|PROB=1000000|CALL_DELTA=28|FLIP_DELTA=28|TARGET=dir-B/file-B2.bin|HASH_PRE=abc123|HASH_POST=abc123|CAT_RC=0|RS_CORRECTED=2|DMESG_UNCORRECTABLE=0|DMESG_EIO=0|BITS_DIFF=0|FRAC_CORRUPT=0|HAMM_BLOCKS=0|FILE_SIZE=3072\n";
        assert_eq!(extract_cluster_attack_field(r, "beamfs-master", 1_000_000, "CAT_RC").as_deref(), Some("0"));
        assert_eq!(extract_cluster_attack_field(r, "beamfs-master", 1_000_000, "HASH_PRE").as_deref(), Some("abc123"));
        assert_eq!(extract_cluster_attack_field(r, "beamfs-master", 1_000_000, "RS_CORRECTED").as_deref(), Some("2"));
        assert_eq!(extract_cluster_attack_field(r, "beamfs-master", 1_000_000, "BITS_DIFF").as_deref(), Some("0"));
        assert_eq!(extract_cluster_attack_field(r, "beamfs-compute01", 1_000_000, "CAT_RC"), None);
        assert_eq!(extract_cluster_attack_field(r, "beamfs-master", 1000, "CAT_RC"), None);
    }

    #[test]
    fn cluster_verdict_recovered() {
        let r = [
            "ATTACK|prob=1000000|CLUSTER|HOST=beamfs-master|PROB=1000000|CALL_DELTA=28|FLIP_DELTA=28|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=4|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|prob=1000000|CLUSTER|HOST=beamfs-master|VERDICT=VERIFIED|DIFFS=0|N_FILES_CHANGED=0|details=ok",
        ].join("\n");
        assert_eq!(extract_cluster_verdict(&r, "beamfs-master", 1_000_000), "RS_RECOVERED");
    }

    #[test]
    fn cluster_verdict_passthrough() {
        let r = [
            "ATTACK|prob=1000|CLUSTER|HOST=beamfs-master|PROB=1000|CALL_DELTA=28|FLIP_DELTA=0|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|prob=1000|CLUSTER|HOST=beamfs-master|VERDICT=VERIFIED|DIFFS=0|N_FILES_CHANGED=0|details=ok",
        ].join("\n");
        assert_eq!(extract_cluster_verdict(&r, "beamfs-master", 1000), "RS_PASSTHROUGH");
    }

    #[test]
    fn cluster_verdict_corrupted() {
        let r = [
            "ATTACK|prob=1000000|CLUSTER|HOST=beamfs-master|PROB=1000000|CALL_DELTA=28|FLIP_DELTA=28|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=def|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|prob=1000000|CLUSTER|HOST=beamfs-master|VERDICT=VERIFIED|DIFFS=2|N_FILES_CHANGED=1|details=ok",
        ].join("\n");
        assert_eq!(extract_cluster_verdict(&r, "beamfs-master", 1_000_000), "CORRUPTED_DATA");
    }

    #[test]
    fn cluster_verdict_failed() {
        let r = [
            "ATTACK|prob=1000000|CLUSTER|HOST=beamfs-master|PROB=1000000|CALL_DELTA=28|FLIP_DELTA=28|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=cat_failed|CAT_RC=1|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|prob=1000000|CLUSTER|HOST=beamfs-master|VERDICT=VERIFIED|DIFFS=0|N_FILES_CHANGED=0|details=ok",
        ].join("\n");
        assert_eq!(extract_cluster_verdict(&r, "beamfs-master", 1_000_000), "RS_FAILED");
    }

    // ============================================================
    // Phase A.1 -- verdict_detail tests
    // ============================================================

    #[test]
    fn detail_beamfs_kernel_panic() {
        // mount_state == FS_PANIC -> KERNEL_PANIC
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=99|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=cat_failed|CAT_RC=1|RS_CORRECTED=0|DMESG_UNCORRECTABLE=5|DMESG_EIO=3",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=FS_PANIC|details=remount failed",
        );
        assert_eq!(extract_verdict_detail(&r, "beamfs", 1_000_000).as_deref(), Some("KERNEL_PANIC"));
        // legacy verdict still says FS_PANIC
        assert_eq!(extract_verdict(&r, "beamfs", 1_000_000).as_deref(), Some("FS_PANIC"));
    }

    #[test]
    fn detail_beamfs_detected_fail_closed() {
        // cat_rc != 0 AND dmesg signal -> DETECTED_FAIL_CLOSED
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=10|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=cat_failed|CAT_RC=1|RS_CORRECTED=0|DMESG_UNCORRECTABLE=1|DMESG_EIO=1",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=MOUNTED|DIFFS_PRE_POST=2|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=1|details=ok",
        );
        assert_eq!(extract_verdict_detail(&r, "beamfs", 1_000_000).as_deref(), Some("DETECTED_FAIL_CLOSED"));
        // Legacy verdict now distinguishes detected fail-closed from
        // unclassified fail: with DMESG_UNCORRECTABLE > 0 we surface
        // RS_FAIL_CLOSED (accepted as pass).
        assert_eq!(extract_verdict(&r, "beamfs", 1_000_000).as_deref(), Some("RS_FAIL_CLOSED"));
    }

    #[test]
    fn detail_beamfs_inaccessible() {
        // cat_rc != 0 AND dmesg silent -> INACCESSIBLE
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=2|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=cat_failed|CAT_RC=1|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_verdict_detail(&r, "beamfs", 1_000_000).as_deref(), Some("INACCESSIBLE"));
        // legacy verdict still RS_FAILED
        assert_eq!(extract_verdict(&r, "beamfs", 1_000_000).as_deref(), Some("RS_FAILED"));
    }

    #[test]
    fn detail_beamfs_silent_corruption() {
        // hash mismatch AND cat_rc == 0 AND dmesg silent -> SILENT_CORRUPTION
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=5|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=def|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=MOUNTED|DIFFS_PRE_POST=2|DIFFS_PRE_REMOUNT=2|N_FILES_CHANGED=1|details=ok",
        );
        assert_eq!(extract_verdict_detail(&r, "beamfs", 1_000_000).as_deref(), Some("SILENT_CORRUPTION"));
        // legacy verdict says CORRUPTED_DATA
        assert_eq!(extract_verdict(&r, "beamfs", 1_000_000).as_deref(), Some("CORRUPTED_DATA"));
    }

    #[test]
    fn detail_beamfs_rs_recovered_unchanged() {
        // hash match AND rs_corrected > 0 -> RS_RECOVERED (same as legacy)
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=3|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=2|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_verdict_detail(&r, "beamfs", 1_000_000).as_deref(), Some("RS_RECOVERED"));
        assert_eq!(extract_verdict(&r, "beamfs", 1_000_000).as_deref(), Some("RS_RECOVERED"));
    }

    #[test]
    fn detail_legacy_silent_corruption() {
        // ext4 hash mismatch with no dmesg signal -> SILENT_CORRUPTION (detail)
        // vs legacy CORRUPTED_DATA which conflates silent and detected.
        let r = rec(
            "ATTACK|FS=ext4|PROB=100000|CALL_DELTA=10|FLIP_DELTA=5|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=def|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=ext4|prob=100000|VERDICT=MOUNTED|DIFFS_PRE_POST=2|DIFFS_PRE_REMOUNT=2|N_FILES_CHANGED=1|details=ok",
        );
        assert_eq!(extract_verdict_detail(&r, "ext4", 100_000).as_deref(), Some("SILENT_CORRUPTION"));
        assert_eq!(extract_verdict(&r, "ext4", 100_000).as_deref(), Some("CORRUPTED_DATA"));
    }

    #[test]
    fn detail_cluster_detected_fail_closed() {
        // cluster compute01 with CAT_RC=1 and dmesg EIO=1 -> DETECTED_FAIL_CLOSED
        let r = [
            "ATTACK|prob=1000000|CLUSTER|HOST=beamfs-compute01|PROB=1000000|CALL_DELTA=28|FLIP_DELTA=4|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=mount_failed|CAT_RC=1|RS_CORRECTED=0|DMESG_UNCORRECTABLE=1|DMESG_EIO=1",
            "VERIFY|prob=1000000|CLUSTER|HOST=beamfs-compute01|VERDICT=VERIFIED|DIFFS=0|N_FILES_CHANGED=0|details=ok",
        ].join("\n");
        assert_eq!(extract_cluster_verdict_detail(&r, "beamfs-compute01", 1_000_000), "DETECTED_FAIL_CLOSED");
        // cluster legacy verdict now surfaces RS_FAIL_CLOSED with
        // DMESG_UNCORRECTABLE > 0 (accepted as pass by R19).
        assert_eq!(extract_cluster_verdict(&r, "beamfs-compute01", 1_000_000), "RS_FAIL_CLOSED");
    }

    // ============================================================
    // Phase A.2 -- FRAG_RELOCATED tests
    // ============================================================

    #[test]
    fn frag_relocated_inplace_ext4() {
        // ext4 typical: same physical extent before/after attack -> "0"
        let r = rec(
            "ATTACK|FS=ext4|PROB=100000|CALL_DELTA=10|FLIP_DELTA=5|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=def|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0|BITS_DIFF=2|FRAC_CORRUPT=8|HAMM_BLOCKS=1|FILE_SIZE=262144|FRAG_PRE_PHYS=1081344,1081345,1081346|FRAG_POST_PHYS=1081344,1081345,1081346|FRAG_RELOCATED=0",
            "VERIFY|fs=ext4|prob=100000|VERDICT=MOUNTED|DIFFS_PRE_POST=2|DIFFS_PRE_REMOUNT=2|N_FILES_CHANGED=1|details=ok",
        );
        assert_eq!(extract_frag_relocated(&r, "ext4", 100_000).as_deref(), Some("0"));
    }

    #[test]
    fn frag_relocated_cow_btrfs() {
        // btrfs typical: extent moved after attack -> "1"
        let r = rec(
            "ATTACK|FS=btrfs|PROB=100000|CALL_DELTA=10|FLIP_DELTA=5|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0|BITS_DIFF=0|FRAC_CORRUPT=0|HAMM_BLOCKS=0|FILE_SIZE=262144|FRAG_PRE_PHYS=2097152,2097153|FRAG_POST_PHYS=3145728,3145729|FRAG_RELOCATED=1",
            "VERIFY|fs=btrfs|prob=100000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_frag_relocated(&r, "btrfs", 100_000).as_deref(), Some("1"));
    }

    #[test]
    fn frag_relocated_na_beamfs() {
        // beamfs / squashfs: filefrag unsupported -> "na"
        let r = rec(
            "ATTACK|FS=beamfs|PROB=1000000|CALL_DELTA=10|FLIP_DELTA=3|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=2|DMESG_UNCORRECTABLE=0|DMESG_EIO=0|BITS_DIFF=0|FRAC_CORRUPT=0|HAMM_BLOCKS=0|FILE_SIZE=262144|FRAG_PRE_PHYS=na|FRAG_POST_PHYS=na|FRAG_RELOCATED=na",
            "VERIFY|fs=beamfs|prob=1000000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_frag_relocated(&r, "beamfs", 1_000_000).as_deref(), Some("na"));
    }

    #[test]
    fn frag_relocated_missing_returns_none() {
        // Old-format record without FRAG_* fields -> None
        let r = rec(
            "ATTACK|FS=ext4|PROB=1000|CALL_DELTA=2|FLIP_DELTA=0|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=ext4|prob=1000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_frag_relocated(&r, "ext4", 1000), None);
    }

    // ============================================================
    // Phase A.3 -- WORKLOAD_MODE tests
    // ============================================================

    #[test]
    fn workload_mode_static() {
        let r = rec(
            "ATTACK|FS=ext4|PROB=100000|CALL_DELTA=10|FLIP_DELTA=5|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=def|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0|BITS_DIFF=2|FRAC_CORRUPT=8|HAMM_BLOCKS=1|FILE_SIZE=262144|FRAG_PRE_PHYS=1081344|FRAG_POST_PHYS=1081344|FRAG_RELOCATED=0|WORKLOAD_MODE=static|WORKLOAD_DURATION=15",
            "VERIFY|fs=ext4|prob=100000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_workload_mode(&r, "ext4", 100_000).as_deref(), Some("static"));
    }

    #[test]
    fn workload_mode_write_active() {
        let r = rec(
            "ATTACK|FS=btrfs|PROB=100000|CALL_DELTA=200|FLIP_DELTA=12|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0|BITS_DIFF=0|FRAC_CORRUPT=0|HAMM_BLOCKS=0|FILE_SIZE=262144|FRAG_PRE_PHYS=2097152|FRAG_POST_PHYS=3145728|FRAG_RELOCATED=1|WORKLOAD_MODE=write-active|WORKLOAD_DURATION=15",
            "VERIFY|fs=btrfs|prob=100000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_workload_mode(&r, "btrfs", 100_000).as_deref(), Some("write-active"));
    }

    #[test]
    fn workload_mode_missing_returns_none() {
        // Old-format record (pre-A.3) without WORKLOAD_MODE -> None
        let r = rec(
            "ATTACK|FS=ext4|PROB=1000|CALL_DELTA=2|FLIP_DELTA=0|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=ext4|prob=1000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_workload_mode(&r, "ext4", 1000), None);
    }

    // ============================================================
    // Phase A.4 -- ATTACKED_BYTES_UNIQUE tests
    // ============================================================

    #[test]
    fn attacked_bytes_unique_present() {
        let r = rec(
            "ATTACK|FS=ext4|PROB=100000|CALL_DELTA=10|FLIP_DELTA=5|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=def|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0|BITS_DIFF=2|FRAC_CORRUPT=8|HAMM_BLOCKS=1|FILE_SIZE=262144|FRAG_PRE_PHYS=1081344|FRAG_POST_PHYS=1081344|FRAG_RELOCATED=0|WORKLOAD_MODE=static|WORKLOAD_DURATION=15|ATTACKED_BYTES_UNIQUE=1259",
            "VERIFY|fs=ext4|prob=100000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_attacked_bytes_unique(&r, "ext4", 100_000).as_deref(), Some("1259"));
    }

    #[test]
    fn attacked_bytes_unique_na_when_flip_log_absent() {
        // emufi may emit "na" if /sys/kernel/debug/emufi/flip_log is missing
        let r = rec(
            "ATTACK|FS=btrfs|PROB=100000|CALL_DELTA=200|FLIP_DELTA=0|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0|BITS_DIFF=0|FRAC_CORRUPT=0|HAMM_BLOCKS=0|FILE_SIZE=262144|FRAG_PRE_PHYS=2097152|FRAG_POST_PHYS=2097152|FRAG_RELOCATED=0|WORKLOAD_MODE=static|WORKLOAD_DURATION=15|ATTACKED_BYTES_UNIQUE=na",
            "VERIFY|fs=btrfs|prob=100000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_attacked_bytes_unique(&r, "btrfs", 100_000).as_deref(), Some("na"));
    }

    #[test]
    fn attacked_bytes_unique_missing_returns_none() {
        // Pre-A.4 record without ATTACKED_BYTES_UNIQUE field
        let r = rec(
            "ATTACK|FS=ext4|PROB=1000|CALL_DELTA=2|FLIP_DELTA=0|TARGET=dir-B/file-B2.bin|HASH_PRE=abc|HASH_POST=abc|CAT_RC=0|RS_CORRECTED=0|DMESG_UNCORRECTABLE=0|DMESG_EIO=0",
            "VERIFY|fs=ext4|prob=1000|VERDICT=MOUNTED|DIFFS_PRE_POST=0|DIFFS_PRE_REMOUNT=0|N_FILES_CHANGED=0|details=ok",
        );
        assert_eq!(extract_attacked_bytes_unique(&r, "ext4", 1000), None);
    }
}
