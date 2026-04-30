//! synthesis.rs — generate synthesis.md + synthesis.json from a completed run.
//!
//! Output format byte-identical to Tir-multifs.sh phase 4. Reference target:
//! Documentation/runs/Tir-multifs-20260430-141008/{synthesis.md,synthesis.json}.
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

    writeln!(f, "# Tir-multifs head-to-head report")?;
    writeln!(f)?;
    writeln!(f, "**Date**: {ts_human}")?;
    writeln!(f, "**Run dir**: `{}`", run_dir.display())?;
    writeln!(f)?;
    writeln!(f, "## Topology")?;
    writeln!(f)?;
    writeln!(f, "5 USB physical disks attached to beamfs-master VM (cache='none' io='threads'):")?;
    writeln!(f)?;
    writeln!(f, "| FS       | Device | USB by-id (truncated)             |")?;
    writeln!(f, "|----------|--------|-----------------------------------|")?;
    writeln!(f, "| ext4     | vdc    | Kingston DataTraveler ...DA006B   |")?;
    writeln!(f, "| ext3     | vdd    | Kingston DataTraveler ...D70052   |")?;
    writeln!(f, "| btrfs    | vde    | Kingston DataTraveler ...E60058   |")?;
    writeln!(f, "| squashfs | vdf    | Kingston DataTraveler ...0ED05    |")?;
    writeln!(f, "| BEAMFS   | vdg    | SanDisk Cruzer ...09503233        |")?;
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

fn extract_verdict(records: &str, fs_name: &str, prob: u32) -> Option<String> {
    // Find lines: "VERIFY|fs=<fs>|prob=<prob>|...VERDICT=<X>..."
    let needle_fs = format!("fs={fs_name}");
    let needle_prob = format!("prob={prob}");
    for line in records.lines() {
        if line.contains("VERDICT=")
            && line.contains(&needle_fs)
            && line.contains(&needle_prob)
        {
            if let Some(idx) = line.find("VERDICT=") {
                let rest = &line[idx + "VERDICT=".len()..];
                // Capture [A-Z_]+ greedy
                let verdict: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_uppercase() || *c == '_')
                    .collect();
                if !verdict.is_empty() {
                    return Some(verdict);
                }
            }
        }
    }
    None
}

fn extract_flip_delta(records: &str, fs_name: &str, prob: u32) -> Option<String> {
    // Find lines: "ATTACK|...FS=<fs>|PROB=<prob>|...FLIP_DELTA=<n>"
    let needle_fs = format!("FS={fs_name}");
    let needle_prob = format!("PROB={prob}");
    for line in records.lines() {
        if line.starts_with("ATTACK|")
            && line.contains(&needle_fs)
            && line.contains(&needle_prob)
            && line.contains("FLIP_DELTA=")
        {
            if let Some(idx) = line.find("FLIP_DELTA=") {
                let rest = &line[idx + "FLIP_DELTA=".len()..];
                let n: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if !n.is_empty() {
                    return Some(n);
                }
            }
        }
    }
    None
}
