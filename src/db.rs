//! db.rs -- measurement database (SQLite).
//!
//! ## Why this exists
//!
//! The 2026-08-28 campaign ran 44 measurements over nine hours and
//! returned rc=0 throughout, while several of them measured nothing at
//! all: the write workload never started on some filesystems, the
//! injection landed outside the verified file on others, and ext4 spent
//! part of the campaign in an error state with its test file
//! unreachable. Each failure was silent, each produced plausible
//! numbers, and each was found only by reading raw logs by hand
//! afterwards.
//!
//! Storing results in a queryable form with an explicit validity
//! verdict per measurement is what makes that visible without manual
//! inspection. A measurement whose workload did not run is not a
//! resilience result, and the record has to be able to say so.
//!
//! ## Design
//!
//! Writes go through the sqlite3 binary rather than a Rust binding.
//! The harness already shells out to ssh, scp, virsh and filefrag, and
//! ingestion is append-only at the end of a run, so a linked C library
//! would buy nothing.
//!
//! Ingestion parses `all-records.txt`, which every multifs run already
//! writes. That also means past runs can be ingested retroactively --
//! 64 of them exist as of 2026-08-29.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the database lives. Alongside the run archives it indexes.
pub fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home)
        .join("git/yocto-beamfs/Documentation/runs/beamfs-bench.db")
}

/// Run a statement. Values must already be escaped by `sql_str`.
///
/// SQL goes in on stdin, not as an argv element: sqlite3 parses leading
/// dashes in an argument as options, so a script containing `-- comment`
/// lines is read as a garbled command line rather than as SQL.
fn exec(db: &Path, sql: &str) -> Result<String> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("sqlite3")
        .arg(db)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn sqlite3 -- is it installed?")?;
    child
        .stdin
        .as_mut()
        .context("sqlite3 stdin")?
        .write_all(sql.as_bytes())
        .context("write SQL to sqlite3")?;
    let out = child.wait_with_output().context("wait for sqlite3")?;
    if !out.status.success() {
        anyhow::bail!(
            "sqlite3 failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        anyhow::bail!("sqlite3 error: {}", err.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Single-quote a value for SQL, or emit NULL for None.
/// Doubling the quote is SQLite's escape; values here come from our own
/// worker output, but a hash or a dmesg excerpt can still contain one.
fn sql_str(v: Option<&str>) -> String {
    match v {
        None => "NULL".into(),
        Some(s) => format!("'{}'", s.replace('\'', "''")),
    }
}

fn sql_num(v: Option<i64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "NULL".into())
}

/// Apply the schema. Idempotent: every statement is CREATE ... IF NOT EXISTS.
pub fn init(db: &Path) -> Result<()> {
    let schema = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/beamfs-bench.sql");
    let sql = std::fs::read_to_string(&schema)
        .with_context(|| format!("read schema {:?}", schema))?;
    if let Some(dir) = db.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    exec(db, &sql)?;
    Ok(())
}

/// One `ATTACK|...` record, parsed.
#[derive(Debug, Default, Clone)]
pub struct AttackRecord {
    pub fs: String,
    pub prob_ppm: Option<i64>,
    pub call_delta: Option<i64>,
    pub flip_delta: Option<i64>,
    pub flips_on_target: Option<i64>,
    pub target_ranges: Option<String>,
    pub cat_rc: Option<i64>,
    pub hash_pre: Option<String>,
    pub hash_post: Option<String>,
    pub rs_corrected: Option<i64>,
    pub dmesg_uncorrectable: Option<i64>,
    pub dmesg_eio: Option<i64>,
    pub bits_diff: Option<i64>,
    pub file_size: Option<i64>,
    pub workload_mode: Option<String>,
}

impl AttackRecord {
    /// Read ok and content unchanged. Anything else is either a refusal
    /// (cat_rc != 0) or silent corruption (cat_rc == 0, hashes differ),
    /// and those must not be collapsed together.
    pub fn intact(&self) -> Option<i64> {
        match (&self.hash_pre, &self.hash_post, self.cat_rc) {
            (Some(a), Some(b), Some(0)) if a == b && a != "missing" => Some(1),
            (_, _, Some(_)) => Some(0),
            _ => None,
        }
    }
}

fn parse_kv(payload: &str) -> HashMap<String, String> {
    payload
        .split('|')
        .filter_map(|tok| tok.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Parse the ATTACK lines of an all-records.txt.
pub fn parse_records(text: &str) -> Vec<AttackRecord> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(payload) = line.strip_prefix("ATTACK|") else { continue };
        let kv = parse_kv(payload);
        let Some(fs) = kv.get("FS") else { continue };
        let n = |k: &str| kv.get(k).and_then(|v| v.parse::<i64>().ok());
        let s = |k: &str| kv.get(k).cloned();
        out.push(AttackRecord {
            fs: fs.clone(),
            prob_ppm: n("PROB"),
            call_delta: n("CALL_DELTA"),
            flip_delta: n("FLIP_DELTA"),
            flips_on_target: n("FLIPS_ON_TARGET"),
            target_ranges: s("TARGET_RANGES"),
            cat_rc: n("CAT_RC"),
            hash_pre: s("HASH_PRE"),
            hash_post: s("HASH_POST"),
            rs_corrected: n("RS_CORRECTED"),
            dmesg_uncorrectable: n("DMESG_UNCORRECTABLE"),
            dmesg_eio: n("DMESG_EIO"),
            bits_diff: n("BITS_DIFF"),
            file_size: n("FILE_SIZE"),
            workload_mode: s("WORKLOAD_MODE"),
        });
    }
    out
}

/// Decide whether a measurement can be used, and say why when it cannot.
///
/// The rule is deliberately mechanical and stated here rather than
/// applied case by case while looking at results.
pub fn verdict(r: &AttackRecord) -> (String, Option<String>) {
    if r.hash_pre.as_deref() == Some("missing") || r.file_size == Some(0) {
        return (
            "target_file_missing".into(),
            Some("HASH_PRE=missing or FILE_SIZE=0: the filesystem could not \
                  read back its own test file, so nothing about the file's \
                  integrity was measured".into()),
        );
    }
    if r.flip_delta == Some(0) {
        return (
            "no_workload".into(),
            Some("FLIP_DELTA=0: no flip was delivered, so the run exercised \
                  nothing".into()),
        );
    }
    if r.flips_on_target == Some(0) {
        return (
            "target_not_hit".into(),
            Some("FLIPS_ON_TARGET=0: flips landed outside the verified \
                  file's extents, so an unchanged hash says nothing about \
                  the filesystem's protection".into()),
        );
    }
    if r.flips_on_target.is_none() {
        return (
            "target_not_hit".into(),
            Some("FLIPS_ON_TARGET absent (older record or FIEMAP \
                  unavailable): impact on the verified file is unknown".into()),
        );
    }
    ("usable".into(), None)
}

/// Insert a run and its measurements. Returns the run id.
#[allow(clippy::too_many_arguments)]
pub fn ingest_run(
    db: &Path,
    campaign_id: Option<i64>,
    started_at: &str,
    duration_s: Option<i64>,
    command: &str,
    exit_code: Option<i64>,
    injector: &str,
    inject_scope: Option<&str>,
    workload_mode: Option<&str>,
    bench_version: &str,
    log_path: Option<&str>,
    records: &[AttackRecord],
) -> Result<i64> {
    let prob = records.iter().find_map(|r| r.prob_ppm);
    let sql = format!(
        "INSERT INTO run (campaign_id, started_at, duration_s, command, exit_code, \
         injector, prob_ppm, inject_scope, workload_mode, bench_version, log_path) \
         VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}); \
         SELECT last_insert_rowid();",
        sql_num(campaign_id),
        sql_str(Some(started_at)),
        sql_num(duration_s),
        sql_str(Some(command)),
        sql_num(exit_code),
        sql_str(Some(injector)),
        sql_num(prob),
        sql_str(inject_scope),
        sql_str(workload_mode),
        sql_str(Some(bench_version)),
        sql_str(log_path),
    );
    let run_id: i64 = exec(db, &sql)?.trim().parse().context("run id")?;

    for r in records {
        let (v, reason) = verdict(r);
        let sql = format!(
            "INSERT INTO measurement (run_id, fs, call_delta, flip_delta, \
             flips_on_target, target_ranges, cat_rc, hash_pre, hash_post, intact, \
             rs_corrected, dmesg_uncorrectable, dmesg_eio, bits_diff, file_size) \
             VALUES ({run_id}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}); \
             INSERT INTO validity (run_id, fs, verdict, reason) \
             VALUES ({run_id}, {}, {}, {});",
            sql_str(Some(&r.fs)),
            sql_num(r.call_delta),
            sql_num(r.flip_delta),
            sql_num(r.flips_on_target),
            sql_str(r.target_ranges.as_deref()),
            sql_num(r.cat_rc),
            sql_str(r.hash_pre.as_deref()),
            sql_str(r.hash_post.as_deref()),
            sql_num(r.intact()),
            sql_num(r.rs_corrected),
            sql_num(r.dmesg_uncorrectable),
            sql_num(r.dmesg_eio),
            sql_num(r.bits_diff),
            sql_num(r.file_size),
            sql_str(Some(&r.fs)),
            sql_str(Some(&v)),
            sql_str(reason.as_deref()),
        );
        exec(db, &sql)?;
    }
    Ok(run_id)
}

/// Ingest one run directory by reading its all-records.txt.
///
/// The directory name carries the timestamp (beamfs-bench-multifs-YYYYMMDD-HHMMSS),
/// which is the only date available for archived runs: nothing else was
/// recorded at the time.
pub fn ingest_run_dir(db: &Path, run_dir: &Path, campaign_id: Option<i64>) -> Result<i64> {
    let records_path = run_dir.join("all-records.txt");
    let text = std::fs::read_to_string(&records_path)
        .with_context(|| format!("read {:?}", records_path))?;
    let records = parse_records(&text);
    if records.is_empty() {
        anyhow::bail!("no ATTACK record in {:?}", records_path);
    }

    let name = run_dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let started = name
        .rsplit_once("-multifs-")
        .map(|(_, ts)| ts.to_string())
        .filter(|ts| ts.len() == 15)
        .map(|ts| format!("{}-{}-{} {}:{}:{}",
            &ts[0..4], &ts[4..6], &ts[6..8], &ts[9..11], &ts[11..13], &ts[13..15]))
        .unwrap_or_else(|| "unknown".into());

    let scope = records.iter().find_map(|r| r.workload_mode.as_deref());

    ingest_run(
        db, campaign_id, &started, None, "multifs", Some(0),
        "emufi", None, scope,
        env!("CARGO_PKG_VERSION"),
        run_dir.to_str(),
        &records,
    )
}

/// Has this directory already been ingested? Matched on log_path, which
/// is the run directory: re-ingesting would double every measurement.
fn already_ingested(db: &Path, run_dir: &Path) -> Result<bool> {
    let sql = format!(
        "SELECT COUNT(*) FROM run WHERE log_path = {};",
        sql_str(run_dir.to_str())
    );
    Ok(exec(db, &sql)?.trim().parse::<i64>().unwrap_or(0) > 0)
}

pub fn cmd_ingest(runs_dir: Option<&str>) -> Result<i32> {
    let db = default_db_path();
    init(&db)?;

    let root = match runs_dir {
        Some(d) => PathBuf::from(d),
        None => db.parent().unwrap().to_path_buf(),
    };

    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .with_context(|| format!("read {:?}", root))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir()
            && p.file_name().and_then(|n| n.to_str())
                .map(|n| n.starts_with("beamfs-bench-multifs-"))
                .unwrap_or(false)
            && p.join("all-records.txt").exists())
        .collect();
    dirs.sort();

    let (mut done, mut skipped, mut failed) = (0, 0, 0);
    for d in &dirs {
        if already_ingested(&db, d)? {
            skipped += 1;
            continue;
        }
        match ingest_run_dir(&db, d, None) {
            Ok(id) => {
                println!("  #{id:<4} {}", d.file_name().unwrap().to_string_lossy());
                done += 1;
            }
            Err(e) => {
                eprintln!("  SKIP  {}: {e:#}", d.file_name().unwrap().to_string_lossy());
                failed += 1;
            }
        }
    }
    println!();
    println!("{done} ingested, {skipped} already present, {failed} failed");
    println!("database: {}", db.display());
    Ok(if failed > 0 { 1 } else { 0 })
}

pub enum Query {
    DoseResponse,
    Exposure,
    Validity,
}

pub fn cmd_query(q: Query) -> Result<i32> {
    let db = default_db_path();
    let sql = match q {
        Query::DoseResponse => "SELECT * FROM v_dose_response ORDER BY fs, prob_ppm;",
        Query::Exposure => "SELECT * FROM v_exposure ORDER BY run_id DESC, fs LIMIT 60;",
        Query::Validity =>
            "SELECT verdict, COUNT(*) AS n,              GROUP_CONCAT(DISTINCT fs) AS filesystems              FROM validity GROUP BY verdict ORDER BY n DESC;",
    };
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new("sqlite3")
        .arg("-header").arg("-column").arg(&db)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn()
        .context("spawn sqlite3")?;
    child.stdin.as_mut().context("stdin")?
        .write_all(sql.as_bytes()).context("write query")?;
    let out = child.wait_with_output().context("wait for sqlite3")?;
    print!("{}", String::from_utf8_lossy(&out.stdout));
    if !out.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&out.stderr));
        return Ok(1);
    }
    Ok(0)
}

/// Drop old runs. Aggregates in flip_distribution are kept: they are the
/// point of computing them at ingest, so trends survive the purge.
pub fn cmd_purge(older_than_days: u32) -> Result<i32> {
    let db = default_db_path();
    let before = exec(&db, "SELECT COUNT(*) FROM run;")?;
    let sql = format!(
        "PRAGMA foreign_keys = ON;          DELETE FROM flip_raw WHERE run_id IN            (SELECT id FROM run WHERE started_at < datetime('now', '-{d} days'));          DELETE FROM measurement WHERE run_id IN            (SELECT id FROM run WHERE started_at < datetime('now', '-{d} days'));          DELETE FROM validity WHERE run_id IN            (SELECT id FROM run WHERE started_at < datetime('now', '-{d} days'));          DELETE FROM run WHERE started_at < datetime('now', '-{d} days');          VACUUM;",
        d = older_than_days
    );
    exec(&db, &sql)?;
    let after = exec(&db, "SELECT COUNT(*) FROM run;")?;
    println!("runs: {before} -> {after} (kept flip_distribution aggregates)");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = "ATTACK|FS=beamfs|PROB=100000|CALL_DELTA=182654|FLIP_DELTA=64|\
TARGET=dir-B/file-B2.bin|HASH_PRE=aaa|HASH_PRECAT=aaa|HASH_POST=aaa|CAT_RC=0|\
RS_CORRECTED=10|DMESG_UNCORRECTABLE=0|DMESG_EIO=0|BITS_DIFF=0|FILE_SIZE=262144|\
WORKLOAD_MODE=write-active|FLIPS_ON_TARGET=11";

    #[test]
    fn parses_an_attack_record() {
        let r = &parse_records(LINE)[0];
        assert_eq!(r.fs, "beamfs");
        assert_eq!(r.flip_delta, Some(64));
        assert_eq!(r.flips_on_target, Some(11));
        assert_eq!(r.intact(), Some(1));
        assert_eq!(verdict(r).0, "usable");
    }

    #[test]
    fn missing_target_file_is_not_a_result() {
        // The shape ext4 produced on 2026-08-29 once it had gone into an
        // error state: the file is there but the filesystem cannot read
        // it back, and the harness reported only HASH_PRE=missing.
        let line = LINE
            .replace("HASH_PRE=aaa", "HASH_PRE=missing")
            .replace("FILE_SIZE=262144", "FILE_SIZE=0");
        let r = &parse_records(&line)[0];
        assert_eq!(verdict(r).0, "target_file_missing");
    }

    #[test]
    fn flips_elsewhere_is_not_a_result() {
        let line = LINE.replace("FLIPS_ON_TARGET=11", "FLIPS_ON_TARGET=0");
        let r = &parse_records(&line)[0];
        assert_eq!(verdict(r).0, "target_not_hit");
    }

    #[test]
    fn silent_corruption_is_distinct_from_refusal() {
        let corrupt = LINE.replace("HASH_POST=aaa", "HASH_POST=bbb");
        assert_eq!(parse_records(&corrupt)[0].intact(), Some(0));
        let refused = LINE.replace("CAT_RC=0", "CAT_RC=1");
        assert_eq!(parse_records(&refused)[0].intact(), Some(0));
    }

    #[test]
    fn quotes_are_escaped() {
        assert_eq!(sql_str(Some("it's")), "'it''s'");
        assert_eq!(sql_str(None), "NULL");
    }
}
