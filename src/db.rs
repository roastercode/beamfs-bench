//! db.rs -- measurement database (`SQLite`).
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
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::io::Write as IoWrite;
use std::process::Stdio;

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
/// Doubling the quote is `SQLite`'s escape; values here come from our own
/// worker output, but a hash or a dmesg excerpt can still contain one.
fn sql_str(v: Option<&str>) -> String {
    match v {
        None => "NULL".into(),
        Some(s) => format!("'{}'", s.replace('\'', "''")),
    }
}

fn sql_num(v: Option<i64>) -> String {
    v.map_or_else(|| "NULL".into(), |n| n.to_string())
}

/// Apply the schema. Idempotent: every statement is CREATE ... IF NOT EXISTS.
pub fn init(db: &Path) -> Result<()> {
    let schema = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/beamfs-bench.sql");
    let sql = std::fs::read_to_string(&schema)
        .with_context(|| format!("read schema {}", schema.display()))?;
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
    pub flip_log_sha256: Option<String>,
    /// gzip+base64 of the injector's `flip_log`, shipped inside the record.
    pub flip_log_b64: Option<String>,
    /// gzip+base64 of the beamfs dmesg lines from the attack window.
    pub dmesg_b64: Option<String>,
}

impl AttackRecord {
    /// Read ok and content unchanged. Anything else is either a refusal
    /// (`cat_rc` != 0) or silent corruption (`cat_rc` == 0, hashes differ),
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
            flip_log_sha256: s("FLIP_LOG_SHA256").filter(|v| v != "na"),
            flip_log_b64: s("FLIP_LOG_B64").filter(|v| v != "na"),
            dmesg_b64: s("DMESG_B64").filter(|v| v != "na"),
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
        if let Err(e) = ingest_flip_events(db, run_id, r) {
            eprintln!("  WARN flip events ({}): {e:#}", r.fs);
        }
    }
    Ok(run_id)
}

/// beamfs on-disk data block geometry (beamfs.h).
///
/// Bytes 0..4079 hold 16 interleaved RS(255,239) subblocks laid out as
/// [239 data][16 parity] repeated; `DATA_CSUM` type sits at 4080, its
/// value at 4084, `DATA_SELFID` at 4088, and the block ends at 4096.
const SUB_TOTAL: i64 = 255;
const SUB_DATA: i64 = 239;
const N_SUB: i64 = 16;
const RS_REGION_END: i64 = SUB_TOTAL * N_SUB; // 4080
/// RS(255,239) repairs up to (255-239)/2 = 8 symbols per subblock.
const RS_BUDGET: i64 = 8;

/// Where a byte offset falls inside a beamfs data block.
///
/// Meaningful for beamfs only. Other filesystems have their own layout,
/// so their events are recorded with region "unknown" rather than
/// forced into a geometry that is not theirs.
fn locate(off: i64) -> (Option<i64>, Option<i64>, &'static str) {
    if off >= 4088 { return (None, None, "data_selfid"); }
    if off >= 4080 { return (None, None, "data_csum"); }
    if off >= RS_REGION_END { return (None, None, "pad"); }
    let idx = off / SUB_TOTAL;
    let pos = off % SUB_TOTAL;
    (Some(idx), Some(pos), if pos < SUB_DATA { "rs_data" } else { "rs_parity" })
}

/// One decoded `flip_log` line.
#[derive(Debug, Clone)]
struct FlipRow {
    seq: i64,
    ktime_ns: i64,
    sector: i64,
    bio_op: i64,
    byte_offset: i64,
    bit_index: i64,
    before: i64,
    after: i64,
}

fn parse_hex_byte(s: &str) -> i64 {
    i64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap_or(-1)
}

/// base64 -d | gzip -dc through the shell: both tools exist on host and
/// nodes, and this keeps the crate free of compression dependencies.
fn decode_b64_gzip(b64: &str) -> Result<String> {
    let mut child = Command::new("sh")
        .arg("-c").arg("base64 -d | gzip -dc")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().context("spawn base64/gzip")?;
    child.stdin.as_mut().context("stdin")?
        .write_all(b64.as_bytes()).context("write b64")?;
    let out = child.wait_with_output().context("wait decode")?;
    if !out.status.success() { anyhow::bail!("decode failed"); }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// What the kernel reported for one (iblock, subblock).
#[derive(Debug, Clone, Default)]
struct KernelVerdict {
    outcome: String,
    inode_no: Option<i64>,
}

/// Index the kernel's verdicts by subblock.
///
/// beamfs names what it acted on:
///   beamfs/inline: ino=11 iblock=55 subblock=7: 3 symbol(s) corrected
///   beamfs/inline: ino=11 iblock=55 subblock=7 uncorrectable
/// keyed by (iblock, subblock) -- the same key the flip reconstruction
/// produces, which is what lets the two be joined. Fail-closed paths
/// name no subblock, so they are keyed on iblock and cover the block.
///
/// Joining these turns "64 flips, hash unchanged" into "these flips hit
/// this subblock and RS repaired it there": the difference between
/// asserting a correction happened and showing it.
fn parse_kernel_verdicts(dmesg: &str)
    -> (HashMap<(i64, i64), KernelVerdict>, HashMap<i64, KernelVerdict>)
{
    let mut by_sub = HashMap::new();
    let mut by_block = HashMap::new();
    let field = |line: &str, key: &str| -> Option<i64> {
        let i = line.find(key)? + key.len();
        let rest = &line[i..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        rest[..end].parse::<i64>().ok()
    };
    for line in dmesg.lines() {
        if !line.contains("beamfs/inline:") { continue; }
        let ino = field(line, "ino=");
        let Some(iblock) = field(line, "iblock=") else { continue };
        if let Some(sub) = field(line, "subblock=") {
            let outcome = if line.contains("uncorrectable") { "uncorrectable" }
                          else if line.contains("corrected") { "corrected" }
                          else { continue };
            by_sub.insert((iblock, sub),
                KernelVerdict { outcome: outcome.into(), inode_no: ino });
        } else if line.contains("mismatch") || line.contains("bad descriptor")
               || line.contains("pointer") || line.contains("unallocated") {
            by_block.insert(iblock,
                KernelVerdict { outcome: "unprotected".into(), inode_no: ino });
        }
    }
    (by_sub, by_block)
}

fn decode_flip_log(b64: &str) -> Result<Vec<FlipRow>> {
    let text = decode_b64_gzip(b64)?;

    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < 8 { continue; }
        let n = |i: usize| f[i].trim().parse::<i64>().unwrap_or(-1);
        // ktime_ns == 0 marks an unused ring slot.
        if n(1) == 0 { continue; }
        rows.push(FlipRow {
            seq: n(0), ktime_ns: n(1), sector: n(2), bio_op: n(3),
            byte_offset: n(4), bit_index: n(5),
            before: parse_hex_byte(f[6]), after: parse_hex_byte(f[7]),
        });
    }
    Ok(rows)
}

/// Is this sector inside one of the "start:end" intervals?
fn in_ranges(sector: i64, ranges: &str) -> bool {
    ranges.split(',').any(|r| {
        match r.split_once(':') {
            Some((a, b)) => {
                let (lo, hi) = (a.trim().parse::<i64>().unwrap_or(-1),
                                b.trim().parse::<i64>().unwrap_or(-1));
                lo >= 0 && sector >= lo && sector < hi
            }
            None => false,
        }
    })
}

/// Reconstruct and store every flip of one measurement.
fn ingest_flip_events(db: &Path, run_id: i64, r: &AttackRecord) -> Result<usize> {
    let Some(b64) = r.flip_log_b64.as_deref() else { return Ok(0) };
    let rows = decode_flip_log(b64)?;
    if rows.is_empty() { return Ok(0); }

    let is_beamfs = r.fs == "beamfs";
    let ranges = r.target_ranges.as_deref().unwrap_or("");

    // Budget occupancy is a property of the subblock over the whole run,
    // not of a single flip: count the distinct bytes hit in each
    // (block, subblock) before deciding whether any of them exceeded the
    // correction radius.
    let mut hits: HashMap<(i64, i64), std::collections::HashSet<i64>> = HashMap::new();
    if is_beamfs {
        for f in &rows {
            let off_in_block = f.byte_offset % 4096;
            let (idx, pos, _) = locate(off_in_block);
            if let (Some(i), Some(p)) = (idx, pos) {
                hits.entry((f.sector / 8, i)).or_default().insert(p);
            }
        }
    }

    let dmesg = r.dmesg_b64.as_deref()
        .and_then(|b| decode_b64_gzip(b).ok())
        .unwrap_or_default();
    let (verdict_by_sub, verdict_by_block) = parse_kernel_verdicts(&dmesg);

    let mut sql = String::from("BEGIN;");
    for f in &rows {
        // byte_offset is relative to the bio payload. Filesystem writes
        // start on a block boundary, so modulo 4096 gives the offset
        // within the block; a bio that did not would misplace this, and
        // that assumption is stated rather than hidden.
        let off_in_block = f.byte_offset % 4096;
        let block_no = f.sector / 8;
        let (idx, pos, region) = if is_beamfs {
            locate(off_in_block)
        } else {
            (None, None, "unknown")
        };
        let bytes_hit = idx.and_then(|i| hits.get(&(block_no, i)).map(|s| i64::try_from(s.len()).unwrap_or(i64::MAX)));
        let over = bytes_hit.map(|b| i64::from(b > RS_BUDGET));
        let on_target = if ranges.is_empty() { None }
                        else { Some(i64::from(in_ranges(f.sector, ranges))) };

        // What the kernel did about this flip: looked up on the subblock
        // it hit, falling back to a block-level fail-closed verdict. No
        // entry means no reported reaction -- parity never needed, or a
        // block never read back.
        let kv = idx.and_then(|i| verdict_by_sub.get(&(block_no, i)))
                    .or_else(|| verdict_by_block.get(&block_no));
        let outcome = match kv {
            Some(v) => v.outcome.as_str(),
            None if !is_beamfs => "unknown",
            None => "no_effect",
        };
        let inode_no = kv.and_then(|v| v.inode_no);

        write!(sql,
            "INSERT INTO flip_event (run_id, fs, seq, ktime_ns, sector, bio_op,              byte_offset, bit_index, before_byte, after_byte, block_no,              offset_in_block, subblock_idx, offset_in_sub, region, on_target,              sub_bytes_hit, rs_budget, over_budget, outcome, inode_no) VALUES              ({run_id}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});",
            sql_str(Some(&r.fs)),
            f.seq, f.ktime_ns, f.sector, f.bio_op, f.byte_offset, f.bit_index,
            f.before, f.after, block_no, off_in_block,
            sql_num(idx), sql_num(pos), sql_str(Some(region)),
            sql_num(on_target), sql_num(bytes_hit),
            if is_beamfs { RS_BUDGET.to_string() } else { "NULL".into() },
            sql_num(over),
            sql_str(Some(outcome)),
            sql_num(inode_no),
        ).unwrap();
    }
    sql.push_str("COMMIT;");
    exec(db, &sql)?;
    Ok(rows.len())
}

/// Ingest one run directory by reading its all-records.txt.
///
/// The directory name carries the timestamp (beamfs-bench-multifs-YYYYMMDD-HHMMSS),
/// which is the only date available for archived runs: nothing else was
/// recorded at the time.
pub fn ingest_run_dir(db: &Path, run_dir: &Path, campaign_id: Option<i64>) -> Result<i64> {
    let records_path = run_dir.join("all-records.txt");
    let text = std::fs::read_to_string(&records_path)
        .with_context(|| format!("read {}", records_path.display()))?;
    let records = parse_records(&text);
    if records.is_empty() {
        anyhow::bail!("no ATTACK record in {records_path:?}");
    }

    let name = run_dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let started = name
        .rsplit_once("-multifs-")
        .map(|(_, ts)| ts.to_string())
        .filter(|ts| ts.len() == 15).map_or_else(|| "unknown".into(), |ts| format!("{}-{}-{} {}:{}:{}",
            &ts[0..4], &ts[4..6], &ts[6..8], &ts[9..11], &ts[11..13], &ts[13..15]));

    let scope = records.iter().find_map(|r| r.workload_mode.as_deref());

    ingest_run(
        db, campaign_id, &started, None, "multifs", Some(0),
        "emufi", None, scope,
        env!("CARGO_PKG_VERSION"),
        run_dir.to_str(),
        &records,
    )
}

/// Has this directory already been ingested? Matched on `log_path`, which
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
        .with_context(|| format!("read {}", root.display()))?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir()
            && p.file_name().and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("beamfs-bench-multifs-"))
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
    Ok(i32::from(failed > 0))
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

/// Drop old runs. Aggregates in `flip_distribution` are kept: they are the
/// point of computing them at ingest, so trends survive the purge.
pub fn cmd_purge(older_than_days: u32) -> Result<i32> {
    let db = default_db_path();
    let before = exec(&db, "SELECT COUNT(*) FROM run;")?;
    let sql = format!(
        "PRAGMA foreign_keys = ON;          DELETE FROM flip_raw WHERE run_id IN            (SELECT id FROM run WHERE started_at < datetime('now', '-{older_than_days} days'));          DELETE FROM measurement WHERE run_id IN            (SELECT id FROM run WHERE started_at < datetime('now', '-{older_than_days} days'));          DELETE FROM validity WHERE run_id IN            (SELECT id FROM run WHERE started_at < datetime('now', '-{older_than_days} days'));          DELETE FROM run WHERE started_at < datetime('now', '-{older_than_days} days');          VACUUM;"
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
