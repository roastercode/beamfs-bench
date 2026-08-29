-- beamfs-bench measurement database
--
-- One row per run, per filesystem measurement, per validity verdict.
-- Raw flip logs are kept for the three most recent runs only; their
-- aggregates are permanent, so long-term trends survive the purge.
--
-- Design intent: a third party must be able to (a) replay a measurement
-- from what is stored here, and (b) contest a published figure by
-- checking it against the record. Hence the emufi seed, the toolchain
-- and hardware identification, and the worker checksum: a campaign whose
-- runs did not all execute the same worker is not a campaign, and
-- without the hash that is invisible.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------- campaign
-- Groups runs that belong to one measurement series. Validity criteria
-- are recorded here, before the campaign starts: discarding runs after
-- seeing their results is the kind of thing a referee is right to
-- refuse, so the rule must predate the data.
CREATE TABLE IF NOT EXISTS campaign (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    label           TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    ended_at        TEXT,
    n_repetitions   INTEGER,
    doses_ppm       TEXT,           -- comma-separated
    fs_list         TEXT,
    inject_scope    TEXT,           -- targeted | uniform
    validity_rule   TEXT,           -- stated before the first run
    worker_sha256   TEXT,           -- all runs must share this
    notes           TEXT
);

-- --------------------------------------------------------------------- run
CREATE TABLE IF NOT EXISTS run (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id         INTEGER REFERENCES campaign(id) ON DELETE SET NULL,
    started_at          TEXT NOT NULL,
    ended_at            TEXT,
    duration_s          INTEGER,
    command             TEXT NOT NULL,     -- full | multifs | mega | fsck ...
    exit_code           INTEGER,

    -- injection parameters, in full: a figure that cannot be replayed
    -- is not a measurement
    injector            TEXT,
    emufi_seed          INTEGER,
    prob_ppm            INTEGER,
    max_flips           INTEGER,
    flip_width          INTEGER,
    width_mode          INTEGER,
    chip_count          INTEGER,
    multi_chip          INTEGER,
    inject_scope        TEXT,
    workload_mode       TEXT,
    workload_duration_s INTEGER,

    -- provenance
    bench_version       TEXT,
    worker_sha256       TEXT,
    beamfs_head         TEXT,
    yocto_head          TEXT,
    bench_head          TEXT,

    -- measurement environment: results obtained under different
    -- toolchains are not comparable, as the styhead->walnascar
    -- migration made plain
    kernel_guest        TEXT,
    kernel_host         TEXT,
    emufi_version       TEXT,
    gcc_host            TEXT,
    yocto_release       TEXT,

    -- hardware under test
    device_model        TEXT,
    device_size_bytes   INTEGER,
    via_usb_hub         INTEGER,           -- 0/1

    log_path            TEXT,
    notes               TEXT
);

CREATE INDEX IF NOT EXISTS idx_run_campaign ON run(campaign_id);
CREATE INDEX IF NOT EXISTS idx_run_started  ON run(started_at);

-- ------------------------------------------------------------- measurement
-- One row per filesystem per run.
CREATE TABLE IF NOT EXISTS measurement (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    fs                  TEXT NOT NULL,
    device              TEXT,

    -- exposure: how much attack this filesystem actually took. Published
    -- alongside the outcome rather than assumed equal, because it is not:
    -- buffered filesystems emit fewer bios in a given window, and their
    -- files sit at different offsets.
    call_delta          INTEGER,           -- bios seen by the injector
    flip_delta          INTEGER,           -- flips delivered
    flips_on_target     INTEGER,           -- flips inside the verified file
    target_ranges       TEXT,              -- sector intervals of that file

    -- outcome
    cat_rc              INTEGER,
    hash_pre            TEXT,
    hash_post           TEXT,
    intact              INTEGER,           -- 1 = read ok and hash matches
    rs_corrected        INTEGER,
    dmesg_uncorrectable INTEGER,
    dmesg_eio           INTEGER,
    bits_diff           INTEGER,
    file_size           INTEGER,

    -- did the write workload actually run here? A silent no is how a
    -- comparison ends up meaningless (beamfs has no O_DIRECT support,
    -- so direct=1 failed on it while succeeding elsewhere)
    workload_ran        INTEGER,
    workload_bytes      INTEGER,

    -- filesystem health, distinct from file integrity. Measured on
    -- 2026-08-29: under uniform injection ext4 logged 13 errors within a
    -- 30 s window, hit ext4_validate_block_bitmap and ext4_lookup
    -- failures, and could no longer find its own test file -- which the
    -- harness reported only as HASH_PRE=missing, indistinguishable from a
    -- setup bug. A filesystem that survives with its data intact and one
    -- that loses access to it are different outcomes, and the record has
    -- to say which happened. Volumes are reformatted at every setup, so
    -- these counts are what the run itself produced.
    fs_error_count      INTEGER,
    fs_health           TEXT,              -- clean | errors
                                           -- | readonly_remount | unmountable

    -- evidence
    flip_log_sha256     TEXT,              -- verifiable after FIFO purge
    dmesg_excerpt       TEXT
);

CREATE INDEX IF NOT EXISTS idx_meas_run ON measurement(run_id);
CREATE INDEX IF NOT EXISTS idx_meas_fs  ON measurement(fs);

-- ---------------------------------------------------------------- validity
-- Separate from the result on purpose: whether a measurement is usable
-- is a different question from what it says, and conflating the two is
-- how a run with no workload gets read as a resilience result.
CREATE TABLE IF NOT EXISTS validity (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    fs          TEXT NOT NULL,
    verdict     TEXT NOT NULL,   -- usable | no_workload | target_not_hit
                                 -- | dose_imbalance | injector_saturated
                                 -- | fs_degraded | target_file_missing
    reason      TEXT
);

CREATE INDEX IF NOT EXISTS idx_validity_run ON validity(run_id);

-- -------------------------------------------------------- flip_distribution
-- Permanent aggregates, computed at ingest. These outlive the raw log
-- and are what the long-term curves are drawn from.
CREATE TABLE IF NOT EXISTS flip_distribution (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    fs              TEXT NOT NULL,
    n_flips         INTEGER,
    sector_min      INTEGER,
    sector_max      INTEGER,
    sector_p25      INTEGER,
    sector_median   INTEGER,
    sector_p75      INTEGER,
    n_on_target     INTEGER,
    n_metadata_zone INTEGER,   -- NULL until per-FS geometry is queried;
                               -- a wrong number here would be worse than none
    n_other         INTEGER
);

CREATE INDEX IF NOT EXISTS idx_dist_run ON flip_distribution(run_id);

-- ---------------------------------------------------------------- flip_raw
-- FIFO, three most recent runs. Ingest computes the aggregates first,
-- then purges anything older.
CREATE TABLE IF NOT EXISTS flip_raw (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    fs          TEXT NOT NULL,
    seq         INTEGER,
    ktime_ns    INTEGER,
    sector      INTEGER,
    bio_op      INTEGER,
    byte_offset INTEGER,
    bit_index   INTEGER,
    before_byte INTEGER,
    after_byte  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_raw_run ON flip_raw(run_id, fs);

-- ------------------------------------------------------------------- views
-- Dose-response, usable measurements only.
CREATE VIEW IF NOT EXISTS v_dose_response AS
SELECT r.prob_ppm,
       m.fs,
       COUNT(*)                     AS n,
       AVG(m.flip_delta)            AS flips_avg,
       AVG(m.flips_on_target)       AS on_target_avg,
       SUM(m.intact)                AS n_intact,
       SUM(CASE WHEN m.cat_rc = 1 THEN 1 ELSE 0 END) AS n_refused,
       SUM(CASE WHEN m.cat_rc = 0 AND m.intact = 0 THEN 1 ELSE 0 END)
                                    AS n_silent_corruption,
       SUM(CASE WHEN m.fs_health != 'clean' THEN 1 ELSE 0 END)
                                    AS n_fs_degraded,
       AVG(m.fs_error_count)        AS fs_errors_avg
FROM measurement m
JOIN run r ON r.id = m.run_id
JOIN validity v ON v.run_id = m.run_id AND v.fs = m.fs
WHERE v.verdict = 'usable'
GROUP BY r.prob_ppm, m.fs;

-- Exposure actually achieved, which is what makes a cross-filesystem
-- comparison defensible or not.
CREATE VIEW IF NOT EXISTS v_exposure AS
SELECT r.id AS run_id, r.prob_ppm, m.fs,
       m.call_delta, m.flip_delta, m.flips_on_target,
       m.workload_ran, v.verdict
FROM measurement m
JOIN run r ON r.id = m.run_id
LEFT JOIN validity v ON v.run_id = m.run_id AND v.fs = m.fs;
