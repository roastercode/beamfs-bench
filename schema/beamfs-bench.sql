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

-- --------------------------------------------------------------- flip_event
-- One row per individual flip, reconstructed.
--
-- Counting impacts is not measuring an outcome. Fourteen flips spread
-- across fourteen RS subblocks are trivially corrected; the same
-- fourteen concentrated in two subblocks exceed the 8-symbol radius and
-- are lost. The aggregate figures cannot tell those cases apart, yet
-- they decide the result -- so the reconstruction has to be per event.
--
-- beamfs data block geometry (beamfs.h): 16 interleaved RS(255,239)
-- subblocks fill bytes 0..4079 as [239 data][16 parity] repeated, then
-- DATA_CSUM type at 4080, its value at 4084, DATA_SELFID at 4088, and
-- the block ends at 4096. A flip's byte offset therefore places it
-- exactly: subblock index, position within it, and whether it landed on
-- payload, on parity, or on a descriptor -- three cases the correction
-- path treats differently.
--
-- Dimensions are kept separate rather than pre-projected: a 3D plot
-- shows three of them, and which three is a question to be answered per
-- analysis, not baked into the storage.
CREATE TABLE IF NOT EXISTS flip_event (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    fs              TEXT NOT NULL,

    -- as recorded by the injector
    seq             INTEGER,
    ktime_ns        INTEGER,
    sector          INTEGER,
    bio_op          INTEGER,      -- 0 read, 1 write
    byte_offset     INTEGER,      -- within the bio payload
    bit_index       INTEGER,      -- 0..7 within the byte
    before_byte     INTEGER,
    after_byte      INTEGER,

    -- reconstructed position
    block_no        INTEGER,      -- sector / 8
    offset_in_block INTEGER,      -- 0..4095
    subblock_idx    INTEGER,      -- 0..15, NULL outside the RS region
    offset_in_sub   INTEGER,      -- 0..254 within that subblock
    region          TEXT,         -- rs_data | rs_parity | data_csum
                                  -- | data_selfid | pad | unknown

    -- reconstructed context
    zone            TEXT,         -- superblock | inode_table | bitmap
                                  -- | data | reserved | outside_fs
    on_target       INTEGER,      -- 1 if inside the verified file's extents
    inode_no        INTEGER,      -- when derivable

    -- energy relative to the correction budget: how many distinct bytes
    -- of this subblock were hit during the run, against the 8 symbols
    -- RS(255,239) can repair. This is the axis that separates a
    -- harmless event from a fatal one.
    sub_bytes_hit   INTEGER,
    rs_budget       INTEGER DEFAULT 8,
    over_budget     INTEGER,      -- 1 when sub_bytes_hit > rs_budget

    -- outcome, filled from the kernel's own account
    outcome         TEXT          -- corrected | uncorrectable | unprotected
                                  -- | no_effect | unknown
);

CREATE INDEX IF NOT EXISTS idx_event_run    ON flip_event(run_id, fs);
CREATE INDEX IF NOT EXISTS idx_event_region ON flip_event(region);
CREATE INDEX IF NOT EXISTS idx_event_sub    ON flip_event(run_id, fs, block_no, subblock_idx);

-- Occupancy of the correction budget, per subblock actually touched.
-- Reading this tells how close a campaign ran to the RS limit, which no
-- flip count can.
CREATE VIEW IF NOT EXISTS v_rs_occupancy AS
SELECT e.run_id, e.fs, e.block_no, e.subblock_idx,
       COUNT(DISTINCT e.offset_in_sub) AS bytes_hit,
       MAX(e.rs_budget)                AS budget,
       CASE WHEN COUNT(DISTINCT e.offset_in_sub) > MAX(e.rs_budget)
            THEN 1 ELSE 0 END          AS over_budget
FROM flip_event e
WHERE e.subblock_idx IS NOT NULL
GROUP BY e.run_id, e.fs, e.block_no, e.subblock_idx;

-- Where flips land, by structure. The comparison "beamfs corrected"
-- means little without knowing whether the hits were on payload, on
-- parity, or on an unprotected pointer.
CREATE VIEW IF NOT EXISTS v_region_breakdown AS
SELECT run_id, fs, region, zone,
       COUNT(*)            AS n,
       SUM(on_target)      AS n_on_target,
       SUM(over_budget)    AS n_over_budget
FROM flip_event
GROUP BY run_id, fs, region, zone;

-- ---------------------------------------------------------------- perf
-- Performance characterisation, one row per filesystem per operation.
--
-- A filesystem that adds forward error correction is slower; the
-- question a reviewer asks is by how much, on which operation, and how
-- predictably. Hence one row per operation rather than an aggregate,
-- and percentiles rather than means: beamfs trades median latency for a
-- tighter distribution -- v2 measured a 1.74x p50/p99 spread against
-- 5.00x for ext4 -- and a mean hides exactly that.
--
-- CPU time sits alongside throughput because on slow media the RS
-- encode hides behind the device, while on fast media it is the cost.
CREATE TABLE IF NOT EXISTS perf (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    fs            TEXT NOT NULL,
    op            TEXT NOT NULL,   -- seqwrite | seqread | randwrite
                                   -- | randread | fsyncwrite
    /*
     * nominal   : no injection, the cost of the format
     * correcting: injection active, the cost of the format plus the
     *             cost of doing the work it exists for
     *
     * The gap between the two is what resilience actually costs. A
     * system under radiation keeps serving while upsets arrive, so the
     * correcting figure is the one that sizes a deployment; the
     * nominal figure alone would understate it. Measured accidentally
     * on 2026-08-30 when a perf run overlapped an injection run: system
     * CPU reached 94-97% on reads, against a much lower nominal load.
     */
    regime        TEXT NOT NULL DEFAULT 'nominal',
    bw_bytes      INTEGER,         -- bytes per second
    iops          REAL,
    p50_ns        INTEGER,
    p95_ns        INTEGER,
    p99_ns        INTEGER,
    p999_ns       INTEGER,
    usr_cpu       REAL,            -- percent
    sys_cpu       REAL,

    -- Write amplification, filled on the 'amplification' pseudo-op:
    -- how many device bytes one logical byte costs. INLINE stores 3824
    -- logical bytes in a 4096-byte block, so 7% is structural before
    -- any read-modify-write on partial writes.
    logical_bytes INTEGER,
    device_bytes  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_perf_run ON perf(run_id, fs);

-- Ratio against a baseline filesystem, which is what a reader wants:
-- not "beamfs writes at 700 KB/s" but "beamfs writes at 0.4x ext4".
CREATE VIEW IF NOT EXISTS v_perf_ratio AS
SELECT p.run_id, p.op, p.fs,
       p.bw_bytes, p.p50_ns, p.p99_ns,
       ROUND(CAST(b.bw_bytes AS REAL) / NULLIF(p.bw_bytes, 0), 2) AS bw_slowdown,
       ROUND(CAST(p.p50_ns  AS REAL) / NULLIF(b.p50_ns, 0),  2) AS p50_ratio,
       ROUND(CAST(p.p99_ns  AS REAL) / NULLIF(b.p99_ns, 0),  2) AS p99_ratio,
       ROUND(CAST(p.p99_ns  AS REAL) / NULLIF(p.p50_ns, 0),  2) AS spread
FROM perf p
JOIN perf b ON b.run_id = p.run_id AND b.op = p.op
             AND b.fs = 'ext4' AND b.regime = p.regime
WHERE p.fs != 'ext4';

-- What resilience costs: the same filesystem, same operation, with and
-- without the injector running.
CREATE VIEW IF NOT EXISTS v_perf_regime_gap AS
SELECT n.run_id, n.fs, n.op,
       n.bw_bytes AS bw_nominal,
       c.bw_bytes AS bw_correcting,
       ROUND(CAST(n.bw_bytes AS REAL) / NULLIF(c.bw_bytes, 0), 2) AS bw_cost,
       n.p99_ns   AS p99_nominal,
       c.p99_ns   AS p99_correcting,
       ROUND(CAST(c.p99_ns AS REAL) / NULLIF(n.p99_ns, 0), 2) AS p99_cost,
       n.sys_cpu  AS cpu_nominal,
       c.sys_cpu  AS cpu_correcting
FROM perf n
JOIN perf c ON c.run_id = n.run_id AND c.fs = n.fs AND c.op = n.op
WHERE n.regime = 'nominal' AND c.regime = 'correcting';
