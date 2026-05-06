# beamfs-bench Roadmap

This document is the staged plan for `beamfs-bench` development. It
consolidates the existing planning artefacts that were previously
scattered :

- `Documentation/HOW-TO-BUILD-beamfs-bench.md` (build, install,
  release procedure, 4 modes).
- `Documentation/roadmap-bench.md` (architectural decision record
  dated 2026-05-04 on the multifs/cluster verdict redesign ;
  M1/M2/M3 milestones for that specific redesign). Note : this
  file is an ADR, not a product roadmap. It is preserved as-is
  for traceability and is referenced from Stage 4 below.
- `~/git/beamfs/Documentation/TODO.md` section 13
  ("beamfs-bench improvements"), section 14 (priority matrix).
- This session's quality sprint output (2026-05-06, v0.7.2 release).

The product roadmap below complements these and does not override
them. Items in this roadmap that derive from a decision in
`roadmap-bench.md` cite the milestone explicitly.

Closing a stage requires the validation chain in `context-recadrage.md`
(R19 `beamfs-bench full --auto-confirm` exit 0 ; clippy clean ;
manifest GPG-signed ; lockstep across both repos per R9).

---

## Status table

| Stage | Title                                                  | Status                  | Tag                |
|-------|--------------------------------------------------------|-------------------------|--------------------|
| 0     | MIL no-NAK pipeline (multifs + cluster + analyse)      | CLOSED 2026-05-02       | `v0.4.0`           |
| 1     | Quality sprint (USB module, exit_code, R21 adaptive)   | CLOSED 2026-05-06       | `v0.7.2`           |
| 2     | Cluster scope verdict derivation (TODO §13.1)          | PENDING                 | (planned `v0.8.0`) |
| 3     | RadFI/EMUFI state timeline in forensics (TODO §13.2)   | PENDING                 | (planned `v0.9.0`) |
| 4     | Multifs/cluster verdict redesign (M1+M2+M3 of ADR)     | PENDING                 | (planned `v1.0.0`) |
| 5     | Worker duplication factor (TODO §13.3)                 | PENDING                 | (planned `v1.1.0`) |
| 6     | Statistical N-runs aggregation (M3 of ADR, paper v3)   | PENDING                 | (planned `v1.2.0`) |

Tag naming convention follows beamfs : `vMAJOR.MINOR.PATCH`. Each
closing stage produces an annotated GPG-signed git tag plus an
overlay ebuild bump in `beamfs-overlay`. Manifest of v1.0.0 (Stage 4
close) is the empirical artefact justifying paper v3 figure
"fraction_corrompue vs prob, by FS".

---

## Stage 0 -- MIL no-NAK pipeline

**Status :** CLOSED 2026-05-02 (`v0.4.0`).

The unified Rust harness replaces the legacy bash harness
(`Tir-*.sh`, `hpc-benchmark*.sh`, ~1176 lines) with a single
`beamfs-bench` binary. All 8 subcommands (version, multifs, analyse,
full, bitrot, metadata, crash, fsck) functional.

Architectural anchors :
- R-isolation cluster topology (master observer, compute01 holds
  USB victims, compute02/03 cluster compute) enforced in
  `lifecycle.rs::assert_isolation_architecture()`.
- Multifs verdict derivation in `synthesis.rs` deriving
  `RS_RECOVERED|RS_PASSTHROUGH|RS_FAILED|FS_PANIC|CORRUPTED_DATA`.
- R19 pipeline : `beamfs-bench full --auto-confirm` chains lifecycle
  -> bootstrap -> multifs -> cluster_attack -> cluster_verify ->
  forensics -> tarball -> dmesg-clean -> manifest GPG-signed ->
  regression check.

---

## Stage 1 -- Quality sprint

**Status :** CLOSED 2026-05-06 (`v0.7.2`).
**Reference :** session 2026-05-06 transcript ; HEAD `0b2b1d0`.

Patches L1 to L7 cumulative. Three categorical improvements :

**Hardware-adaptive USB layer.** New `usb_health` module
(~470 LOC, 5 unit tests) running as Phase 0.0a. Reads libvirt XML +
host-side `blockdev` + `dd` head/tail probe + 4 KiB canary
write-back to detect read-only-physical USB sticks. Replaces the
hardcoded `EXPECTED_HEALTHY_SLOTS` constant with runtime detection.
New `FS_PRIORITY` + `build_fs_mapping(verdicts)` in `multifs.rs`.

**Exit code semantic correctness.** `aggregate_exit_code()` in
`analyse.rs` enforces R19 Phase 6 criterion "12/12 RECOVERED
DIFFS=0" by inspecting actual cluster + multifs verdicts (was
previously documented but unchecked ; only `multifs_result.is_some()`
gated). 6 new unit tests for `verdict_is_pass()`.

**R21 isolation adaptive on compute01.** `assert_isolation_architecture()`
keeps strict-equal `[vda, vdb]` for master + compute02 + compute03
(invariant : these VMs MUST never get a USB), but accepts any
vd[c-z] count on compute01 (the only USB host). The post-2026-05-06
2-USB hardware layout is now valid where the previous 5-USB
hardcoded list rejected it.

**Tooling :** clippy::pedantic now passes Tier 1 gate. Documented
build/release procedure in `HOW-TO-BUILD-beamfs-bench.md` (4 modes :
dev iteration, live ebuild, versioned ebuild, full release with bump).

R19 final pass : tarball
`beamfs-bench-analyse-full-20260506-115825.tar.gz` (12.8 MB),
manifest `manifest-20260506T100152Z.json.asc`, 0 fatal regression,
4 nodes dmesg clean, exit code 0.

---

## Stage 2 -- Cluster scope verdict derivation

**Status :** PENDING.
**Source :** `~/git/beamfs/Documentation/TODO.md` section 13.1.
**Effort :** 2-3h.

`synthesis.rs` derives 5-class verdicts for the multifs scope by
cross-referencing ATTACK and VERIFY records. The cluster scope
emits factual records in the same format
(`CLUSTER|HOST=...|HASH_PRE/POST/CAT_RC/RS_CORRECTED/...`) but
no derivation runs on them. Cluster verdicts remain raw
(`VERIFIED|DIFFS=N`) at synthesis time.

Asymmetry to remove :
- multifs : worker emits factual ; `synthesis.rs` derives logical.
- cluster : worker emits factual ; nothing derives logical.

**Action :** write `derive_cluster_verdict()` mirroring
`derive_verdict_beamfs()` and apply per-node + per-prob. Aggregate
cluster verdict = worst case across 4 nodes (FS_PANIC dominates,
CORRUPTED_DATA next, RS_FAILED next, RS_PASSTHROUGH next,
RS_RECOVERED best).

**DoD :**
- `derive_cluster_verdict()` implemented + unit tested.
- R19 cluster output prints derived verdict per (host, prob)
  alongside raw `DIFFS=N`.
- `aggregate_exit_code()` already iterates cluster verdicts via
  Stage 1 L4 patch ; behaviour remains correct after this change.

---

## Stage 3 -- RadFI/EMUFI state timeline in forensics

**Status :** PENDING.
**Source :** `~/git/beamfs/Documentation/TODO.md` section 13.2.
**Effort :** 1-2h.

VM-side forensics capture dmesg, ftrace, perf, lsmod, but not the
`/sys/kernel/debug/{radfi,emufi}/{call_count,flip_count,target_dev,
target_block,probability,enabled,hook_blk}` content snapshots at
arm/disarm boundaries. Reading dmesg for radfi log entries works
but is not always emitted at every flip ; a clean before/after
counter snapshot is missing.

**Action :** add `radfi-timeline.log` (or `emufi-timeline.log`
post-rename) per-VM capture file. `worker.sh attack` already reads
CALL_B/FLIP_B/CALL_A/FLIP_A for delta computation ; persist these
per-attack with monotonic timestamps. `forensics.rs` post-capture
appends final state. Output format machine-parseable for
cross-correlation with dmesg RS corrected events.

**DoD :**
- Per-VM timeline file in run_dir.
- Format specified in `Documentation/forensics.md` (TBD).
- Trial run shows monotonic ordering ; cross-correlatable with
  dmesg via timestamp.

**Coupling note :** Stage 3 must align with EMUFI rename
(`debugfs root /sys/kernel/debug/radfi/` → `/sys/kernel/debug/emufi/`).
See `~/git/emufi/ROADMAP.md` section 7 (Migration plan).

---

## Stage 4 -- Multifs/cluster verdict redesign (paper v3 prerequisite)

**Status :** PENDING.
**Source :** `Documentation/roadmap-bench.md` (ADR 2026-05-04).
**Effort :** ~16-20h (M1 5h + M2 6-8h + M3 5h).

The most strategic open item. `roadmap-bench.md` section 1
documents the methodological bias : current verdict cannot
discriminate FS that protect data from FS that don't, because the
read after attack is served from pagecache. Concrete factual
evidence from R19 sub-5 (2026-05-04) :

| FS       | flips@1k | flips@100k | flips@1M | DIFFS pre/post |
|----------|----------|------------|----------|----------------|
| ext4     | 0        | 0          | 15       | 0              |
| ext3     | 0        | 17         | 111      | 0              |
| btrfs    | 0        | 0          | 3        | 0              |
| squashfs | 0        | 2          | 13       | 0              |
| beamfs   | 0        | 2          | 8        | 0              |

ext4 received 15 flips and reports DIFFS=0 -- ext4 has no FEC. The
flips landed elsewhere on the device, or the byte that flipped is
not re-read. `roadmap-bench.md` lays out the 6-component fix C1-C6
mapped to 3 milestones.

Stage 4 close means **paper v3 figure 1** ("fraction_corrompue vs
prob, by FS") becomes empirically defensible. ext4 sortira
`CORRUPTED_DATA`, beamfs sortira `RS_RECOVERED` with `dmesg
"corrected by RS FEC" >= 1`, both observed in the same GPG-signed
manifest.

**M1 -- forensic truth** (~5h, no kernel change) :
- C1 : worker cycle write/sync/umount/attack/mount/read with
  drop_caches between attack and verify.
- C3 : 5-class verdict derivation uniform across multifs + cluster
  (this overlaps with Stage 2 ; one fix covers both).
- C4 : bits_diff / frac_corrupt / hamm_blocks metrics in records.

**M2 -- targeted attack** (~6-8h, kernel change) :
- C2 : `target_block_list` in RadFI debugfs (or its EMUFI
  successor), parsed at write. Comma-list semantic.
- Worker filefrag + per-FS block-list derivation (ext4 + beamfs
  first via filefrag/FIEMAP ; btrfs and squashfs deferred to M2.5
  if scientifically useful).
- RadFI ebuild bump 0.1.3 → 0.1.4 (or EMUFI bump to v0.2.x).
- beamfs-bench bump to v1.0.0 (architectural change).
- Coupled with **beamfs Stage 4 deliverable on FIEMAP support**
  (cf. beamfs-roadmap stage 4 `iomap_iter` path).

**M3 -- statistics** (~5h, instrumentation) :
- C5 : N=5 runs per (FS, prob) point. Default N=1 (preserve current
  R19 time). N=5 invoked only for paper v3 dataset.
- C6 : flip-budget calibration. Two-pass : run with prob=test,
  measure effective flips, adjust prob to hit target budget per FS.
- JSON aggregation for paper v3 figure.

**DoD (full Stage 4 close) :**
- ext4 verdict CORRUPTED_DATA empirically observed under targeted
  attack, in a GPG-signed manifest.
- beamfs verdict RS_RECOVERED empirically observed under same
  targeted attack, with `dmesg "corrected by RS FEC" >= 1`, in
  the same manifest.
- Quantitative difference between `frac_corrompue` ext4 and
  `frac_corrompue` beamfs over three orders of magnitude of prob.
- Manifest reproducible by a third party (R36 tarball + procedure
  in `Documentation/testing`).

**Risks** (per `roadmap-bench.md` section 6) :
- R1 RadFI API change breaks existing tests (mitigation :
  `target_block_list` additive, default empty).
- R2 `filefrag` not in image (mitigation : verify
  `IMAGE_INSTALL` of `hpc-arm64-research-beamfs` before M2 ;
  add e2fsprogs filefrag if absent).
- R3 N=5 runs balloon R19 to 30+ min (mitigation :
  `--runs-per-point` flag, default N=1).
- R4 `target_block_list` for btrfs/squashfs non-trivial (mitigation :
  M2 ships ext4 + beamfs first).
- R5 ext4 sorts as RS_FAILED instead of CORRUPTED_DATA (mitigation :
  refine target_block_list to data blocks not metadata).

---

## Stage 5 -- Factor multifs/cluster worker duplication

**Status :** PENDING.
**Source :** `~/git/beamfs/Documentation/TODO.md` section 13.3.
**Effort :** TBD (refactor scope, smallish).

Cross-reference to `~/git/beamfs/Documentation/TODO.md` "beamfs-bench
evolution: cluster_*/multifs worker duplication" (single source of
truth there). After Stages 2 + 4 unify the verdict derivation
across the two scopes, the underlying worker code paths become
amenable to a clean factor. Postpone until then to avoid two
refactors.

---

## Stage 6 -- Statistical N-runs aggregation (paper v3 dataset)

**Status :** PENDING.
**Source :** Stage 4 M3 (already specified there).
**Effort :** included in Stage 4 budget.

Listed separately because the JSON aggregation format is the API
between beamfs-bench and the gnuplot/PGFPlots scripts that produce
the paper v3 figures. The format must be stable across paper
revisions. Specify in `Documentation/paper-dataset-format.md` (TBD)
before any plotting code is written.

---

## Cross-product coupling

beamfs-bench is the harness. It exists to validate beamfs and
demonstrate the BEAMFS-vs-others contrast under EM SEE injection.
It is therefore coupled to three sibling products :

- **beamfs** (`~/git/beamfs/`) : the device under test. Stage 4 M2
  requires beamfs to implement `.fiemap` in `inode_operations` so
  `filefrag` returns the actual block list. Tracked in
  `~/git/beamfs/Documentation/roadmap.md` (and TODO §11).
- **radfi** (`~/git/radfi/`) : the legacy injector, frozen at
  v0.1.3 pending migration to emufi.
- **emufi** (`~/git/emufi/`) : the successor injector. Stage 4 M2
  is delivered against EMUFI (target_block_list lands in the new
  module), and Stage 3 forensics timeline file naming follows
  emufi rename.

Lockstep R9 applies on every cross-product change : both repos
commit before push, both pushes verified before R19, R19 green
before tag.

---

## Document maintenance

This roadmap is the source of truth for `beamfs-bench` stages.
Each stage close updates the status table at the top, adds the
reference tag, and migrates the stage description to past tense
with the closing date. Items move out from the relevant section
of `~/git/beamfs/Documentation/TODO.md` section 13 and into a
"closed" record below.

`HOW-TO-BUILD-beamfs-bench.md` is independent and tracks build
mechanics. `roadmap-bench.md` is preserved as the verdict-redesign
ADR and is referenced from Stage 4. Neither file is modified by
roadmap updates.

---

## Closed items log

- 2026-05-02 : Stage 0 closed (`v0.4.0`). MIL no-NAK pipeline.
- 2026-05-03 : `R31 invariant + tarball forensic enrichment`
  closed (3 commits in beamfs-bench). See TODO §13.4 for details.
- 2026-05-06 : Stage 1 closed (`v0.7.2`). Quality sprint
  (L1 USB module, L4 exit_code, L5 adaptive USB, L6 R21 adaptive,
  L7 clippy). HEAD `0b2b1d0`, manifest `manifest-20260506T100152Z`.
