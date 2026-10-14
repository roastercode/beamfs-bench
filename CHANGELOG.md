# Changelog

Every change to beamfs-bench, newest first.

The entries below were rebuilt on 2026-10-14 from the commit history:
one line per commit, its subject and its short hash, under the version
its Cargo.toml carried after each commit; a subject that begins with
that version is given without it, and one that names nothing but the
version gives way to the first paragraph of its message. Tags are named
on the commit they point to. From the next version on, each version adds
its entry, written with the change, and the README carries the latest
entries.

## [0.16.2] - 2026-10-14

- `upstream` checks that the base holds the newest mainline tag
  kernel.org lists, read with `git ls-remote` within 20 seconds: its
  commit must be in the kernel tree and an ancestor of the base, or
  the check fails and says what to fetch or onto what to rebase.
  kernel.org out of reach leaves the check out, and so the series not
  ready to mail.

## [0.16.1] - 2026-10-10

- a check that does not run does not pass (`98de956`)

## [0.16.0] - 2026-10-09

- kernel.org submission checks, whole (`f669949`)

## [0.15.1] - 2026-10-09

- build what upstream says it builds (`641b493`)

## [0.15.0] - 2026-10-09

- check a patch series before it is mailed (`0086c1d`)

## [0.14.8] - 2026-10-08

- README and COPYING for the public repository (`d6635c1`)
- check the extent list emufi holds (`607716e`)

## [0.14.7] - 2026-10-08

- the cluster attacks its own file (`60155f3`)

## [0.14.6] - 2026-10-01

- the manifest is signed only when it can be, and gpg cannot hang it (`661e8aa`)

## [0.14.5] - 2026-10-01

- the lab key is the one the image authorizes (`5eb5a0a`)

## [0.14.4] - 2026-09-29

- Test G reads the repair from the medium; full keeps to the cluster (`8542121`)

## [0.14.3] - 2026-09-28

- the image is the one the layer builds (`a1820ae`)

## [0.14.2] - 2026-09-28

- the module version comes from the layer; the holder of a slot is found by what paths point at (`d54c7f4`)

## [0.14.1] - 2026-09-27

- the USB pre-flight reads the medium, and says what it read (`f8459a0`)

## [0.14.0] - 2026-09-21

- the shell is checked by the suite (`2abb068`)

## [0.13.0] - 2026-09-21

- a junction before every measurement (`82f4953`)

## [0.12.7] - 2026-08-17

- chain: --machine names which chain a run belongs to (`3c2012a`)
- chain: one seal per architecture, one variable per chain (`1c8b8b9`)
- chain: refuse to measure an image BX never saw (`884c7bd`)
- synthesis: a volume nobody attacked is not a volume that held (`524e4f9`)
- lab: the harness names one account on one station, thirty-seven times (`56f3e3e`)
- trace: attach a probe while it happens, instead of reading what it left (`e91ad20`)
- repo: a run's output is not part of the source tree (`1c5c797`)
- feat: BEAMFS_INTERLEAVE formats a cluster in the capsule layout (`674c2ff`)
- feat: write the whole run too, nothing dropped (`e2e3a15`)
- feat: write the evidence as one plain file, beside the tarball (`8b106a5`)
- feat: --no-bell, accepted on any subcommand (`e66af54`)
- fix(pipeline): modules.builtin lists kernel/fs/beamfs, not fs/beamfs (`a9d23c4`)
- fix(pipeline): identify the kernel, not a module nobody loads (`7361d14`)
- fix(pipeline): the lockstep check covers every kernel source (`429e797`)
- feat: ring when a run finishes, until someone answers (`9105c49`)
- docs: a manual page (`b26f76b`)
- feat(scrub): measure the scrubber, not just the reader (`e74d386`)
- feat(rsbench): measure the codec, in the guest and on the host (`8ed8690`)
- feat(dose): derive the event count from a deployment and a duration (`d37ff60`)
- feat(xfstests): run the kernel suite from the harness (`e59d2fc`)
- feat(indparity): measure what each parity mode does about a flipped pointer (`586add6`)
- feat(conservation): check the filesystem's own bookkeeping (`d8526ba`)
- feat(saturation): active protocol for Theorem v2.2 (`c67902e`)
- feat(perf): measure what the filesystem costs, in two regimes (`fd75893`)
- fix(pipeline): resolve the module path from uname -r (`c96a47a`)
- refactor: remove radfi, emufi is the only injector (`2fa4399`)
- fix(db): translate kernel logical blocks to physical before correlating (`f41de47`)
- refactor: last of the mechanical pedantic warnings (`88d5c55`)
- refactor: clone_from, Copy enum, borrowed parameters (`5523734`)
- refactor: drop Result from three infallible functions (`9bf6ddb`)
- refactor: name enum variants instead of wildcards, fix bail formatting (`323df9e`)
- fix(db): store flip_log_sha256, and tighten two signatures (`6a7ffc0`)
- refactor: merge identical match arms, tidy signatures and literals (`3791ac0`)
- refactor: hoist local items to module scope (`20a3a23`)
- refactor: convert remaining manual let-else patterns (`d1dfc92`)
- refactor: writeln in forensics_host (`1019298`)
- refactor: clear most of the clippy::pedantic backlog (`8b0c1a0`)
- feat(db): reconstruct each flip, not just count them (`fbfcdf8`)
- feat(db): ingest measurements, and say which ones are usable (`0833399`)
- feat(db): measurement database schema (`0669502`)
- feat(worker): record how many flips landed in the verified file's blocks (`bf5eb38`)
- feat(worker): add INJECT_SCOPE=uniform, a physically faithful attack model (`bda9068`)
- fix(worker): make write-active usable -- TARGET_REL ordering, scratch file (`e61885d`)
- fix(worker): count every fail-closed path in DMESG_UNCORRECTABLE (`65927d6`)
- fix(fsck): stop treating NOT_IMPLEMENTED as a passing beamfs result (`afd5bf3`)
- fix(worker): run fsck.beamfs in Test D, and capture its real exit code (`f1b55e7`)
- fix(cluster): pose the eight injector parameters that were multifs-only (`e6a9cc5`)

## [0.12.6] - 2026-08-15

- feat(bench): post per-extent target ranges instead of the enclosing interval (`82a1fd7`)

## [0.12.5] - 2026-08-15

- fix(bench): actually wire MAX_FLIPS into worker.sh (missing from 71dd050) (`45484b3`)
- feat(bench): forward MAX_FLIPS to give every filesystem the same injection dose (`71dd050`)

## [0.12.4] - 2026-08-15

- feat(bench): record HASH_PRECAT to separate pre-existing from attack-induced corruption (`21ee0a9`)

## [0.12.3] - 2026-08-14

- feat(synthesis): NOT_EXERCISED verdict for filesystems the campaign never attacked (v0.12.3) (`1b78151`)

## [0.12.1] - 2026-05-15

- feat(bench): measure and publish per-FS reachability at setup (`199fa23`)
- fix(bench): use extent END column in filefrag parsing (unfragmented FS got 1-block range) (`1548d3e`)
- fix(cluster): apply FLIP_WIDTH/MULTI_CHIP/CHIP_COUNT/WIDTH_MODE in cluster_attack (`1dbd3d0`)
- feat(code-analysis): extend emdash_r16 to full R16 forbidden Unicode set (`ffad7b2`)
- fix(multifs): show actual injector name in attack banner (was hardcoded "RadFI") (`4dbef08`)
- fix(cluster): apply target_block_range in cluster_attack (was computed but never posed) (`e0705ac`)
- feat(data-csum): R19(b) tooling for DATA_CSUM active validation (`869bac9`)
- fix(pipeline): update KO_PATH_IN_FS for kernel 7.0.9 (`52f2720`)
- feat(verdict): RS_FAIL_CLOSED for kernel-detected fail-closed corruption (`a4c1693`)
- feat(cluster): S3.1 file-precise EM injection on cluster path (v0.12.1) (`5193b0a`)

## [0.12.0] - 2026-05-15

- forensics: migrate VM rootfs capture to resolve_vda_source (Q1) + version bump paths (Q2) (`9f90dbe`)
- feat(pipeline): resolve vda source dynamically via virsh dumpxml (Bug B fix) (`e33dd4b`)

## [0.11.1] - 2026-05-14

- chore(release): bump version to 0.11.1 (`70016b0`)

## [0.11.0] - 2026-05-13

- pipeline: switch canonical image from .ext2 to .beamfs (`f76480a`)
- feat(tindirect): subcommand validating triple-indirect addressing (v0.11.0) (`0cdcbf0`)

## [0.10.0] - 2026-05-09

- fix(worker): detect built-in beamfs and reed_solomon via /proc (`05dd94a`)
- feat(bench): BEAMFS_INODE_COUNT env var propagation for mkfs -N (`1108e43`)
- fix(pipeline): bump yocto kernel files path 0.1.0 -> 0.1.1 (`734f75e`)
- doc/roadmap: append v1.0 multifs equitable bench section (`d884c02`)
- fix(cluster): propagate BEAMFS_SCHEME via SSH for compute01 worker.sh (`f1e347b`)
- fix(worker): pre-N100 device-level teardown to prevent residual mounts (`a7f3e99`)
- feat(bench): pre-N3 parametrization for v3 publication campaign (`45cebb8`)
- fix(multifs): S3.1 missing Rust-side wiring (correctif 3ec9d32) (`907a012`)
- feat: S3.1 file-precise EM injection via target_block_range (`3ec9d32`)
- chore(version): bump 0.9.0 -> 0.10.0 (S2.3+S2.4 file-precise targeting) (`6574c98`)

## [0.9.0] - 2026-05-08

- fix(worker): S2.4 remove second beamfs guard in filefrag_phys() (`4ad6f04`)
- feat(worker): S2.3 enable filefrag for beamfs (file-precise targeting) (`91a94d0`)
- feat(worker): Phase A.5 - SB-targeted I/O burst for RS saturation (`233564b`)
- fix(worker): Phase A.4-fix - sudo test -e for flip_log existence (`75d2c39`)
- chore(deps): update Cargo.lock for v0.9.0 bump (`f8467a8`)
- feat(worker): Phase B.1-fix - add ZFS support, retire jfs/bcachefs/hfsplus (`c470159`)
- chore(version): Phase B.2 - bump beamfs-bench to v0.9.0 (`2e244be`)

## [0.8.3] - 2026-05-08

- feat(worker): Phase B.1 - extend worker.sh to 15 multi-OS FS (`87a880d`)
- feat(workload): Phase A.4 - bytes-on-disk attack normalization (`5997b71`)
- fix(synthesis): Phase A.3.1 - call extract_workload_mode (R20 hotfix) (`74ca142`)
- feat(workload): Phase A.3 - workload modes (static + write-active) (`8992aea`)
- feat(synthesis): Phase A.2.2 - consume FRAG_RELOCATED in synthesis.md (`b3f1d59`)
- feat(worker): Phase A.2 - filefrag CoW relocation tracking (`5bc0dca`)
- feat(synthesis,analyse): Phase A.1 - verdict_detail companion to verdict (`c1c916d`)
- fix(host_auth): detect NOPASSWD before sudo -v (autonomous campaign) (`ddc627c`, tag v0.8.3)

## [0.8.2] - 2026-05-07

- feat(worker): fix filefrag -v + bump file size to 256 KiB (publication-grade) (`bf91331`, tag v0.8.2)

## [0.8.1] - 2026-05-07

- chore(release): v0.8.1 - Architecture C lifecycle isolation (`f81974d`, tag v0.8.1)

## [0.8.0] - 2026-05-07

- feat(lifecycle): extend FS-test isolation to 3 computes (Architecture C) (`be1a7ce`)
- docs(diagnosis): R19 v0.8.0 night session, MBU bursting unobserved (`38e9570`)
- chore(bench): bump 0.7.8 -> 0.8.0 (emufi 0.3.2 full debugfs surface) (`51ebe06`, tag v0.8.0)

## [0.7.8] - 2026-05-06

- feat(bench): expose full emufi 0.3.2 debugfs surface as cumulative CLI flags (`509009c`)
- docs(plan): beamfs-bench v2 USB topology roadmap (`c191651`)
- fix(worker): sudo test -e for debugfs presence checks (v0.7.8) (`e4490fe`, tag v0.7.8)

## [0.7.7] - 2026-05-06

- feat(cluster): propagate attack envvars host->remote (v0.7.7) (`73caa2e`, tag v0.7.7)

## [0.7.6] - 2026-05-06

- feat(worker): push inject_on_read=1 explicitly (v0.7.6) (`87eb7aa`, tag v0.7.6)

## [0.7.5] - 2026-05-06

- feat(worker): activate per_inode_rs on all 5 mkfs sites (v0.7.5) (`6ece137`, tag v0.7.5)

## [0.7.4] - 2026-05-06

- feat(worker): push emufi 0.3.0 surgical envvars (v0.7.4) (`8fbc743`, tag v0.7.4)

## [0.7.3] - 2026-05-06

- feat(worker): push FLIP_WIDTH and LET_CLASS env vars to injector debugfs (`5ed7d23`, tag v0.7.3)

## [0.7.2] - 2026-05-06

- docs(roadmap): replace 11 em-dashes by ASCII -- (R16 conformity) (`b7c0fbc`)
- docs: add product roadmap consolidating planning artefacts (`46b3e87`)
- fix(bench): mod tests after make_tarball in analyse.rs (`0b2b1d0`, tag v0.7.2)

## [0.7.1] - 2026-05-06

- fix(bench): adaptive R21 isolation check on compute01 (`8daf04d`, tag v0.7.1)

## [0.7.0] - 2026-05-06

- docs: add HOW-TO-BUILD reference + link in README (`62ced19`)
- fix(bench): aggregate exit_code from cluster + multifs verdicts (`ab1e08e`, tag v0.7.0)
- feat(bench): adaptive USB count + Phase 0.0a usb_health module (`baebb54`)

## [0.6.0] - 2026-05-06

- fix(bench): enforce strict injector isolation + complete B2a path migration (`65a827b`)
- feat(bench): M-EMUFI-1 B2b - propagate --injector through Rust modules (`ab56371`)
- feat(bench): M-EMUFI-1 B2a - worker.sh injector dispatch + Cargo bump 0.6.0 (`de03fb2`)

## [0.5.1] - 2026-05-04

- feat(bench): naming_r17 -- skip citations (backtick/quote) on .md files (`3e7fc32`, tag v0.5.1)

## [0.5.0] - 2026-05-04

- feat(bench): retire 4 obsolete TEMPORARY exclusions, reclassify 2 as PERMANENT (`1a98d61`)
- chore(bench): replace em-dashes with ASCII hyphen in 4 source files (`5586c94`)
- feat(bench): Phase Y -- implement Tier 1 checkers (sparse + clang + kernel-doc + clippy) (`48ed12f`, tag v0.5.0)

## [0.4.9] - 2026-05-04

- feat(bench): M1.B.4 -- cluster verdict 5-classes derivation (`906c250`, tag v0.4.9)

## [0.4.8] - 2026-05-04

- feat(bench): M1.B.3 -- bit-level corruption metrics (cmp -l + popcount XOR) (`c94c5d7`, tag v0.4.8)

## [0.4.7] - 2026-05-04

- feat(bench): M1.B.2 -- worker cluster_attack uses umount/mount cycle (`799d72a`, tag v0.4.7)

## [0.4.6] - 2026-05-04

- feat(bench): M1.B.1 -- worker attack uses umount/mount cycle (multifs scope) (`fd044ce`, tag v0.4.6)

## [0.4.5] - 2026-05-04

- fix(bench): R19 unblock -- 3 TEMPORARY exclusions for code-analysis Tier 1 (`f6ac827`, tag v0.4.5)

## [0.4.4] - 2026-05-04

- fix(bench): naming_r17 -- self-exclude + temporary TODO.md exclusion (`716742e`, tag v0.4.4)

## [0.4.3] - 2026-05-04

- feat(bench): code-analysis Tier 1 -- 5 real checkers replace todo stubs (`5f8aee4`, tag v0.4.3)

## [0.4.2] - 2026-05-04

- feat(bench): M1.X session priming + M1.Y code-analysis activation (`eae3af2`, tag v0.4.2)

## [0.4.1] - 2026-05-04

- docs(roadmap-bench): architecture revisee multifs/cluster sous attaque RadFI (`147593e`)
- chore(release): bump version 0.4.0 -> 0.4.1 (`71fe504`, tag v0.4.1)

## [0.4.0] - 2026-05-03

- feat(bench): func-12 sub-4 -- --per-inode-rs flag for cluster /data bootstrap (`60e80dc`)
- chore(release): bump version 0.3.0 -> 0.4.0 + pin Cargo.lock (`6ebe83d`, tag v0.4.0)

## [0.3.0] - 2026-05-01

- feat(bench): code-analysis + regression-check skeleton + clippy strict zero (`6702fb1`)
- fix(forensics): R31 capture bugs (ssh quoting, known_hosts, manifest filter) (`e6c7441`)
- feat(forensics): enrich tarball with R31 audit trail artefacts (`5f8ad6f`)
- fix(pipeline): R31 verify .ext2 byte-identity after cp, before VM start (`62a0640`)
- fix(forensics): escape newlines in bpftrace probe script (`f007934`)
- feat(forensics): add host-side capture module + bpftrace opt-in flag (`4e604d5`)
- fix(bench): bench-2 redesign attack/verify for RS-FEC functional proof (`61ea13b`)
- docs(readme): add bench-2 + bench-3 rationalization items (`dbdc03f`)
- fix(bench): explicit -s inline for mkfs.beamfs invocations (`6c1e0c0`)
- feat(bench): tarball under /tmp/ for analyse/full (`6c4b7ea`)
- fix(bench): func-1 add fix B placement to INITIAL cluster_setup (`87815b1`)
- docs(naming): synthesis.rs BEAMFS -> beamfs (R17) (`95fd9ef`)
- docs(naming): align bench strings to "beamfs - resilient filesystem" (`88e748e`)
- fix(bench): 3 robustness fixes (cluster setup retry + metadata cleanup + gpg batch) (`f4b76f0`)
- feat(bench): mega scope + beamfs-bench-* naming alignment + bitbake log capture (`1c97274`)
- feat(pipeline): MIL no-NAK validation chain absorbing R21 invariants (`9cd6e50`)
- fix(forensics): wait on exact perf PID + validate header before exit (`97ca646`)
- docs(readme): mark bitrot/metadata/crash/fsck as DONE in status table (`d638949`)
- feat(bench): add crash + fsck subcommands (Test B + Test D) (`df76a4d`)
- feat(bench): add metadata subcommand (Test A, RadFI deterministic) (`3f54611`)
- docs(readme): document R-isolation architecture + bitrot DONE (`7c390b6`)
- feat(bench): isolate FS-test victim node + Phase 0 isolation pre-flight (`b23ab2a`)
- feat(bench): add bitrot subcommand (Test C - offline injection) (`9c787f6`)
- docs(readme): rewrite beamfs-bench README post-full-implementation (`8b5d151`)
- feat(bench): add 'full' subcommand wiring lifecycle+bootstrap+analyse (`8d4ee71`)

## [0.2.0] - 2026-04-30

- feat(bench): add cluster /data bootstrap + worker.sh action (`c6886b0`)
- feat(bench): add lifecycle module for VM destroy/start/wait_ssh (`36dabd3`)
- feat(beamfs-bench): port analyse subcommand + cluster-wide forensics + safety pipeline (`2b0e0c0`)

## [0.1.0] - 2026-04-30

- feat(beamfs-bench): port multifs subcommand from Tir-multifs.sh (`ee4765a`)
- feat(beamfs-bench): add Rust skeleton with subcommand surface (`a34ed79`)
