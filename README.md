# beamfs-bench

A Rust harness that runs beamfs, and the filesystems it is compared
with, under fault injection on a libvirt cluster, and records every
attack. It is a measurement instrument, not a judgment engine: the
nodes emit raw records, and the verdict is derived from them in Rust
(`src/synthesis.rs`).

Version 0.16.2. Its 0.14 releases ran the fault-injection campaign of
the beamfs v3 technical report,
[10.5281/zenodo.23253350](https://doi.org/10.5281/zenodo.23253350):
run 2 from `661e8aa` (0.14.6), run 3 from `60155f3` (0.14.7), run 4 from
`607716e` (0.14.8). The injector is emufi
([EMUFI v1](https://doi.org/10.5281/zenodo.20041762)); RadFI, its
predecessor, still names some options and records in the code.

## Verdicts

Each attack ends in one verdict:

- passing: `RS_RECOVERED` (beamfs corrected at least one symbol and the
  file read back intact), `RS_PASSTHROUGH` (the file read back intact
  and no correction was needed), `RS_FAIL_CLOSED` (beamfs refused the
  read rather than return wrong bytes);
- failing: `CORRUPTED_DATA` (wrong bytes returned), `RS_FAILED`,
  `FS_PANIC`;
- for filesystems without forward error correction: `RECOVERED`,
  `SILENT_CORRUPTION`;
- `NOT_EXERCISED`: no attack reached the target.

## Known defects of 0.16.2

Found with 0.14.8 while writing the v3 report, whose results are read
from the raw records, not from these summaries; the 0.15 and 0.16
releases do not touch them:

- the synthesis gives the attacked files as "3 files of 3KB", where
  they are 262 144 bytes;
- a btrfs read refused on a checksum mismatch, with a healthy remount,
  is labelled `FS_PANIC`;
- the kernel log of the btrfs attacks is not captured in the multifs
  records (`DMESG_B64` empty);
- squashfs is never targeted;
- the count of corrected symbols is read from a rate-limited kernel log
  and is capped;
- the topology report says the beamfs module is loaded when beamfs is
  built into the kernel.

The regression check of `full` (phase 8.3) compares nothing: its eight
comparators are empty, and it is given the directory of the code
analysis rather than the run's. A run passes it whatever it measured.

## Before a patch series is mailed

`beamfs-bench upstream --base <rev>` runs the crate `beamfs-upstream` (shared with beamfs-xfstests since 0.18.0): it checks the kernel patch series on
a branch of `~/git/linux` the way its reviewers and their build robots
will: commits and trailers (one `Assisted-by: LLM` line, the analysis
tools used named after it if any, as
Documentation/process/coding-assistants.rst writes it), checkpatch
with spdxcheck on every patch, the mails, the cover letter with a
paragraph beginning "Tools" and one beginning "Testing"
(Documentation/process/generated-content.rst), MAINTAINERS, Kconfig,
the documentation of the userspace interfaces, builds under several
configurations, on 32 bits (i386, arm with LLVM) and big-endian (s390
with LLVM) as well, with W=1 and with gcc -W, sparse, smatch,
coccicheck, kernel-doc and checkstack, the merge into mainline and
linux-next, and the documentation build. It needs sparse and smatch
recent enough for the kernel's scripts/checker-valid.sh, spatch
(coccinelle, its python and OCaml rules working), clang with lld and
the LLVM binutils, and for arm64 an aarch64 cross gcc. When modpost
finds a symbol undefined, the calls are placed by file, line and
function. A check left out, arm64 with `--no-cross` or the newer trees
with an empty `--newer`, leaves the series not ready to mail: the run
names it and exits 3, as when a check fails.

Since 0.16.2 the base must hold the newest mainline tag kernel.org
lists, read with `git ls-remote` within 20 seconds: a series is reviewed
against mainline as it is when it is mailed. When the tag is not in the
kernel tree, or the base does not hold it, the check fails and says
what to fetch or onto what to rebase; kernel.org out of reach leaves
the check out, and the series not ready to mail.

The runtime half of Documentation/process/submit-checklist.rst is not
run here. beamfs-xfstests runs xfstests on kernels the bitbake chain
built with lockdep, PROVE_RCU, DEBUG_OBJECTS and kmemleak; how much of
the code those runs exercise is not measured, and the rest of that half
(DEBUG_PREEMPT and DEBUG_PAGEALLOC with the other debug options, kernels
without SMP and without preemption, slab and page allocation failure
injection, linux-next) is run nowhere yet.

The code analysis gate of `full` runs the same checkpatch and kernel-doc
on the module sources, from a worktree of `BEAMFS_BENCH_LINUX_BASE`
(origin/master by default) of the kernel repository, with sparse,
clang, the commit signatures, clippy and the lockstep with the layer.
Every check of it has to run: a tool that is not installed fails it.

## The lab

The bench drives four libvirt VMs, `beamfs-master` and
`beamfs-compute01` to `beamfs-compute03`, on the network `hpcnet`
(bridge `virbr1`, 192.168.56.0/24), over SSH as `hpcadmin` with the key
`recipes-core/images/files/beamfs-release` of the layer `yocto-beamfs`
(`BEAMFS_BENCH_SSH_KEY` overrides it). The filesystems compared by
`multifs` sit on USB flash media passed through to `beamfs-compute01`
only, as virtio disks;
the cluster attack targets the beamfs data volume of all four nodes,
the master included. Before a full run the bench checks this layout in
the libvirt definitions and refuses to run on a cluster that does not
match it.

The images of the nodes are built by the Yocto layer `yocto-beamfs`;
the images and the layer used for the v3 report are in its Zenodo
record.

## Build

    cargo build --release
    cargo test --release
    ./target/release/beamfs-bench version

On the author's station the bench is installed from the ebuild
`sys-fs/beamfs-bench` of the overlay `beamfs-overlay`, whose source tree
at the v3 commit is also in the Zenodo record.
`Documentation/HOW-TO-BUILD-beamfs-bench.md` gives the build and release
procedure.

## Documentation

`doc/beamfs-bench.1` is the manual (`man -l doc/beamfs-bench.1`):
commands, options, environment, the lab, the files.

## Changelog

The full record is in [CHANGELOG.md](CHANGELOG.md); its latest entries
follow.

### [0.20.3] - 2026-10-24

- README: 0.17.0 to 0.19.1 are dated by 0.19.2, the version that shipped
  them; 0.20.2 had written their dates without the day.

### [0.20.2] - 2026-10-24

- README: the entries 0.18.0 to 0.20.0, which this section had skipped.

### [0.20.1] - 2026-10-24

- Built against beamfs-upstream 0.9.0: `upstream` builds the filesystem
  as a module on hexagon, where a 64-bit division the other ports do
  inline shows in modpost, and refuses a MAINTAINERS entry out of
  alphabetical order (Cargo.lock).

### [0.20.0] - 2026-10-19

- `upstream` carries the plan's `base.behind` reason to the checker: a
  base that does not hold the newest tag on kernel.org is mailed as the
  plan declares, the reason in the signed summary (beamfs-upstream 0.8.0).

### [0.19.2] - 2026-10-19

0.17.0 to 0.19.1 were never built on their own: Cargo.toml went from
0.16.2 (2026-10-14) to 0.19.2 (`800f15a`, 2026-10-19), and their entries
shipped together in it.

- `upstream --plan`: the plan's `cc` takes precedence over `--cc`.

### [0.19.1] - 2026-10-19

- The GPG priming of a session comes from beamfs-upstream 0.7.0, shared
  with beamfs-xfstests.

### [0.19.0] - 2026-10-19

- `upstream --plan`: `checkpatch --strict` blocks, with the plan's
  justified exceptions (beamfs-upstream 0.6.1).

### [0.18.0] - 2026-10-19

- `upstream` moved to the crate beamfs-upstream (0.3.0), shared with
  beamfs-xfstests: the series is built from `upstream/series.toml` of
  the beamfs repository with `--plan`, from a commit, on the newest
  mainline tag; the build checks hold against the series only the
  diagnostics of its own files; the MAINTAINERS entry may end the
  series; `--quick` runs the checks of seconds as a gate before a
  measurement, with no verdict on mailing.
- With beamfs-upstream 0.4.0, `upstream` ends with git am of the mails
  and git send-email --dry-run to the recipients get_maintainer names
  plus `--cc` (the author's gmail by default), and builds fs/ at every
  commit; `send.sh` beside the patches is the real command.

### [0.17.0] - 2026-10-14

- Every flip is joined to the kernel's own verdict through the
  `beamfs_rs_event` tracepoint (beamfs v3.1+), armed for the attack
  window and shipped in the record as `RS_TRACE_B64`: every decode
  path, no rate limit, keyed by physical block and subblock, so no
  extent reconstruction stands between a flip and what became of it.
  Outcomes are `corrected`, `rmw_neutralised`, `uncorrectable` and
  `no_rs_event`; `verdict_source` says whether the trace or, on an
  older kernel, the dmesg lines decided, and `rs_symbols` and
  `rs_flags` keep what the tracepoint said. `queue_idx` and
  `mechanism` tie a flip to the campaign event that produced it.
- `offset_in_block` is `(sector % 8) * 512 + byte_offset`, the place
  of emufi 0.9.0's exact sector; `byte_offset % 4096` read the offset
  into the bio segment and placed a flip in any segment past the
  first in the wrong block.
- A campaign is stated as a beam when `BEAM_FLUX` is set, with
  `EXPOSURE_SECONDS` or `FLUENCE`, `SIGMA_CM2_PER_BIT`,
  `SEFI_SIGMA_CM2` or `DUT` (`pi-zero-2w`, `imx8mp`, `orangecrab`, the
  devices of Memon et al. at `PHYSICS_ENERGY_MEV`), `PHYSICS_SOURCE`
  and `PHYSICS_GEOMETRY`; `emufi-radsim` writes the manifest beside
  the run as `campaign-<fs>.json` and it is pushed next to the blob.
  `SEFI_HOLD_MS`, `SEFI_STATUS` and `SEFI_PERMANENT` reach the
  injector, and `sefi_clear` is written before every attack.
- Files go to the nodes with rsync; `scp_to` is gone.
- Databases created before this version gain the new columns on the
  next `init`.
- `--flip-locality` and `--target-struct` are documented as the module
  numbers them: locality 0 to 5 (the help offered `RANDOM`, `CONSECUTIVE`
  and `EXACT`, words the module never read), and structure 3 bitmap,
  4 root directory (the help had them the other way round).

### [0.16.2] - 2026-10-14

- `upstream` checks that the base holds the newest mainline tag
  kernel.org lists, read with `git ls-remote` within 20 seconds: its
  commit must be in the kernel tree and an ancestor of the base, or
  the check fails and says what to fetch or onto what to rebase.
  kernel.org out of reach leaves the check out, and so the series not
  ready to mail.

### [0.16.1] - 2026-10-10

- a check that does not run does not pass (`98de956`)

### [0.16.0] - 2026-10-09

- kernel.org submission checks, whole (`f669949`)

## License

GPL-2.0-only, see `COPYING`.
