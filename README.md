# beamfs-bench

A Rust harness that runs beamfs, and the filesystems it is compared
with, under fault injection on a libvirt cluster, and records every
attack. It is a measurement instrument, not a judgment engine: the
nodes emit raw records, and the verdict is derived from them in Rust
(`src/synthesis.rs`).

Version 0.16.1. Its 0.14 releases ran the fault-injection campaign of
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

## Known defects of 0.16.1

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

`beamfs-bench upstream --base <rev>` checks the kernel patch series on
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

## License

GPL-2.0-only, see `COPYING`.
