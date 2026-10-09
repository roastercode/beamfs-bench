# beamfs-bench

A Rust harness that runs beamfs, and the filesystems it is compared
with, under fault injection on a libvirt cluster, and records every
attack. It is a measurement instrument, not a judgment engine: the
nodes emit raw records, and the verdict is derived from them in Rust
(`src/synthesis.rs`).

Version 0.15.0. Its 0.14 releases ran the fault-injection campaign of
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

## Known defects of 0.15.0

Found with 0.14.8 while writing the v3 report, whose results are read
from the raw records, not from these summaries; 0.15.0 does not touch
them:

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

## Before a patch series is mailed

`beamfs-bench upstream --base <rev>` checks the kernel patch series on
a branch of `~/git/linux` the way its reviewers and their build robots
will: commits and trailers, checkpatch with spdxcheck on every patch,
the mails and the cover letter, MAINTAINERS, Kconfig, the documentation
of the userspace interfaces, builds under several configurations with
W=1, sparse, kernel-doc and checkstack, the merge into mainline and
linux-next, and the documentation build. Since 0.15.0 the code analysis
gate runs the same checkpatch on the module sources.

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
