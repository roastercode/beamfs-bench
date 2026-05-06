# beamfs-bench

Unified Rust harness for beamfs resilience testing under RadFI live
fault injection. Replaces the legacy bash harness (`Tir-*.sh`,
`hpc-benchmark*.sh`, ~1176 lines) with a single Rust binary.

> **Building or releasing ?** See
> [`Documentation/HOW-TO-BUILD-beamfs-bench.md`](Documentation/HOW-TO-BUILD-beamfs-bench.md)
> for the canonical build, install, and release procedure (4 modes :
> dev iteration, live ebuild, versioned ebuild, full release with bump).

## Status (2026-05-01)

| Subcommand | Status   | Description                                              |
|------------|----------|----------------------------------------------------------|
| `version`  | DONE     | Print version + status, exit                             |
| `multifs`  | DONE     | 5 FS x 3 probs head-to-head bench on USB (compute01)     |
| `analyse`  | DONE     | Forensic wrapper, 3 scopes (quick / standard / full)     |
| `full`     | DONE     | Phase 0 isolation pre-flight + lifecycle + bootstrap + analyse |
| `bitrot`   | DONE     | Test C : offline dd injection + observation (compute01)  |
| `metadata` | DONE     | Test A : RadFI deterministic on metadata blocks          |
| `crash`    | DONE     | Test B : virsh destroy mid-write + remount observation   |
| `fsck`     | DONE     | Test D : fsck recovery post-FS_PANIC                     |

**bench-2 redesign** (substep 10, 2026-05-02) : `multifs` and cluster
attack/verify actions reworked from random-overwrite (semantically broken)
to pristine-read under live RadFI attack. Verdict derivation moved from
`worker.sh` to `synthesis.rs`. See sections below.



## Architecture (R-isolation)

The bench enforces a strict separation between the orchestrator and
the FS-under-test victims. The 5 USB sticks holding the filesystem
partitions are physically attached to `beamfs-compute01` only.
Master remains a non-victim observer.

beamfs-master    (192.168.56.10) : vda + vdb only       (orchestrator)
beamfs-compute01 (192.168.56.11) : vda + vdb + vdc..vdg (FS-test holder)
beamfs-compute02 (192.168.56.12) : vda + vdb only       (cluster compute)
beamfs-compute03 (192.168.56.13) : vda + vdb only       (cluster compute)


`beamfs-bench full` Phase 0 (`assert_isolation_architecture()`)
inspects libvirt persistent XML and refuses to run on a
non-conforming cluster. See `context-recadrage.md` R-isolation.

## Canonical use : `beamfs-bench full`

`beamfs-bench full` is the canonical pre-push validation per R19 of
the beamfs context-recadrage. It chains:

1. **VM lifecycle** : virsh destroy aveugle + start + parallel SSH wait
2. **Cluster /data bootstrap** : insmod reed_solomon + beamfs.ko +
   mkfs.beamfs /dev/vdb + mount on 4 nodes (parallel, fail-fast)
3. **Worker deployment** : worker.sh on the 4 nodes
4. **Cluster topology discovery** (twice : pre and post bootstrap)
5. **Multifs head-to-head** : 5 FS x 3 probs on USB sticks (master)
6. **Cluster attack** : 4 nodes x 3 probs on /dev/vdb
7. **Forensics** : dmesg, ftrace, perf, RadFI counters, RS journal
8. **Tarball archive**

beamfs-bench full [--auto-confirm] [--no-tarball] [--shutdown] [--skip-vm-bootstrap]


Exit 0 only when:
- 4 VMs running + SSH ready
- 4 nodes /data mounted beamfs (BOOTSTRAP=OK x4)
- multifs beamfs verdict in {RS_RECOVERED, RS_PASSTHROUGH} 3/3 (probs 1k, 100k, 1M)
- cluster 12/12 hash-match DIFFS=0 (4 nodes x 3 probs)
- 0 new BUG/Oops/WARN in dmesg

Notes :
- `RS_RECOVERED` means RS-FEC actively corrected at least one symbol (RS_CORRECTED > 0)
  AND the file content matches its pre-attack hash. This is the strongest proof of
  FEC functional correctness.
- `RS_PASSTHROUGH` means the file content matches pre-attack but RS-FEC did not fire
  (no flip hit a target file block during the attack window). Both are R19-passing
  outcomes.
- `CORRUPTED_DATA`, `RS_FAILED`, `FS_PANIC` are R19-failing.

R19 forbids commit/push if any criterion fails.

## Installation (Gentoo)

> Full install + release procedure (mask 9999, versioned vs live ebuild,
> Manifest regeneration, common pitfalls) :
> [`Documentation/HOW-TO-BUILD-beamfs-bench.md`](Documentation/HOW-TO-BUILD-beamfs-bench.md).

Provided as `sys-fs/beamfs-bench` in the `beamfs-overlay` overlay
(local, `/var/db/repos/beamfs-overlay/`).

sudo emerge -v sys-fs/beamfs-bench


The ebuild also installs `/etc/sudoers.d/beamfs-bench` (NOPASSWD virsh
for the `libvirt` group). Add your user to that group:

sudo gpasswd -a $USER libvirt


Requirements:
- 4 VMs `beamfs-{master,compute01,compute02,compute03}` defined in
  libvirt qemu:///system (XMLs in `/etc/libvirt/qemu/`)
- libvirt network `hpcnet` (bridge `virbr1`, 192.168.56.0/24)
- SSH key `~/.ssh/hpclab_admin` (passwordless, on `hpcadmin@<vm-ip>`)
- 1+ USB sticks attached to **compute01** (not master ; R-isolation)
  via virtio-blk passthrough. The bench is fully adaptive to any
  count : add or remove `<disk type='block'>` entries in the
  libvirt XML and the bench picks them up at next run, mapping
  filesystems by priority (`beamfs`, `ext4`, `squashfs`, `ext3`,
  `btrfs`). Current default for hardware audit 2026-05-06 is 2 USBs
  (vdc=ext4 reference, vdd=beamfs under test). See
  [`Documentation/HOW-TO-BUILD-beamfs-bench.md`](Documentation/HOW-TO-BUILD-beamfs-bench.md)
  section 6.6 for adding/removing USBs.

## Build from source (development)

> Mode A in [`Documentation/HOW-TO-BUILD-beamfs-bench.md`](Documentation/HOW-TO-BUILD-beamfs-bench.md).

cd ~/git/beamfs-bench
cargo build --release
./target/release/beamfs-bench version


For dev iteration without re-emerge:

cargo install --path .
~/.cargo/bin/beamfs-bench full


## Output

Run dirs and tarballs land in
`~/git/yocto-beamfs/Documentation/runs/Tir-analyse-multifs-full-<TS>/`
(naming kept for archive compatibility with pre-2026-05-01 runs).

## Subcommand details

### `multifs`

5 FS x 3 probs head-to-head on USB sticks (master only).
Requires device validation prompt (R12) unless `--auto-confirm`.

### `analyse`

Wraps `multifs` with forensic capture. Three scopes:

- `quick`    : multifs(probs=[1M]) + master-only post-capture
- `standard` : multifs(default probs) + 4-node post-capture
- `full`     : standard + ftrace + perf + cluster_setup/attack/verify

### `full`

Wraps `analyse --scope=full` with VM lifecycle + cluster /data
bootstrap. The autonomous canonical bench. Run before any commit.

## License

GPL-2.0-only - same as the beamfs kernel module.

## Source

- Code   : roastercode/beamfs-bench (private)
- Issues : track via beamfs-devel TODO.md (private)

## TODO / Rationalization (2026-05-02)

Two structural items identified during substep 9 review.
Tracked in beamfs/Documentation/TODO.md under bench-2 and bench-3.

### bench-2 : attack/verify semantic mismatch

The `attack` action overwrites file-B2.bin with random bytes; the
`verify` action then expects pre/post hashes to match for a RECOVERED
verdict. By construction this can never be true on a working FS that
persists writes. Historical RECOVERED 12/12 verdicts on beamfs were
vacuous truths produced by an unrelated kernel bug
(d_file_type=1 emitting DT_FIFO, breaking `find -type f`).

Redesign required: inject RadFI on READ of pristine files, then verify
the data returned to userspace is correct (RS-FEC corrected) or that
the read fails with EIO (uncorrectable). Add a parsed dmesg counter
of `beamfs/inline:.*symbol(s) corrected` lines between attack and
verify timestamps.

### bench-3 : multifs vs cluster duplication

`setup`/`attack`/`verify` and `cluster_setup`/`cluster_attack`/
`cluster_verify` share roughly 80% of their logic in worker.sh.
Differences: $SUBDIR vs $MNT, verdict guard for empty POST_FILE,
hard-coded vs argument device. Factorize into shared helpers.

## Observation record formats

`beamfs-bench` is a measurement instrument, not a judgment engine
(per the rigour standards documented in `bitrot.rs` and `metadata.rs`).
`worker.sh` actions emit raw factual fields ; the verdict is derived
in Rust (`synthesis.rs` for multifs, future-extensible to cluster).

### multifs scope (`worker.sh attack` + `worker.sh verify`)

```
ATTACK|FS=<fs>|PROB=<p>|CALL_DELTA=<n>|FLIP_DELTA=<n>
       |TARGET=dir-B/file-B2.bin
       |HASH_PRE=<sha256|missing>
       |HASH_POST=<sha256|cat_failed|missing>
       |CAT_RC=<exit-code>
       |RS_CORRECTED=<count>
       |DMESG_UNCORRECTABLE=<count>
       |DMESG_EIO=<count>

VERIFY|fs=<fs>|prob=<p>
       |VERDICT=<MOUNTED|FS_PANIC>
       |DIFFS_PRE_POST=<n>
       |DIFFS_PRE_REMOUNT=<n>
       |N_FILES_CHANGED=<n>
       |details=<free text>
```

The case-asymmetry (`ATTACK` UPPERCASE keys vs `VERIFY` lowercase keys)
is preserved from the legacy `Tir-multifs.sh` parity contract documented
at the top of `synthesis.rs`. Do not normalize it without updating both.

### cluster scope (`worker.sh cluster_attack` + `worker.sh cluster_verify`)

```
CLUSTER|HOST=<vm>|PROB=<p>|CALL_DELTA=<n>|FLIP_DELTA=<n>
        |TARGET=dir-B/file-B2.bin
        |HASH_PRE=<sha256|missing>
        |HASH_POST=<sha256|cat_failed|missing>
        |CAT_RC=<exit-code>
        |RS_CORRECTED=<count>
        |DMESG_UNCORRECTABLE=<count>
        |DMESG_EIO=<count>

CLUSTER|HOST=<vm>|VERDICT=<VERIFIED>
        |DIFFS=<n>|N_FILES_CHANGED=<n>|details=<free text>
```

Cluster verdict derivation is not yet wired (substep 10 keeps the
multifs-only derivation in `synthesis.rs`). Cluster R19 criterion is
still the factual `DIFFS=0` 12/12 ; promoting cluster to the same
`RS_RECOVERED|RS_PASSTHROUGH` ladder is tracked as a follow-up.

### Other scopes

See `bitrot.rs`, `metadata.rs`, `crash.rs`, `fsck.rs` for their
respective record formats. Each scope owns its own `write_synthesis`.

## Verdict derivation (multifs)

`synthesis.rs::extract_verdict` cross-references the `ATTACK|` record
and the `VERIFY|` record for each (fs, prob) tuple, and returns one
verdict per the tables below. The decision is also documented inline
in the source.

### FS = beamfs (RS-FEC protected)

| mount_state | CAT_RC | hash_pre vs hash_post | RS_CORRECTED | verdict          |
|-------------|--------|-----------------------|--------------|------------------|
| FS_PANIC    | any    | any                   | any          | `FS_PANIC`       |
| MOUNTED     | != 0   | any                   | any          | `RS_FAILED`      |
| MOUNTED     | 0      | mismatch              | any          | `CORRUPTED_DATA` |
| MOUNTED     | 0      | match                 | > 0          | `RS_RECOVERED`   |
| MOUNTED     | 0      | match                 | 0            | `RS_PASSTHROUGH` |

`RS_RECOVERED` is the desired outcome under attack : RS-FEC fired
(at least one symbol corrected, observable in dmesg) AND the file
content was preserved.

`RS_PASSTHROUGH` is also a passing outcome : the attack window did
not produce a flip on the target file blocks, hash matches by
happenstance. Distinguishing it from `RS_RECOVERED` is essential
because `RS_PASSTHROUGH` does not prove FEC correctness ; only the
`RS_RECOVERED` count over multiple runs proves the FEC path is
functional.

### FS != beamfs (no FEC)

| mount_state | CAT_RC | hash_pre vs hash_post | verdict          |
|-------------|--------|-----------------------|------------------|
| FS_PANIC    | any    | any                   | `FS_PANIC`       |
| MOUNTED     | != 0   | any                   | `FS_PANIC`       |
| MOUNTED     | 0      | mismatch              | `CORRUPTED_DATA` |
| MOUNTED     | 0      | match                 | `RECOVERED`      |

Legacy filesystems do not have an RS-FEC distinction ; either the
kernel returned the bytes (RECOVERED if hash matches), returned EIO
or panicked (FS_PANIC), or returned wrong bytes silently
(CORRUPTED_DATA, the bad case for non-FEC filesystems under EM
attack).

## Tests

```
cd ~/git/beamfs-bench && cargo test --release
```

9 unit tests in `synthesis.rs` cover the verdict derivation matrix
(5 beamfs cases + 3 legacy cases + 1 field-extractor unit test).
