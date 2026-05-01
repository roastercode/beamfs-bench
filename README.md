# beamfs-bench

Unified Rust harness for beamfs resilience testing under RadFI live
fault injection. Replaces the legacy bash harness (`Tir-*.sh`,
`hpc-benchmark*.sh`, ~1176 lines) with a single Rust binary.

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
- multifs beamfs RECOVERED 3/3 (probs 1k, 100k, 1M)
- cluster 12/12 RECOVERED DIFFS=0 (4 nodes x 3 probs)
- 0 new BUG/Oops/WARN in dmesg

R19 forbids commit/push if any criterion fails.

## Installation (Gentoo)

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
- 5 USB sticks attached to master VM via virtio-blk passthrough
  (vdc=ext4, vdd=ext3, vde=btrfs, vdf=squashfs, vdg=beamfs target)

## Build from source (development)

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

GPL-2.0-only - same as the BEAMFS kernel module.

## Source

- Code   : roastercode/beamfs-bench (private)
- Issues : track via beamfs-devel TODO.md (private)
