# beamfs-bench v2 -- USB topology plan

> Status: PLAN, companion to emufi v2 physical-model plan.
>
> Written: 2026-05-06.
> Companion plan: `~/git/emufi/Documentation/physical-model-v2-plan.md`
> (axes A, B, C + paliers 1, 3, 4, 5).
>
> This document covers axe D (USB topology) and palier 2 of the
> global v2 roadmap.

---

## 1. Objective

The empirical demonstration in emufi paper v2 requires
simultaneous testing of 5 filesystems (ext2, ext3, ext4, btrfs,
beamfs) under the physics-driven fault model. The compute01
hardware exposes 2 physical USB slots. The current beamfs-bench
v0.7.8 setup uses 5 USB sticks on compute01, one per FS, which
is no longer the target topology for v2.

The objective is to define a balanced partitioning of 5 FS
across 2 USB sticks, preserving:
- R21 injector isolation invariants
- R31 byte-identity guarantees where they still apply
- Worker.sh per-FS attack semantics
- Forensics granularity (per-FS counters and dmesg slices)

---

## 2. Constraints

Hardware:
- 2 USB sticks slotted on compute01.
- Both visible to the kernel as separate block devices
  (`/dev/sdaX`, `/dev/sdbX` typically, exact naming subject to
  enumeration order).
- No assumption on capacity beyond "enough for 2-3 FS each with
  test files of a few MiB".

Software:
- Each FS must be independently mountable, mkfs-able, and
  measurable for hashes pre/post attack.
- The injector targets one FS at a time (R21). Cross-FS
  contamination is forbidden.
- The image canonical (R31) byte-identity rule applies to the
  rootfs of the 4 VMs, NOT to the USB content (USB are targets,
  not runtime).

Workflow:
- `worker.sh setup` must build the partition tables and FS layouts
  reproducibly.
- `worker.sh attack` must select the right partition for the FS
  it is currently exercising.
- `worker.sh teardown` must leave the USB sticks in a known clean
  state.

---

## 3. Partition strategy options

### 3.1 Option A -- GPT partitioning

Each USB stick holds 2 or 3 GPT partitions, one FS per partition.

Repartition proposal:
- USB-1: ext2 + ext3 + beamfs (3 partitions)
- USB-2: ext4 + btrfs (2 partitions)

The asymmetry favours btrfs which is more sensitive to space
constraints than the ext family.

Pros:
- Each FS lives on a real block device path (`/dev/sda1`,
  `/dev/sda2`, etc.). The kprobe `target_dev` field already
  discriminates them via `MAJOR<<20 | MINOR`.
- No interposing layer (no LVM, no loop) between the kprobe and
  the FS.
- `parted` or `sgdisk` scripts give reproducible partition
  tables.

Cons:
- USB enumeration order is not guaranteed. Worker.sh must
  resolve sticks by serial number or by-id rather than by /dev
  path.

### 3.2 Option B -- LVM with 5 LVs over 2 PVs

Each USB stick is a single PV. A VG aggregates both. 5 LVs are
carved out, one per FS.

Pros:
- Fully balanced sizing (LVs can be sized independently of
  physical stick capacities).

Cons:
- LVM device-mapper layer interposes between the kprobe and the
  USB block device. R21 isolation reasoning becomes harder: a
  flip on `/dev/dm-N` may map to either physical stick depending
  on stripe layout.
- `target_dev` filter must point to the LV minor, not the USB
  minor. This means worker.sh per-FS arming becomes
  LV-minor-aware, which is fragile across reboots.

### 3.3 Option C -- Single partition + loop files

Each USB stick is one partition. 2 or 3 loop-back FS image files
live on each partition.

Pros:
- Simplest to set up.

Cons:
- Two layers of indirection: USB block -> partition -> loop ->
  FS. The kprobe target_dev hits the loop device, not the
  underlying USB. Loss of physical realism.
- This is exactly the topology that was retired earlier in the
  project history because it produced ambiguous forensics.

### 3.4 Recommendation

Option A. The GPT partitioning approach matches the existing R21
reasoning, requires no new isolation primitives, and the cost
(USB enumeration order resolution) is solved with `/dev/disk/by-id/`
paths which Linux exposes deterministically.

Final decision will be committed at the start of palier 2 after
verifying that a quick `parted` scripted run reproduces
identically across two reboot cycles.

---

## 4. Implications on existing primitives

### 4.1 R21 -- injector isolation

R21 currently relies on `target_dev` matching a single USB minor.
With option A, the same logic applies; only the minor numbers
change. Worker.sh must be updated to:
- Resolve USB-1 and USB-2 by `/dev/disk/by-id/`.
- For each FS, derive the correct partition path
  (`/dev/disk/by-id/usb-Vendor_Model_Serial-0:0-part1` etc).
- Pass the resolved partition's `MAJOR<<20 | MINOR` as
  `target_dev`.

No change required in emufi.ko.

### 4.2 R31 -- byte-identity

R31 originally required all 4 VM disks to be byte-identical
copies of the canonical .ext2 rootfs image. This rule is
unchanged. R31 does NOT extend to USB partition content: each
partition is a target, mkfs'd freshly per attack run, and its
state is per definition NOT byte-identical across runs.

This was already implicit in v1; it becomes explicit in v2.

### 4.3 Worker.sh setup phase

New responsibilities:
- Detect both USB sticks via by-id paths.
- Apply scripted GPT partition tables (idempotent: skip if
  partition table already matches expected layout).
- mkfs each partition with the appropriate FS family.
- Generate test files (file-A1.bin, file-B2.bin, etc.) per FS
  consistently.
- Compute and store the by-id-to-partition mapping in a
  per-run JSON for forensics.

New Rust module proposal: `usb-partitioner` inside beamfs-bench.
- Wraps `parted` (or `sgdisk`) calls with idempotency checks.
- Outputs a layout descriptor consumable by worker.sh (env vars
  or sidecar file).

### 4.4 Worker.sh attack phase

For each FS, the attack handler must:
- Select the correct partition (by-id resolution).
- Compute `target_dev` from that partition's dev_t.
- Run the attack as today (manual or via flip_queue once
  physics_driven mode lands in palier 3).

### 4.5 Forensics

The forensics tarball must include the by-id-to-partition mapping
so that post-mortem analysis can reconstruct which physical stick
was hit. This is one extra file per run, negligible overhead.

---

## 5. Compatibility with v1

The v1 paper uses the 5-USB topology. v1 reproducibility must be
preserved: the v0.7.8 worker.sh code path stays available for
historical R19 manifests. The new 2-USB topology is added as a
parallel mode, selected by a new env var (suggestion:
`USB_TOPOLOGY=v1` for legacy 5-stick, `USB_TOPOLOGY=v2` for
2-stick partitioned).

This avoids forking beamfs-bench. Both topologies coexist on
`main`.

---

## 6. Palier 2 deliverables

- This document, expanded in palier 2 with:
  - Concrete `parted` script for USB-1 and USB-2 partition
    creation.
  - Concrete by-id resolution code (Rust module signature +
    shell fallback).
  - Updated R21 isolation matrix accounting for partition
    semantics.
  - Migration plan for the v0.7.8 -> v0.8.0 worker.sh change.
- A signed commit on beamfs-bench `main`.

Effort: 3 to 5 days.

Gate: decision committed on partition layout (option A confirmed
or revised), R21 consequences accepted, worker.sh migration plan
reviewed.

---

## 7. Cross-references

- Plan companion: `~/git/emufi/Documentation/physical-model-v2-plan.md`
- Worker.sh current implementation: `~/git/beamfs-bench/src/worker.sh`
- HOW-TO global cycle: `~/git/beamfs/Documentation/HOW-TO-beamfs-globally.md`
  (section 3.6 phase F covers worker.sh patch + bump procedure).
- Last R19 v1 manifest: `~/git/yocto-beamfs/Documentation/runs/manifest-20260506T182029Z.json.asc`

---

## 8. Document maintenance

This plan is updated when palier 2 progresses or when an
implementation choice in palier 3 or 4 forces a topology
revision. Each update is a GPG-signed commit. Removed sections
must be moved to `Documentation/archive/` rather than deleted
outright.

End of plan.
