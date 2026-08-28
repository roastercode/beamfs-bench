#!/bin/bash
# beamfs-bench multifs/analyse worker - embedded as include_str! in the Rust binary.
#
# Deployed to /tmp/beamfs-bench-worker.sh on the master VM (and on each compute
# for cluster scope) via scp, then invoked once per (action, ...) tuple.
#
# Actions (read-only, safe to call before any destructive op):
#   discover_devices          : list /dev/vd[c-z] with size + mountpoint + fstype
#   discover_cluster          : show /data state + injector loaded? + kernel version
#
# Actions (multifs scope, master only, single-FS targeted):
#   setup  <fs> <vd>          : format + populate one FS on /dev/<vd>
#   attack <fs> <vd> <prob>   : arm INJECTOR on <vd> + trigger I/O on dir-B/file-B2.bin
#   verify <fs> <vd>          : recompute hashes + classify verdict
#
# Actions (cluster scope, master + all 3 computes, beamfs on /data):
#   bootstrap_data            : insmod reed_solomon+beamfs, mkfs.beamfs /dev/vdb, mount /data
#   cluster_setup  <ts>       : create /data/beamfs-bench-<ts>/ test layout
#   cluster_attack <ts> <prob>: arm INJECTOR on /dev/vdb + I/O on /data/beamfs-bench-<ts>/
#   cluster_verify <ts>       : check integrity + cleanup
#
# Actions (metadata scope, compute01 only, RadFI deterministic on metadata blocks):
#   metadata_setup  <ts> <fs> <vd> : format <fs> on /dev/<vd>, populate, capture pre-state
#   metadata_inject <ts> <fs> <vd> <block> <prob> : arm INJECTOR target_block=<block>, trigger I/O
#   metadata_verify <ts> <fs> <vd> : remount + read + parse dmesg + emit observation
#
# Actions (crash scope, compute01 only, simulate power-loss mid-write):
#   crash_setup        <ts> <fs> <vd> : format <fs>, populate stable files, capture hash_pre
#   crash_start_writer <ts> <fs> <vd> : start dd loop in background; bench then virsh-destroys
#   crash_verify       <ts> <fs> <vd> : remount post-reboot, parse dmesg journal-replay, emit obs
#
# Actions (fsck scope, compute01 only, offline recovery):
#   fsck_check <ts> <fs> <vd> : run fsck.<fs> on /dev/<vd>, capture rc + output
#
# IMPORTANT (recadrage R12 / R13):
#   This worker NEVER discovers physical USB identity by itself. The Rust caller
#   parses `virsh dumpxml <vm>` on the host (spartian) to obtain the authoritative
#   vd[c-z] -> usb-by-id mapping, presents it to the user for confirmation, and
#   only THEN deploys + invokes this worker with already-validated (fs, vd) pairs.
#
#   Inside the guest VM, /dev/disk/by-id/ does NOT exist (virtio-blk strips serial),
#   so any worker-side "discovery" of physical identity would be a lie. The only
#   safe pre-action knowledge we have is "/dev/vdX is a 2G block device mounted on
#   /mnt/test-Y", which is what discover_devices returns.

set -u

# ============================================================
# Injector dispatch - radfi (legacy SEU) or emufi (MBU-capable)
# ============================================================
# beamfs-bench passes INJECTOR=radfi|emufi via the ssh remote_cmd
# environment. Default is radfi to preserve the historical R19
# baseline. The two injectors share 7 of 8 debugfs control entries
# verbatim (enabled, hook_blk, inject_on_read, probability,
# target_dev, target_block, call_count); only the flip-count key
# differs (radfi=flip_count, emufi=flip_count_total).
# Reference: EMUFI v1 paper Zenodo DOI 10.5281/zenodo.20041762
INJECTOR="${INJECTOR:-radfi}"
# v3 campaign : beamfs mkfs scheme parameterization
# scheme=inline (default, scheme=2) reproduces N=30 baseline behaviour
# scheme=inode-universal (scheme=5) enables paper v2 §VI.B B1/B2 latency benchmarks
BEAMFS_SCHEME="${BEAMFS_SCHEME:-inline}"
# BEAMFS_INODE_COUNT: total inodes requested at mkfs time. 0 (default)
# preserves the mkfs.beamfs built-in default of 256. Forwarded from
# the orchestrator via cluster.rs env whitelist.
BEAMFS_INODE_COUNT="${BEAMFS_INODE_COUNT:-0}"

# mkfs_beamfs_args -- echo the canonical mkfs.beamfs argument list.
# Centralises the -s / -O / -N flag composition so every invocation
# site stays in lockstep. -N is omitted when BEAMFS_INODE_COUNT=0,
# letting mkfs apply its built-in default (back-compat).
# BEAMFS_DATA_CSUM: when 1, format with --data-csum (format-v6 RO_COMPAT
# bit 4). Off by default so the canonical path stays byte-identical to v5.
BEAMFS_DATA_CSUM="${BEAMFS_DATA_CSUM:-0}"

mkfs_beamfs_args() {
    local args="-s $BEAMFS_SCHEME -O per_inode_rs"
    if [ "$BEAMFS_DATA_CSUM" = "1" ]; then
        args="$args --data-csum"
    fi
    if [ "$BEAMFS_INODE_COUNT" -gt 0 ] 2>/dev/null; then
        args="$args -N $BEAMFS_INODE_COUNT"
    fi
    echo "$args"
}
case "${INJECTOR}" in
    radfi) INJECTOR_DBG="/sys/kernel/debug/radfi" ; INJECTOR_KO="radfi.ko" ; FLIP_COUNT_KEY="flip_count" ;;
    emufi) INJECTOR_DBG="/sys/kernel/debug/emufi" ; INJECTOR_KO="emufi.ko" ; FLIP_COUNT_KEY="flip_count_total" ;;
    *) echo "ERR|unknown INJECTOR=${INJECTOR} (expected: radfi|emufi)" >&2 ; exit 2 ;;
esac

ACTION="${1:-}"
ARG2="${2:-}"
ARG3="${3:-}"
ARG4="${4:-}"
ARG5="${5:-}"
ARG6="${6:-}"

# ============================================================
# discover_devices : enumerate /dev/vd[c-z] visible in the guest
# ============================================================
# Output (stdout, one device per line):
#   <vd>|<size>|<mountpoint>|<fstype>
# Note : the by-id field is INTENTIONALLY OMITTED. virtio-blk does not expose
# the host SCSI/USB serial inside the guest, so any value here would be wrong.
# The Rust caller already has the authoritative mapping from virsh dumpxml.
if [ "$ACTION" = "discover_devices" ]; then
    for dev in /dev/vd?; do
        [ -b "$dev" ] || continue
        vd=$(basename "$dev")
        case "$vd" in
            vda|vdb) continue ;;
        esac
        size=$(lsblk -dn -o SIZE "$dev" 2>/dev/null | tr -d ' ')
        mnt=$(lsblk -dn -o MOUNTPOINT "$dev" 2>/dev/null | tr -d ' ')
        fstype=$(lsblk -dn -o FSTYPE "$dev" 2>/dev/null | tr -d ' ')
        echo "${vd}|${size}|${mnt}|${fstype}"
    done
    exit 0
fi

# ============================================================
# discover_cluster : per-node state, used by analyse to render the
# cluster topology table BEFORE any destructive cluster_* action.
# ============================================================
if [ "$ACTION" = "discover_cluster" ]; then
    echo "HOST=$(hostname)"
    echo "KERNEL=$(uname -r)"
    echo "DATA_MOUNT=$(mount | grep ' /data ' | head -1)"
    echo "DATA_USED=$(df -h /data 2>/dev/null | tail -1 | awk '{print $3"/"$2}')"
    echo "INJECTOR_NAME=${INJECTOR}"
    echo "INJECTOR_LOADED=$(lsmod | grep -q "^${INJECTOR}" && echo yes || echo no)"
    echo "INJECTOR_KO_PRESENT=$([ -f /lib/modules/$(uname -r)/updates/${INJECTOR_KO} ] && echo yes || echo no)"
    echo "RADFI_LOADED=$(lsmod | grep -q '^radfi' && echo yes || echo no)"
    echo "BEAMFS_LOADED=$(grep -qw beamfs /proc/filesystems && echo yes || echo no)"
    echo "RADFI_KO_PRESENT=$([ -f /lib/modules/$(uname -r)/updates/radfi.ko ] && echo yes || echo no)"
    echo "EMUFI_LOADED=$(lsmod | grep -q '^emufi' && echo yes || echo no)"
    echo "EMUFI_KO_PRESENT=$([ -f /lib/modules/$(uname -r)/updates/emufi.ko ] && echo yes || echo no)"
    echo "PERF_AVAILABLE=$(command -v perf >/dev/null 2>&1 && echo yes || echo no)"
    echo "FTRACE_DEBUGFS=$(sudo test -d /sys/kernel/debug/tracing && echo yes || echo no)"
    exit 0
fi

# ============================================================
# Helper : ensure ${INJECTOR_KO} + beamfs.ko + (btrfs.ko if needed) loaded.
# IMPORTANT: enforces strict injector isolation. Only the requested ${INJECTOR}
# is loaded; any other injector (radfi when emufi is requested, or vice versa)
# is rmmod'd first to prevent superposition of fault injection hooks.
# This guarantees comparative analyses (radfi vs emufi) measure each injector
# in isolation, not their union.
# ============================================================
ensure_modules() {
    local fs="${1:-}"
    # --- Strict isolation: rmmod any OTHER injector before loading ours ---
    case "$INJECTOR" in
        radfi)
            if lsmod | grep -q '^emufi'; then
                sudo /sbin/rmmod emufi 2>/dev/null || true
            fi
            ;;
        emufi)
            if lsmod | grep -q '^radfi'; then
                sudo /sbin/rmmod radfi 2>/dev/null || true
            fi
            ;;
    esac
    sudo depmod -a 2>/dev/null
    if [ "$fs" = "btrfs" ]; then
        sudo modprobe btrfs 2>/dev/null || true
    fi
    # reed_solomon is built-in (CONFIG_REED_SOLOMON=y in BEAMFS-arm64.cfg).
    # Detect by exported symbol instead of lsmod.
    if ! sudo grep -qE '^[0-9a-f]+ [Tt] encode_rs8$' /proc/kallsyms; then
        sudo modprobe reed_solomon 2>/dev/null || true
    fi
    # beamfs is built-in (CONFIG_BEAMFS_FS=y) since commit eddf561.
    # No module to load; presence is verified via /proc/filesystems.
    if ! grep -qw beamfs /proc/filesystems; then
        echo "WORKER|HOST=$(hostname)|ERROR=beamfs not in /proc/filesystems (built-in missing)" >&2
    fi
    if ! lsmod | grep -q "^${INJECTOR}"; then
        sudo /sbin/insmod /lib/modules/$(uname -r)/updates/${INJECTOR_KO} 2>/dev/null || true
    fi
}

# ============================================================
# multifs scope : setup / attack / verify (master-only, USB targets)
# Args: $1=action $2=fs $3=vd $4=prob
# ============================================================

# Phase A.2 helper: extract the physical block offsets of a target file via
# filefrag, to detect CoW relocation between pre-attack and post-attack
# states. Output format: comma-separated u64 list, or 'na' if filefrag is
# unsupported on the FS, or 'filefrag_failed' on tool error.
# Phase B.1: generalized read-only FS detection helper. Used by
# filefrag_phys() and the setup/attack/verify branches to handle
# squashfs, erofs (and any future RO FS) uniformly.
is_readonly_fs() {
    case "$1" in
        squashfs|erofs) return 0 ;;
        *) return 1 ;;
    esac
}

# Phase B.1: probe whether mkfs.<fs> tool AND the kernel module
# are available. Returns 0 if usable, 1 if either is missing.
# Used by setup branches to gracefully skip unsupported FS.
fs_is_supported() {
    local fs="$1"
    local mkfs_tool=""
    case "$fs" in
        ext2)     mkfs_tool="mkfs.ext2" ;;
        ext3)     mkfs_tool="mkfs.ext3" ;;
        ext4)     mkfs_tool="mkfs.ext4" ;;
        btrfs)    mkfs_tool="mkfs.btrfs" ;;
        xfs)      mkfs_tool="mkfs.xfs" ;;
        f2fs)     mkfs_tool="mkfs.f2fs" ;;
        jfs)      mkfs_tool="mkfs.jfs" ;;
        bcachefs) mkfs_tool="mkfs.bcachefs" ;;
        ntfs3)    mkfs_tool="mkfs.ntfs" ;;
        exfat)    mkfs_tool="mkfs.exfat" ;;
        vfat)     mkfs_tool="mkfs.vfat" ;;
        hfsplus)  mkfs_tool="mkfs.hfsplus" ;;
        squashfs) mkfs_tool="mksquashfs" ;;
        erofs)    mkfs_tool="mkfs.erofs" ;;
        beamfs)   mkfs_tool="mkfs.beamfs" ;;
        zfs)      mkfs_tool="zpool" ;;
        *)        return 1 ;;
    esac
    if ! command -v "$mkfs_tool" >/dev/null 2>&1; then
        return 1
    fi
    # Module load test (non-destructive). vfat <-> fat module aliasing
    # handled implicitly by modprobe -n.
    case "$fs" in
        ntfs3)    sudo modprobe -n -v ntfs3    >/dev/null 2>&1 || return 1 ;;
        exfat)    sudo modprobe -n -v exfat    >/dev/null 2>&1 || return 1 ;;
        xfs)      sudo modprobe -n -v xfs      >/dev/null 2>&1 || return 1 ;;
        f2fs)     sudo modprobe -n -v f2fs     >/dev/null 2>&1 || return 1 ;;
        jfs)      sudo modprobe -n -v jfs      >/dev/null 2>&1 || return 1 ;;
        bcachefs) sudo modprobe -n -v bcachefs >/dev/null 2>&1 || return 1 ;;
        hfsplus)  sudo modprobe -n -v hfsplus  >/dev/null 2>&1 || return 1 ;;
        erofs)    sudo modprobe -n -v erofs    >/dev/null 2>&1 || return 1 ;;
        zfs)      sudo modprobe -n -v zfs      >/dev/null 2>&1 || return 1 ;;
    esac
    return 0
}

filefrag_phys() {
    local fs="$1" tgt="$2"
    # Phase C-fix: skip filefrag for zfs (ZFS pool block allocation
    # doesn't expose physical extents via filefrag in a way that maps
    # back to a single underlying device).
    # S2.4: beamfs supports FIEMAP since v0.1.1 (commit c98e851 in
    # roastercode/beamfs-devel devel). zfs and read-only FS are still
    # skipped (zfs doesn't map filefrag back to a single underlying
    # device; squashfs/erofs are offline images without dynamic mapping).
    if [ "$fs" = "zfs" ] || is_readonly_fs "$fs"; then
        echo "na"
        return 0
    fi
    if ! command -v filefrag >/dev/null 2>&1; then
        echo "na"
        return 0
    fi
    if [ ! -e "$tgt" ]; then
        echo "missing"
        return 0
    fi
    local out
    out=$(sudo filefrag -v -b4096 "$tgt" 2>/dev/null \
        | awk '/^ +[0-9]+:/ {gsub(/[.:]/, "", $4); print $4}' \
        | paste -sd, 2>/dev/null)
    if [ -z "$out" ]; then
        echo "filefrag_failed"
    else
        echo "$out"
    fi
}

case "$ACTION" in

setup)
    FS="$ARG2"
    VD="$ARG3"
    DEV="/dev/$VD"
    MNT="/mnt/test-$FS"

    ensure_modules "$FS"

    # Phase B.1: gracefully skip unsupported FS. The worker emits a
    # SKIP record that synthesis.rs treats as a no-op cell rather
    # than a hard error.
    if ! fs_is_supported "$FS"; then
        echo "FS=$FS|VD=$VD|MNT=$MNT|TARGET_FILE=na|TARGET_BLOCK=0|SETUP=SKIP|reason=tool_or_module_missing"
        exit 0
    fi

    # pre-N100 fix: device-level cleanup to prevent residual mounts
    # from polluting the new run. The previous worker.sh (pre-S3.x) only
    # umounted the current mountpoint $MNT, which fails to detect when
    # $DEV is still mounted under a *different* mountpoint left by a
    # previous run with a different FS_LIST mapping (e.g. Batch A xfs on
    # /mnt/test-xfs, then Batch B vfat expecting /dev/vdf clean).
    # findmnt --source returns ALL mountpoints currently using $DEV;
    # we umount each, then wipefs to scrub FS magic numbers so the
    # subsequent mkfs operates on a virgin device.
    for resmnt in $(findmnt --source "$DEV" --noheadings --output TARGET 2>/dev/null); do
        sudo umount -f "$resmnt" 2>/dev/null || sudo umount -l "$resmnt" 2>/dev/null || true
    done
    sudo umount $MNT 2>/dev/null || true
    sudo wipefs -a "$DEV" >/dev/null 2>&1 || true
    sudo rm -rf $MNT
    sudo mkdir -p $MNT

    case "$FS" in
        ext2)     sudo mkfs.ext2 -F -q $DEV ;;
        ext3)     sudo mkfs.ext3 -F -q $DEV ;;
        ext4)     sudo mkfs.ext4 -F -q $DEV ;;
        btrfs)    sudo mkfs.btrfs -f $DEV >/dev/null ;;
        xfs)      sudo mkfs.xfs  -f -q $DEV >/dev/null ;;
        f2fs)     sudo mkfs.f2fs -f -q $DEV >/dev/null ;;
        jfs)      sudo mkfs.jfs  -q $DEV >/dev/null ;;
        bcachefs) sudo mkfs.bcachefs -f $DEV >/dev/null ;;
        ntfs3)    sudo mkfs.ntfs -F -Q $DEV >/dev/null ;;
        exfat)    sudo mkfs.exfat $DEV >/dev/null ;;
        vfat)     sudo mkfs.vfat -F 32 $DEV >/dev/null ;;
        hfsplus)  sudo mkfs.hfsplus $DEV >/dev/null ;;
        squashfs|erofs)
            ;;  # read-only FS handled below via offline image build
        beamfs)   sudo mkfs.beamfs $(mkfs_beamfs_args) $DEV >/dev/null ;;
        zfs)
            # ZFS uses zpool, not mkfs. The pool name embeds VD to ensure
            # uniqueness across compute nodes. -f forces creation even if
            # the device has a previous label. -m sets the mount point
            # explicitly to override ZFS auto-mount default.
            POOL_NAME="bench_zfs_${VD}"
            sudo zpool destroy "$POOL_NAME" 2>/dev/null || true
            sudo zpool create -f -m "$MNT" "$POOL_NAME" "$DEV"
            ;;
        *)        echo "ERROR: unknown FS $FS" >&2; exit 1 ;;
    esac

    if ! is_readonly_fs "$FS"; then
        # ZFS auto-mounts via zpool create -m ; skip explicit mount.
        if [ "$FS" != "zfs" ]; then
            sudo mount -t $FS $DEV $MNT
        fi
        for letter in A B C; do
            sudo mkdir -p $MNT/dir-$letter
            for n in 1 2 3; do
                sudo bash -c "head -c 262144 /dev/urandom > $MNT/dir-$letter/file-${letter}${n}.bin"
            done
            sudo bash -c "cd $MNT/dir-$letter && sha256sum file-${letter}1.bin file-${letter}2.bin file-${letter}3.bin > HASHES.sha256"
        done
        sudo sync

        TARGET_FILE=$MNT/dir-B/file-B2.bin
        # S3.1: compute TARGET_BLOCK plus the full physical-block range of
        # the target file. The single-extent TARGET_BLOCK is kept for
        # backward compatibility (legacy structure-aware path).
        # The new TARGET_BLOCK_RANGE_{START,END} pair, in sectors (512 B),
        # is consumed by emufi v0.3.4+ to focus injection on the file's
        # extent footprint instead of the whole device. Required for
        # file-level RS-FEC functional correctness measurement (Theorem IV.1).
        TARGET_BLOCK=0
        TARGET_BLOCK_RANGE_START=0
        TARGET_BLOCK_RANGE_END=0
        if command -v filefrag >/dev/null 2>&1; then
            # v0.8.2 (publication-grade) : -v required, sans lui filefrag
            # n'imprime PAS la ligne "0: 0.. 63: 1081344.." que awk match.
            # Sans -v on extrait '' qui devient TARGET_BLOCK=0, et le filtre
            # blk_filter_match (target_struct_block_no=0) rejette 99% des bios
            # vers skipped_filter, faussant la mesure de dose-réponse.
            FRAG_OUT=$(sudo filefrag -v -b4096 "$TARGET_FILE" 2>/dev/null)
            TARGET_BLOCK=$(echo "$FRAG_OUT" | awk '/^ +0:/ {gsub(/[.:]/, "", $4); print $4; exit}')
            # S3.1: extract ALL physical block numbers, find min and max,
            # convert to sectors (×8), apply exclusive upper bound (+1 then ×8).
            # v0.12.2 : read BOTH physical_offset columns ($4=start, $5=end).
            # Reading only $4 gave RMIN==RMAX on unfragmented files (ext4,
            # btrfs: 1 extent), yielding an 8-sector range = 1 block out of 64,
            # so injection almost never hit them while fragmented FS (beamfs,
            # ext3) got full coverage. That biased every head-to-head run.
            EXT_STARTS=$(echo "$FRAG_OUT" | awk '/^ +[0-9]+:/ {gsub(/[.:]/, "", $4); print $4}')
            EXT_ENDS=$(echo "$FRAG_OUT" | awk '/^ +[0-9]+:/ {gsub(/[.:]/, "", $5); print $5}')
            EXTENTS="$EXT_STARTS"
            if [ -n "$EXTENTS" ]; then
                RMIN=$(echo "$EXT_STARTS" | sort -n | head -1)
                RMAX=$(echo "$EXT_ENDS" | sort -n | tail -1)
                TARGET_BLOCK_RANGE_START=$((RMIN * 8))
                TARGET_BLOCK_RANGE_END=$(((RMAX + 1) * 8))
            fi
            # v0.12.6 : per-extent list (emufi 0.7.0+). The min/max interval
            # above spans everything between the first and last block, which
            # on a fragmented layout is mostly foreign: ext3 placed 16 blocks
            # near 3277377 and 48 near 18160, giving an interval 10000x the
            # file size, and the injections never reached the data. Emit each
            # extent as start:end in sectors so the injector targets the
            # file's own blocks.
            TARGET_RANGES=$(echo "$FRAG_OUT" | awk '/^ +[0-9]+:/ {
                s=$4; e=$5; gsub(/[.:]/, "", s); gsub(/[.:]/, "", e);
                printf "%s%d:%d", (NR_OUT++ ? "," : ""), s*8, (e+1)*8
            }')
        fi
        [ -z "$TARGET_BLOCK" ] && TARGET_BLOCK=0

        # Reachability probe (v0.12.3). A CALL_DELTA of 0 is ambiguous on its
        # own: the filesystem may have resisted, or may simply never have been
        # attacked. Measured 2026-08-14: erofs and vfat served the 256 KiB
        # target entirely from cache after drop_caches + umount/mount, emitting
        # zero bios on their own device (all traffic was on 254,0 = rootfs from
        # cat itself), so no injection was possible regardless of targeting.
        # Count bios issued on THIS filesystem device during a cold read and
        # publish the result, so synthesis can separate "resisted" from
        # "never exercised". Requires tracing_on=1: it defaults to 0 and a
        # disabled tracer silently reports zero events.
        REACHABLE=unknown
        REACH_BIOS=0
        TRACE_DIR=/sys/kernel/debug/tracing
        if sudo test -e ${TRACE_DIR}/events/block/block_bio_queue/enable; then
            DEV_MAJ_R=$((0x$(stat -c '%t' /dev/$VD 2>/dev/null)))
            DEV_MIN_R=$((0x$(stat -c '%T' /dev/$VD 2>/dev/null)))
            sudo sync
            echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
            sudo umount $MNT 2>/dev/null
            sudo mount /dev/$VD $MNT 2>/dev/null
            sudo bash -c "echo 1 > ${TRACE_DIR}/tracing_on"
            sudo bash -c "echo > ${TRACE_DIR}/trace"
            sudo bash -c "echo 1 > ${TRACE_DIR}/events/block/block_bio_queue/enable"
            sudo cat "$TARGET_FILE" > /dev/null 2>&1
            sudo bash -c "echo 0 > ${TRACE_DIR}/events/block/block_bio_queue/enable"
            REACH_BIOS=$(sudo grep -v '^#' ${TRACE_DIR}/trace 2>/dev/null \
                         | grep -c "${DEV_MAJ_R},${DEV_MIN_R} " || true)
            [ -z "$REACH_BIOS" ] && REACH_BIOS=0
            if [ "$REACH_BIOS" -gt 0 ] 2>/dev/null; then
                REACHABLE=yes
            else
                REACHABLE=no
            fi
        fi
        echo "FS=$FS|VD=$VD|MNT=$MNT|TARGET_FILE=$TARGET_FILE|TARGET_BLOCK=$TARGET_BLOCK|TARGET_BLOCK_RANGE_START=$TARGET_BLOCK_RANGE_START|TARGET_BLOCK_RANGE_END=$TARGET_BLOCK_RANGE_END|REACHABLE=$REACHABLE|REACH_BIOS=$REACH_BIOS|TARGET_RANGES=$TARGET_RANGES"
        sudo find $MNT -type f -exec sha256sum {} \; | sort > /tmp/pre-attack-$FS.txt
    else
        # Phase B.1: read-only FS branch covers squashfs and erofs uniformly.
        # Build offline image with the standard 3-dirs x 3-files layout,
        # write it to the target device, mount RO.
        TMPSRC=/tmp/${FS}-src-$$
        sudo rm -rf $TMPSRC
        sudo mkdir -p $TMPSRC
        for letter in A B C; do
            sudo mkdir -p $TMPSRC/dir-$letter
            for n in 1 2 3; do
                sudo bash -c "head -c 262144 /dev/urandom > $TMPSRC/dir-$letter/file-${letter}${n}.bin"
            done
            sudo bash -c "cd $TMPSRC/dir-$letter && sha256sum file-${letter}1.bin file-${letter}2.bin file-${letter}3.bin > HASHES.sha256"
        done
        case "$FS" in
            squashfs)
                sudo mksquashfs $TMPSRC /tmp/roimg-$$.img -noappend -comp xz >/dev/null 2>&1
                ;;
            erofs)
                sudo mkfs.erofs /tmp/roimg-$$.img $TMPSRC >/dev/null 2>&1
                ;;
            *)
                echo "ERROR: unsupported read-only FS $FS in setup" >&2
                sudo rm -rf $TMPSRC
                exit 1
                ;;
        esac
        sudo dd if=/tmp/roimg-$$.img of=$DEV bs=1M conv=notrunc status=none
        sudo rm -rf $TMPSRC /tmp/roimg-$$.img
        sudo mount -t $FS -o ro $DEV $MNT

        TARGET_FILE=$MNT/dir-B/file-B2.bin
        echo "FS=$FS|VD=$VD|MNT=$MNT|TARGET_FILE=$TARGET_FILE|TARGET_BLOCK=0"
        sudo find $MNT -type f -exec sha256sum {} \; | sort > /tmp/pre-attack-$FS.txt
    fi
    ;;

attack)
    FS="$ARG2"
    VD="$ARG3"
    PROB="$ARG4"
    DEV="/dev/$VD"
    MNT="/mnt/test-$FS"

    DEV_MAJ=$((0x$(stat -c '%t' $DEV)))
    DEV_MIN=$((0x$(stat -c '%T' $DEV)))
    DEV_NUM=$(( (DEV_MAJ << 20) | DEV_MIN ))

    echo 0 | sudo tee ${INJECTOR_DBG}/enabled  >/dev/null
    echo 0 | sudo tee ${INJECTOR_DBG}/hook_blk >/dev/null

    CALL_B=$(sudo cat ${INJECTOR_DBG}/call_count)
    FLIP_B=$(sudo cat ${INJECTOR_DBG}/${FLIP_COUNT_KEY})

    echo $DEV_NUM | sudo tee ${INJECTOR_DBG}/target_dev   >/dev/null
    echo 0        | sudo tee ${INJECTOR_DBG}/target_block >/dev/null
    # INJECT_SCOPE selects the spatial model of the attack.
    #
    #   targeted (default) -- flips confined to the blocks of the file whose
    #     integrity is then verified. Answers "does this file survive", and
    #     is the right shape for directed tests.
    #
    #   uniform -- no block filter at all: every bio on the device is a
    #     candidate. This is the physically faithful model. A particle
    #     strike, a mechanical shock or an EM transient does not know where
    #     the inode table ends and the data begins; it hits whatever silicon
    #     is in its path. Confining flips to one file's extents both flatters
    #     a filesystem whose FEC covers exactly those blocks, and makes
    #     cross-filesystem comparison meaningless, since each filesystem's
    #     target range has a different size (512 sectors for btrfs against
    #     ~14 GiB for ext3 in the 2026-08-28 campaign, so ext4 and btrfs saw
    #     1-2 filtered bios while beamfs and ext3 saw hundreds).
    #
    # The three targeting mechanisms must be cleared explicitly: the module
    # keeps its previous values between runs, so leaving the env vars unset
    # is not enough to widen the scope.
    if [ "${INJECT_SCOPE:-targeted}" = "uniform" ]; then
        if sudo test -e ${INJECTOR_DBG}/target_block_range_start; then
            echo 0 | sudo tee ${INJECTOR_DBG}/target_block_range_start >/dev/null
            echo 0 | sudo tee ${INJECTOR_DBG}/target_block_range_end   >/dev/null
        fi
        if sudo test -e ${INJECTOR_DBG}/target_ranges; then
            printf '' | sudo tee ${INJECTOR_DBG}/target_ranges >/dev/null
        fi
    else
        # S3.1: file-precise targeting via target_block_range (emufi v0.3.4+).
        # Both env vars must be set (>0 and end>start) to activate. Falls back
        # silently to broadcast (target_block=0) on older modules without these
        # debugfs entries.
        if [ -n "${TARGET_BLOCK_RANGE_START:-}" ] && [ -n "${TARGET_BLOCK_RANGE_END:-}" ] \
           && [ "${TARGET_BLOCK_RANGE_END}" -gt "${TARGET_BLOCK_RANGE_START:-0}" ] \
           && sudo test -e ${INJECTOR_DBG}/target_block_range_start; then
            echo ${TARGET_BLOCK_RANGE_START} | sudo tee ${INJECTOR_DBG}/target_block_range_start >/dev/null
            echo ${TARGET_BLOCK_RANGE_END}   | sudo tee ${INJECTOR_DBG}/target_block_range_end   >/dev/null
        fi
        # v0.12.6 : per-extent list takes precedence over the interval above.
        if [ -n "${TARGET_RANGES:-}" ] && sudo test -e ${INJECTOR_DBG}/target_ranges; then
            printf '%s' "${TARGET_RANGES}" | sudo tee ${INJECTOR_DBG}/target_ranges >/dev/null
        fi
    fi
    echo $PROB    | sudo tee ${INJECTOR_DBG}/probability  >/dev/null
    # v0.7.6 : push inject_on_read=1 unconditionally. emufi v0.3.0
    # defaulted to false (vs radfi true), making read-driven attacks
    # inert. emufi v0.3.1 aligns default to true ; this push remains
    # as defense-in-depth and explicit harness-side contract.
    echo 1        | sudo tee ${INJECTOR_DBG}/inject_on_read >/dev/null
    # v0.1.4 : flip_width MBU burst width. Default 1 (legacy single-bit SEU).
    # Honour env var FLIP_WIDTH if set by Rust caller. If debugfs entry
    # does not exist (radfi <0.1.4 / emufi <0.2.x), the tee silently fails
    # which is fine -- module ignores it and behaves single-bit.
    FLIP_WIDTH_VAL=${FLIP_WIDTH:-1}
    if sudo test -e ${INJECTOR_DBG}/flip_width; then
        echo $FLIP_WIDTH_VAL | sudo tee ${INJECTOR_DBG}/flip_width >/dev/null
    fi
    # v0.12.5 : dose control (emufi 0.6.0+). Posing the same MAX_FLIPS for
    # every filesystem makes the campaign a controlled experiment: without
    # it the injector fires once per filtered bio, so a filesystem issuing
    # many small bios (beamfs: 72 for a 256 KiB read) receives far more
    # flips than one issuing a single merged readahead (ext4: 4).
    if [ -n "${MAX_FLIPS:-}" ] && sudo test -e ${INJECTOR_DBG}/max_flips; then
        echo ${MAX_FLIPS} | sudo tee ${INJECTOR_DBG}/max_flips >/dev/null
    fi
    # v0.2.1 : LET_CLASS high-level intensity (overrides PROB/FLIP_WIDTH).
    # 0=LOW 1=MEDIUM 2=HIGH 3=EXTREME (Baumann 2005 / JEDEC JEP89 calibrated).
    if [ -n "${LET_CLASS:-}" ] && sudo test -e ${INJECTOR_DBG}/let_class; then
        echo $LET_CLASS | sudo tee ${INJECTOR_DBG}/let_class >/dev/null
    fi

    # v0.7.4 : emufi 0.3.0 surgical attack envvars.
    # All optional, all guarded by [ -e ] so radfi (no entry) is no-op.
    # rv4-3 BURST-IN-CODEWORD :
    if [ -n "${FLIP_LOCALITY:-}" ] && sudo test -e ${INJECTOR_DBG}/flip_locality; then
        echo ${FLIP_LOCALITY} | sudo tee ${INJECTOR_DBG}/flip_locality >/dev/null
    fi
    if [ -n "${BURST_SYMBOLS:-}" ] && sudo test -e ${INJECTOR_DBG}/burst_symbols; then
        echo ${BURST_SYMBOLS} | sudo tee ${INJECTOR_DBG}/burst_symbols >/dev/null
    fi
    # rv4-4 STRUCTURE-AWARE :
    # Auto-fill TARGET_STRUCT_BLOCK_NO from already-computed ${TARGET_BLOCK}
    # (line 194 filefrag) when TARGET_STRUCT=5 (DATA_BLOCK) and var is unset.
    if [ -n "${TARGET_STRUCT:-}" ] && sudo test -e ${INJECTOR_DBG}/target_struct; then
        echo ${TARGET_STRUCT} | sudo tee ${INJECTOR_DBG}/target_struct >/dev/null
        if [ "${TARGET_STRUCT}" = "5" ] && [ -z "${TARGET_STRUCT_BLOCK_NO:-}" ] \
               && [ -n "${TARGET_BLOCK:-}" ] && [ "${TARGET_BLOCK}" != "0" ]; then
            TARGET_STRUCT_BLOCK_NO=${TARGET_BLOCK}
            echo "INFO|reuse TARGET_BLOCK=${TARGET_BLOCK} as TARGET_STRUCT_BLOCK_NO" >&2
        fi
    fi
    if [ -n "${TARGET_STRUCT_BLOCK_NO:-}" ] && sudo test -e ${INJECTOR_DBG}/target_struct_block_no; then
        echo ${TARGET_STRUCT_BLOCK_NO} | sudo tee ${INJECTOR_DBG}/target_struct_block_no >/dev/null
    fi
    # rv4-1 SEFI :
    if [ -n "${SEFI_PROBABILITY:-}" ] && sudo test -e ${INJECTOR_DBG}/sefi_probability; then
        echo ${SEFI_PROBABILITY} | sudo tee ${INJECTOR_DBG}/sefi_probability >/dev/null
    fi
    if [ -n "${SEFI_WINDOW_MS:-}" ] && sudo test -e ${INJECTOR_DBG}/sefi_window_ms; then
        echo ${SEFI_WINDOW_MS} | sudo tee ${INJECTOR_DBG}/sefi_window_ms >/dev/null
    fi

    # v0.8.0 : full emufi 0.3.2 debugfs surface. All optional, cumulative
    # simultaneous. Each push guarded by [ -n VAR ] && sudo test -e entry,
    # so radfi (lacks most entries) is no-op and unset host vars are no-op.
    # Ordering does not matter (none of these depend on each other) but
    # placement BEFORE hook_blk/enabled arming is critical so values are
    # in place when injection starts.
    # rv4-4 STRUCTURE-AWARE byte offset (complements TARGET_STRUCT_BLOCK_NO):
    if [ -n "${TARGET_STRUCT_OFFSET:-}" ] && sudo test -e ${INJECTOR_DBG}/target_struct_offset; then
        echo ${TARGET_STRUCT_OFFSET} | sudo tee ${INJECTOR_DBG}/target_struct_offset >/dev/null
    fi
    # FS-aware inode targeting:
    if [ -n "${TARGET_INODE:-}" ] && sudo test -e ${INJECTOR_DBG}/target_inode; then
        echo ${TARGET_INODE} | sudo tee ${INJECTOR_DBG}/target_inode >/dev/null
    fi
    # FS-level hook (in addition to blk-level which is always armed):
    if [ -n "${HOOK_FS:-}" ] && sudo test -e ${INJECTOR_DBG}/hook_fs; then
        echo ${HOOK_FS} | sudo tee ${INJECTOR_DBG}/hook_fs >/dev/null
    fi
    # Multi-segment burst (one event spans multiple non-contiguous segments):
    if [ -n "${MULTI_SEGMENT:-}" ] && sudo test -e ${INJECTOR_DBG}/multi_segment; then
        echo ${MULTI_SEGMENT} | sudo tee ${INJECTOR_DBG}/multi_segment >/dev/null
    fi
    # Multi-chip realism (event distributed over CHIP_COUNT chips):
    if [ -n "${MULTI_CHIP:-}" ] && sudo test -e ${INJECTOR_DBG}/multi_chip; then
        echo ${MULTI_CHIP} | sudo tee ${INJECTOR_DBG}/multi_chip >/dev/null
    fi
    if [ -n "${CHIP_COUNT:-}" ] && sudo test -e ${INJECTOR_DBG}/chip_count; then
        echo ${CHIP_COUNT} | sudo tee ${INJECTOR_DBG}/chip_count >/dev/null
    fi
    # MBU width sampling mode (overrides FLIP_WIDTH semantic):
    if [ -n "${WIDTH_MODE:-}" ] && sudo test -e ${INJECTOR_DBG}/width_mode; then
        echo ${WIDTH_MODE} | sudo tee ${INJECTOR_DBG}/width_mode >/dev/null
    fi
    # Stride between flips in a burst (controls intra-burst spacing):
    if [ -n "${FLIP_STRIDE_BITS:-}" ] && sudo test -e ${INJECTOR_DBG}/flip_stride_bits; then
        echo ${FLIP_STRIDE_BITS} | sudo tee ${INJECTOR_DBG}/flip_stride_bits >/dev/null
    fi
    # RS-aware codeword targeting (FEC budget exploration):
    if [ -n "${CODEWORD_SIZE_BYTES:-}" ] && sudo test -e ${INJECTOR_DBG}/codeword_size_bytes; then
        echo ${CODEWORD_SIZE_BYTES} | sudo tee ${INJECTOR_DBG}/codeword_size_bytes >/dev/null
    fi
    if [ -n "${CODEWORD_ALIGN_BYTES:-}" ] && sudo test -e ${INJECTOR_DBG}/codeword_align_bytes; then
        echo ${CODEWORD_ALIGN_BYTES} | sudo tee ${INJECTOR_DBG}/codeword_align_bytes >/dev/null
    fi
    # Reseed PRNG (write-only command, useful for campaign reproducibility):
    if [ -n "${RESEED:-}" ] && sudo test -e ${INJECTOR_DBG}/reseed; then
        echo ${RESEED} | sudo tee ${INJECTOR_DBG}/reseed >/dev/null
    fi

    echo 1        | sudo tee ${INJECTOR_DBG}/hook_blk     >/dev/null
    echo 1        | sudo tee ${INJECTOR_DBG}/enabled      >/dev/null

    # Phase A.5 : SB-targeted I/O burst for RS saturation campaign.
    # When TARGET_STRUCT=1 (SUPERBLOCK) and SB_READ_LOOPS is set,
    # generate N raw direct-I/O reads on block 0 during the
    # attack-armed window. Each read produces one bio matching the
    # kprobe filter, applying one flip. Without this, a single mount
    # + cat generates only 1-3 SB reads, insufficient to saturate
    # the RS journal (need T+1=5 flips per 40-byte codeword).
    # With N=500 + probability=1000000 ppm, density ~13 flips/sub-block.
    # Empirical validation: bloc R7 -- 50 reads -> 50 flips (100% yield).
    if [ "${TARGET_STRUCT:-0}" = "1" ] && [ -n "${SB_READ_LOOPS:-}" ]; then
        echo "INFO|A.5 SB burst: ${SB_READ_LOOPS} direct reads on $DEV block 0" >&2
        for sb_i in $(seq 1 ${SB_READ_LOOPS}); do
            sudo dd if=$DEV bs=4k count=1 skip=0 iflag=direct of=/dev/null 2>/dev/null
        done
    fi

    # TARGET_REL must be set before the workload dispatch below: the
    # write-active branch builds TARGET_FULLPATH from it, but the
    # original assignment sat 28 lines further down, so the variable was
    # empty there. TARGET_FULLPATH then resolved to "$MNT/" -- a
    # directory, which passes [ -e ] -- and fio was handed a directory as
    # --filename. The whole worker branch failed silently, emitting an
    # empty record for every writable FS while squashfs (skipped by
    # is_readonly_fs) reported normally. Latent since write-active was
    # written; first exercised by the 2026-08-28 multi-FS campaign.
    TARGET_REL="dir-B/file-B2.bin"

    # Phase A.3 -- workload mode dispatch.
    # Default "static" matches legacy behavior (FS quiescent during attack).
    # "write-active" launches a background fio randwrite on TARGET_FILE for
    # WORKLOAD_DURATION seconds, exercising the write path under live
    # injection. CoW filesystems will allocate fresh extents on each write,
    # exposing the relocation mechanism to the FRAG_RELOCATED measurement.
    WORKLOAD_MODE_VAL=${WORKLOAD_MODE:-static}
    WORKLOAD_DURATION_VAL=${WORKLOAD_DURATION:-15}
    WORKLOAD_PID=""
    if [ "$WORKLOAD_MODE_VAL" = "write-active" ] && ! is_readonly_fs "$FS"; then
        # --time_based + --runtime bound the write loop, so the background
        # job self-terminates at the end of the attack window.
        # Write to a scratch file, NOT to the attack target. The integrity
        # verdict compares HASH_PRE (frozen in HASHES.sha256 at setup)
        # against HASH_POST; writing randwrite over the target would make
        # them differ by construction, so every FS would look corrupted and
        # the measurement would mean nothing. HASHES.sha256 lists exactly
        # file-{A,B,C}{1,2,3}.bin, so a file under any other name is outside
        # the 12 verified files and safe to churn. What matters for exposure
        # is that the device sees real bios during the attack window, which
        # this delivers on every FS.
        WORKLOAD_FILE="$MNT/dir-A/workload-active.bin"
        if command -v fio >/dev/null 2>&1 && [ -d "$MNT/dir-A" ]; then
            sudo fio --name=workload-active \
                     --filename="$WORKLOAD_FILE" \
                     --rw=randwrite \
                     --bs=4k \
                     --size=4M \
                     --time_based=1 \
                     --runtime=${WORKLOAD_DURATION_VAL} \
                     --ioengine=psync \
                     --direct=1 \
                     --output-format=terse \
                     >/tmp/fio-workload-$FS.log 2>&1 &
            WORKLOAD_PID=$!
            # Brief wait so fio actually starts emitting bios before the
            # cat-driven attack begins (otherwise the attack window may
            # complete before fio writes anything).
            sleep 0.5
        fi
    fi

    # bench-2 redesign (substep 10) : pristine-read under RadFI live attack.
    # Previous implementation overwrote dir-B/file-B2.bin with random bytes
    # before the cat, which guaranteed a hash mismatch by construction and
    # made RS-FEC functional proof impossible. We now capture the pristine
    # hash from HASHES.sha256 (generated at setup), arm RadFI, drop_caches,
    # cat the target file under attack, capture cat exit code + RS-FEC dmesg
    # markers + post-attack hash. Verdict derivation lives in synthesis.rs.
    TARGET_REL="dir-B/file-B2.bin"
    TARGET_FILE="$MNT/$TARGET_REL"
    HASHES_FILE="$MNT/dir-B/HASHES.sha256"
    HASH_PRE=$(sudo awk '$2 == "file-B2.bin" {print $1}' "$HASHES_FILE" 2>/dev/null)
    [ -z "$HASH_PRE" ] && HASH_PRE=missing
    HASH_POST=""  # B.1 : explicit init so umount/mount failure can pre-set
    # Phase A.2 : capture pre-attack physical extent map for CoW detection
    FRAG_PRE_PHYS=$(filefrag_phys "$FS" "$TARGET_FILE")
    DMESG_MARK="bench2-attack-$FS-$PROB-$$-$(date +%s%N)"
    sudo bash -c "echo \"$DMESG_MARK\" > /dev/kmsg" 2>/dev/null || true

    # B.3 (M1 C4) : save pristine copy of TARGET_FILE BEFORE umount cycle.
    # RadFI is temporarily disarmed during this read so pre.bin is guaranteed
    # to contain pristine bytes (uncontaminated by the active attack). This
    # is critical for cmp -l accuracy : if pre.bin already had flipped bits
    # from RadFI, BITS_DIFF would underestimate the post-attack corruption.
    echo 0 | sudo tee ${INJECTOR_DBG}/enabled >/dev/null
    sudo cat "$TARGET_FILE" > /tmp/pre-cat-$FS.bin 2>/dev/null
    PRE_SIZE=$(stat -c '%s' /tmp/pre-cat-$FS.bin 2>/dev/null || echo 0)
    # v0.12.4 : hash the disarmed read as well. BITS_DIFF only compares
    # pre-cat against post-cat, so it reports 0 whenever both reads return
    # the same bytes -- including when both are already wrong. Comparing
    # HASH_PRECAT against HASH_PRE (the setup-time sha256 of the written
    # content) tells whether the file was still pristine when the attack
    # window opened. Without it, a run where corruption predates the attack
    # is indistinguishable from a run where the filesystem protected the
    # data, which is exactly the ambiguity found in the N=5 campaign
    # (beamfs iterations 2, 4, 5: BITS_DIFF=0 but HASH_POST != HASH_PRE).
    HASH_PRECAT=$(sha256sum /tmp/pre-cat-$FS.bin 2>/dev/null | awk '{print $1}')
    [ -z "$HASH_PRECAT" ] && HASH_PRECAT=missing
    echo 1 | sudo tee ${INJECTOR_DBG}/enabled >/dev/null

    if is_readonly_fs "$FS"; then
        sudo umount $MNT 2>/dev/null
        echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
        sudo mount -t $FS -o ro $DEV $MNT 2>/dev/null || true
        sudo cat "$TARGET_FILE" > /tmp/post-cat-$FS.bin 2>/tmp/cat-err-$FS.log
        CAT_RC=$?
        sudo cat $MNT/dir-A/file-A1.bin > /dev/null 2>&1
        sudo cat $MNT/dir-C/file-C3.bin > /dev/null 2>&1
    else
        # B.1 (M1 C1) : umount + drop_caches + mount cycle for ext4/ext3/
        # btrfs/beamfs. Without this, sync + drop_caches alone leaves the
        # icache populated and pagecache pages get repopulated from disk
        # bypassing the RadFI hook on first read. The umount/mount cycle
        # forces the VFS to reread SB, root inode, target inode, and data
        # blocks via submit_bio, all of which are caught by RadFI.
        sudo sync
        # Phase C-fix: ZFS uses zpool export instead of umount.
        if [ "$FS" = "zfs" ]; then
            POOL_NAME="bench_zfs_${VD}"
            sudo zpool export "$POOL_NAME" 2>/tmp/umount-err-$FS.log || true
        else
            sudo umount $MNT 2>/tmp/umount-err-$FS.log
        fi
        UMOUNT_RC=$?
        echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
        # Phase C-fix: ZFS uses zpool import instead of mount.
        if [ "$FS" = "zfs" ]; then
            POOL_NAME="bench_zfs_${VD}"
            sudo zpool import -d /dev -f "$POOL_NAME" 2>/tmp/mount-err-$FS.log
        else
            sudo mount -t $FS $DEV $MNT 2>/tmp/mount-err-$FS.log
        fi
        MOUNT_RC=$?
        if [ $MOUNT_RC -ne 0 ]; then
            CAT_RC=255
            HASH_POST=mount_failed
        else
            sudo cat "$TARGET_FILE" > /tmp/post-cat-$FS.bin 2>/tmp/cat-err-$FS.log
            CAT_RC=$?
            sudo cat $MNT/dir-A/file-A1.bin > /dev/null 2>&1
            sudo cat $MNT/dir-C/file-C3.bin > /dev/null 2>&1
        fi
    fi

    CALL_A=$(sudo cat ${INJECTOR_DBG}/call_count)
    FLIP_A=$(sudo cat ${INJECTOR_DBG}/${FLIP_COUNT_KEY})

    echo 0 | sudo tee ${INJECTOR_DBG}/enabled  >/dev/null
    echo 0 | sudo tee ${INJECTOR_DBG}/hook_blk >/dev/null

    # Phase A.3 -- terminate the active workload if one was launched.
    # fio is time_based=1 so it self-terminates at WORKLOAD_DURATION ; the
    # explicit kill is defense-in-depth in case fio overshoots or hung.
    if [ -n "$WORKLOAD_PID" ]; then
        sudo kill -TERM $WORKLOAD_PID 2>/dev/null || true
        # Brief grace period for clean shutdown then force.
        sleep 0.2
        sudo kill -KILL $WORKLOAD_PID 2>/dev/null || true
        wait $WORKLOAD_PID 2>/dev/null || true
        sudo sync
    fi

    # Phase A.2 : capture post-attack physical extent map for CoW detection.
    # If mount_failed already set, the FS is not currently mounted; report
    # mount_failed for FRAG_POST_PHYS rather than calling filefrag on a
    # non-existent path. Otherwise filefrag the live remounted file.
    if [ "$HASH_POST" = "mount_failed" ]; then
        FRAG_POST_PHYS="mount_failed"
    else
        FRAG_POST_PHYS=$(filefrag_phys "$FS" "$TARGET_FILE")
    fi
    # Compute FRAG_RELOCATED: 1 if PRE and POST are both non-na/non-failed
    # AND differ ; 0 if both are non-na/non-failed AND equal ; na otherwise.
    case "$FRAG_PRE_PHYS:$FRAG_POST_PHYS" in
        na:*|*:na|*:mount_failed|*:filefrag_failed|filefrag_failed:*|missing:*|*:missing)
            FRAG_RELOCATED=na
            ;;
        *)
            if [ "$FRAG_PRE_PHYS" = "$FRAG_POST_PHYS" ]; then
                FRAG_RELOCATED=0
            else
                FRAG_RELOCATED=1
            fi
            ;;
    esac

    CALL_DELTA=$((CALL_A - CALL_B))
    FLIP_DELTA=$((FLIP_A - FLIP_B))

    # B.1 : do not overwrite HASH_POST if it was already set (e.g.
    # mount_failed), only compute from /tmp/post-cat-$FS.bin if untouched.
    if [ -z "$HASH_POST" ]; then
        if [ $CAT_RC -eq 0 ] && [ -s /tmp/post-cat-$FS.bin ]; then
            HASH_POST=$(sha256sum /tmp/post-cat-$FS.bin 2>/dev/null | awk '{print $1}')
        else
            HASH_POST=cat_failed
        fi
        [ -z "$HASH_POST" ] && HASH_POST=missing
    fi

    # B.3 (M1 C4) : bit-level corruption metrics via popcount XOR on the
    # byte-by-byte diff between pre and post. Produces 3 plottable fields :
    #   BITS_DIFF      : total bits flipped between pre and post (0 if pre == post)
    #   FRAC_CORRUPT   : fraction in basis points (1/10000) for integer math
    #                    in downstream synthesis ; 100 = 1%, 10000 = 100%.
    #   HAMM_BLOCKS    : number of 4 KB blocks with at least 1 bit flipped
    # Defensive : emit zeros if either file is missing.
    BITS_DIFF=0
    FRAC_CORRUPT=0
    HAMM_BLOCKS=0
    if [ -s /tmp/pre-cat-$FS.bin ] && [ -s /tmp/post-cat-$FS.bin ]; then
        METRICS=$(sudo python3 -c "
pre = open('/tmp/pre-cat-$FS.bin', 'rb').read()
post = open('/tmp/post-cat-$FS.bin', 'rb').read()
n = min(len(pre), len(post))
bits = 0
blocks = set()
for i in range(n):
    x = pre[i] ^ post[i]
    if x:
        bits += bin(x).count('1')
        blocks.add(i // 4096)
total_bits = max(n * 8, 1)
frac_bp = (bits * 10000) // total_bits
print(f'{bits} {frac_bp} {len(blocks)}')
" 2>/dev/null)
        if [ -n "$METRICS" ]; then
            BITS_DIFF=$(echo "$METRICS" | awk '{print $1}')
            FRAC_CORRUPT=$(echo "$METRICS" | awk '{print $2}')
            HAMM_BLOCKS=$(echo "$METRICS" | awk '{print $3}')
        fi
    fi

    DMESG_SLICE=$(sudo dmesg 2>/dev/null | awk -v m="$DMESG_MARK" '$0 ~ m {found=1; next} found')
    RS_CORRECTED=$(echo "$DMESG_SLICE" | grep -cE 'beamfs(/inline)?:.*symbol\(s\) corrected' | tr -d '\n')
    DMESG_UNCORR=$(echo "$DMESG_SLICE" | grep -ciE 'beamfs.*uncorrectable|beamfs.*RS decode failed|beamfs/inline.*(corrupted|unallocated) (direct|indirect|dindirect|tindirect) pointer|beamfs/inline.*(corrupted|unallocated) .* block|beamfs/inline.*data_csum mismatch|beamfs/inline.*data_selfid mismatch|beamfs/inline.*bad descriptor' | tr -d '\n')
    DMESG_EIO=$(echo "$DMESG_SLICE" | grep -ciE 'beamfs.*-EIO|beamfs.*Input/output error' | tr -d '\n')
    [ -z "$RS_CORRECTED" ] && RS_CORRECTED=0
    [ -z "$DMESG_UNCORR" ] && DMESG_UNCORR=0
    [ -z "$DMESG_EIO" ] && DMESG_EIO=0

    # Phase A.4 : count unique bytes attacked from the EMUFI flip_log ring
    # buffer. Each flip event carries (sector, byte_offset) ; we deduplicate
    # the tuple to count bytes physically distinct on disk.
    #
    # CSV header: seq,ktime_ns,sector,bio_op,byte_offset,bit_index,before,after
    # Columns of interest: $3 (sector) and $5 (byte_offset).
    #
    # Limitation: ring buffer is 4096 entries ; under saturation
    # (probability=10^6 + workload-active) seq numbers wrap and earlier
    # flips are overwritten. ATTACKED_BYTES_UNIQUE is therefore a lower
    # bound in such regimes (EMUFI v1 §VII.C.a).
    # Phase A.4-fix : use 'sudo test -e' instead of '[ -e ]' because
    # /sys/kernel/debug/ is typically mode 700 (root only), so a
    # non-root shell test fails the existence check even though
    # 'sudo cat' would succeed afterward. The privilege level of the
    # gate must match the privilege level of the read.
    if sudo test -e "${INJECTOR_DBG}/flip_log" ; then
        ATTACKED_BYTES_UNIQUE=$(sudo cat ${INJECTOR_DBG}/flip_log 2>/dev/null \
            | awk -F',' 'NR>1 && $2!="0" {print $3","$5}' \
            | sort -u \
            | wc -l)
        [ -z "$ATTACKED_BYTES_UNIQUE" ] && ATTACKED_BYTES_UNIQUE=0
    else
        ATTACKED_BYTES_UNIQUE=na
    fi

    sudo rm -f /tmp/pre-cat-$FS.bin /tmp/post-cat-$FS.bin /tmp/cat-err-$FS.log 2>/dev/null || true

    echo "FS=$FS|PROB=$PROB|CALL_DELTA=$CALL_DELTA|FLIP_DELTA=$FLIP_DELTA|TARGET=$TARGET_REL|HASH_PRE=$HASH_PRE|HASH_PRECAT=$HASH_PRECAT|HASH_POST=$HASH_POST|CAT_RC=$CAT_RC|RS_CORRECTED=$RS_CORRECTED|DMESG_UNCORRECTABLE=$DMESG_UNCORR|DMESG_EIO=$DMESG_EIO|BITS_DIFF=$BITS_DIFF|FRAC_CORRUPT=$FRAC_CORRUPT|HAMM_BLOCKS=$HAMM_BLOCKS|FILE_SIZE=$PRE_SIZE|FRAG_PRE_PHYS=$FRAG_PRE_PHYS|FRAG_POST_PHYS=$FRAG_POST_PHYS|FRAG_RELOCATED=$FRAG_RELOCATED|WORKLOAD_MODE=$WORKLOAD_MODE_VAL|WORKLOAD_DURATION=$WORKLOAD_DURATION_VAL|ATTACKED_BYTES_UNIQUE=$ATTACKED_BYTES_UNIQUE"
    ;;

verify)
    FS="$ARG2"
    VD="$ARG3"
    DEV="/dev/$VD"
    MNT="/mnt/test-$FS"

    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null

    POST_FILE=/tmp/post-attack-$FS.txt
    sudo find $MNT -type f -exec sha256sum {} \; 2>/dev/null | sort > $POST_FILE || echo "READ_ERROR"

    if [ ! -s $POST_FILE ]; then
        echo "FS=$FS|VERDICT=FS_PANIC|details=read failed"
        exit 0
    fi

    PRE_FILE=/tmp/pre-attack-$FS.txt
    DIFFS=$(diff $PRE_FILE $POST_FILE 2>/dev/null | grep -c '^[<>]')
    DIFFS=${DIFFS:-0}

    if ! is_readonly_fs "$FS"; then
        # Phase C-fix: ZFS uses zpool export/import.
        if [ "$FS" = "zfs" ]; then
            POOL_NAME="bench_zfs_${VD}"
            sudo zpool export "$POOL_NAME" 2>/dev/null
            sudo zpool import -d /dev -f "$POOL_NAME" 2>/dev/null
            REMOUNT_OK=$?
        else
            sudo umount $MNT 2>/dev/null
            sudo mount -t $FS $DEV $MNT 2>/dev/null
            REMOUNT_OK=$?
        fi
    else
        sudo umount $MNT 2>/dev/null
        sudo mount -t $FS -o ro $DEV $MNT 2>/dev/null
        REMOUNT_OK=$?
    fi

    if [ $REMOUNT_OK -ne 0 ]; then
        echo "FS=$FS|VERDICT=FS_PANIC|details=remount failed"
        exit 0
    fi

    REMOUNT_FILE=/tmp/remount-$FS.txt
    sudo find $MNT -type f -exec sha256sum {} \; 2>/dev/null | sort > $REMOUNT_FILE
    DIFFS_REMOUNT=$(diff $PRE_FILE $REMOUNT_FILE 2>/dev/null | grep -c '^[<>]')
    DIFFS_REMOUNT=${DIFFS_REMOUNT:-0}
    N_FILES_CHANGED=$((DIFFS_REMOUNT / 2))

    # bench-2 redesign (substep 10) : factual mount-state observation only.
    # The previous code picked between RECOVERED / CORRUPTED_DATA /
    # CORRUPTED_HEAVY based on DIFFS_REMOUNT, which is a derived judgment
    # that belongs in synthesis.rs (alongside HASH_PRE/HASH_POST/RS_CORRECTED
    # captured in the attack record). Verify now only signals whether the
    # FS came back up cleanly after umount/remount; per-file hash deltas
    # are emitted as raw counts.
    VERDICT="MOUNTED"
    DETAILS="remount ok ; $N_FILES_CHANGED of 12 file(s) hash-changed vs pre-attack"

    echo "FS=$FS|VERDICT=$VERDICT|DIFFS_PRE_POST=$DIFFS|DIFFS_PRE_REMOUNT=$DIFFS_REMOUNT|N_FILES_CHANGED=$N_FILES_CHANGED|details=$DETAILS"
    ;;

# ============================================================
# Cluster scope : run on each node (master + computes), targets beamfs on /data.
# Args: $1=action $2=ts_tag (also $3=prob for cluster_attack)
# Layout per node : /data/beamfs-bench-<ts_tag>/dir-{A,B,C}/file-{A,B,C}{1,2,3}.bin
# Cleanup        : cluster_verify removes the test subdirectory after verdict.
# Slurm artefacts /data/slurm-*.txt are NEVER touched.
# ============================================================

cluster_setup)
    TS_TAG="$ARG2"
    SUBDIR="/data/beamfs-bench-$TS_TAG"
    ensure_modules
    if ! mountpoint -q /data; then
        echo "CLUSTER|HOST=$(hostname)|ERROR=/data not mounted"
        exit 1
    fi
    sudo rm -rf "$SUBDIR" 2>/dev/null || true
    sudo mkdir -p "$SUBDIR"
    for letter in A B C; do
        sudo mkdir -p "$SUBDIR/dir-$letter"
        for n in 1 2 3; do
            sudo bash -c "head -c 262144 /dev/urandom > $SUBDIR/dir-$letter/file-${letter}${n}.bin"
        done
        sudo bash -c "cd $SUBDIR/dir-$letter && sha256sum file-${letter}1.bin file-${letter}2.bin file-${letter}3.bin > HASHES.sha256"
    done
    sudo sync
    sudo find "$SUBDIR" -type f -exec sha256sum {} \; 2>/dev/null | sort > "/tmp/pre-cluster-$TS_TAG.txt"

    # S3.1-cluster : compute target_block_range from filefrag on the
    # canonical cluster target_file ($SUBDIR/dir-B/file-B2.bin). Same
    # logic as the multifs setup path (worker.sh:355-382). The range
    # is sector-units (= fs_block x 8), end exclusive. Emitted in the
    # SETUP=OK record for the orchestrator to consume.
    # Without this, cluster_attack pushed target_block=0 (whole device)
    # to RadFI and flipped indiscriminately on SB / inode 1 / inode
    # table, producing spurious RS_FAILED verdicts at prob=1M (cf.
    # known-limitations.md scheme=2 no per-inode RS).
    CL_TARGET_FILE="$SUBDIR/dir-B/file-B2.bin"
    CL_TBR_START=0
    CL_TBR_END=0
    if command -v filefrag >/dev/null 2>&1 && [ -f "$CL_TARGET_FILE" ]; then
        CL_FRAG=$(sudo filefrag -v -b4096 "$CL_TARGET_FILE" 2>/dev/null)
        CL_STARTS=$(echo "$CL_FRAG" | awk '/^ +[0-9]+:/ {gsub(/[.:]/, "", $4); print $4}')
        CL_ENDS=$(echo "$CL_FRAG" | awk '/^ +[0-9]+:/ {gsub(/[.:]/, "", $5); print $5}')
        CL_EXTENTS="$CL_STARTS"
        if [ -n "$CL_EXTENTS" ]; then
            CL_RMIN=$(echo "$CL_STARTS" | sort -n | head -1)
            CL_RMAX=$(echo "$CL_ENDS" | sort -n | tail -1)
            CL_TBR_START=$((CL_RMIN * 8))
            CL_TBR_END=$(((CL_RMAX + 1) * 8))
        fi
    fi

    echo "CLUSTER|HOST=$(hostname)|SETUP=OK|SUBDIR=$SUBDIR|FILES=12|TARGET_BLOCK_RANGE_START=$CL_TBR_START|TARGET_BLOCK_RANGE_END=$CL_TBR_END"
    ;;

cluster_attack)
    TS_TAG="$ARG2"
    PROB_VAL="$ARG3"
    SUBDIR="/data/beamfs-bench-$TS_TAG"
    DEV_VDB="/dev/vdb"

    if [ ! -d "$SUBDIR" ]; then
        echo "CLUSTER|HOST=$(hostname)|ATTACK=ERROR|reason=subdir_missing"
        exit 1
    fi
    # Ensure ${INJECTOR_KO} loaded before testing debugfs presence
    ensure_modules
    if ! sudo test -d "${INJECTOR_DBG}"; then
        echo "CLUSTER|HOST=$(hostname)|ATTACK=SKIP|reason=${INJECTOR}_debugfs_unavailable"
        exit 0
    fi

    DEV_MAJ=$((0x$(stat -c '%t' $DEV_VDB)))
    DEV_MIN=$((0x$(stat -c '%T' $DEV_VDB)))
    DEV_NUM=$(( (DEV_MAJ << 20) | DEV_MIN ))

    echo 0 | sudo tee ${INJECTOR_DBG}/enabled  >/dev/null
    echo 0 | sudo tee ${INJECTOR_DBG}/hook_blk >/dev/null

    CALL_B=$(sudo cat ${INJECTOR_DBG}/call_count)
    FLIP_B=$(sudo cat ${INJECTOR_DBG}/${FLIP_COUNT_KEY})

    echo $DEV_NUM   | sudo tee ${INJECTOR_DBG}/target_dev   >/dev/null
    echo 0          | sudo tee ${INJECTOR_DBG}/target_block >/dev/null
    echo $PROB_VAL  | sudo tee ${INJECTOR_DBG}/probability  >/dev/null
    # v0.7.6 : push inject_on_read=1 unconditionally (see multifs site).
    echo 1          | sudo tee ${INJECTOR_DBG}/inject_on_read >/dev/null
    # MBU/multi-chip realism fix : cluster_attack never posed FLIP_WIDTH,
    # MULTI_CHIP, CHIP_COUNT, WIDTH_MODE, unlike the multifs site (worker.sh
    # ~464-539). Without this, cluster injections always fell back to
    # flip_width=1 SEU regardless of the caller-requested MBU intensity.
    FLIP_WIDTH_VAL=${FLIP_WIDTH:-1}
    if sudo test -e ${INJECTOR_DBG}/flip_width; then
        echo $FLIP_WIDTH_VAL | sudo tee ${INJECTOR_DBG}/flip_width >/dev/null
    fi
    # v0.12.5 : dose control (emufi 0.6.0+). Posing the same MAX_FLIPS for
    # every filesystem makes the campaign a controlled experiment: without
    # it the injector fires once per filtered bio, so a filesystem issuing
    # many small bios (beamfs: 72 for a 256 KiB read) receives far more
    # flips than one issuing a single merged readahead (ext4: 4).
    if [ -n "${MAX_FLIPS:-}" ] && sudo test -e ${INJECTOR_DBG}/max_flips; then
        echo ${MAX_FLIPS} | sudo tee ${INJECTOR_DBG}/max_flips >/dev/null
    fi
    if [ -n "${MULTI_CHIP:-}" ] && sudo test -e ${INJECTOR_DBG}/multi_chip; then
        echo ${MULTI_CHIP} | sudo tee ${INJECTOR_DBG}/multi_chip >/dev/null
    fi
    if [ -n "${CHIP_COUNT:-}" ] && sudo test -e ${INJECTOR_DBG}/chip_count; then
        echo ${CHIP_COUNT} | sudo tee ${INJECTOR_DBG}/chip_count >/dev/null
    fi
    if [ -n "${WIDTH_MODE:-}" ] && sudo test -e ${INJECTOR_DBG}/width_mode; then
        echo ${WIDTH_MODE} | sudo tee ${INJECTOR_DBG}/width_mode >/dev/null
    fi
    # v0.12.7 : parameters that were posed only at the multifs site. All of
    # them already crossed SSH through the cluster.rs whitelist, so an
    # invocation setting any of them looked like it applied everywhere while
    # the four cluster nodes silently ran a different configuration.
    # target_ranges is the consequential one: without it the cluster path
    # kept using the enclosing interval that the per-extent fix replaced.
    if [ -n "${TARGET_RANGES:-}" ] && sudo test -e ${INJECTOR_DBG}/target_ranges; then
        printf '%s' "${TARGET_RANGES}" | sudo tee ${INJECTOR_DBG}/target_ranges >/dev/null
    fi
    if [ -n "${LET_CLASS:-}" ] && sudo test -e ${INJECTOR_DBG}/let_class; then
        echo ${LET_CLASS} | sudo tee ${INJECTOR_DBG}/let_class >/dev/null
    fi
    if [ -n "${FLIP_STRIDE_BITS:-}" ] && sudo test -e ${INJECTOR_DBG}/flip_stride_bits; then
        echo ${FLIP_STRIDE_BITS} | sudo tee ${INJECTOR_DBG}/flip_stride_bits >/dev/null
    fi
    if [ -n "${CODEWORD_SIZE_BYTES:-}" ] && sudo test -e ${INJECTOR_DBG}/codeword_size_bytes; then
        echo ${CODEWORD_SIZE_BYTES} | sudo tee ${INJECTOR_DBG}/codeword_size_bytes >/dev/null
    fi
    if [ -n "${CODEWORD_ALIGN_BYTES:-}" ] && sudo test -e ${INJECTOR_DBG}/codeword_align_bytes; then
        echo ${CODEWORD_ALIGN_BYTES} | sudo tee ${INJECTOR_DBG}/codeword_align_bytes >/dev/null
    fi
    if [ -n "${MULTI_SEGMENT:-}" ] && sudo test -e ${INJECTOR_DBG}/multi_segment; then
        echo ${MULTI_SEGMENT} | sudo tee ${INJECTOR_DBG}/multi_segment >/dev/null
    fi
    if [ -n "${TARGET_STRUCT_OFFSET:-}" ] && sudo test -e ${INJECTOR_DBG}/target_struct_offset; then
        echo ${TARGET_STRUCT_OFFSET} | sudo tee ${INJECTOR_DBG}/target_struct_offset >/dev/null
    fi
    if [ -n "${RESEED:-}" ] && sudo test -e ${INJECTOR_DBG}/reseed; then
        echo ${RESEED} | sudo tee ${INJECTOR_DBG}/reseed >/dev/null
    fi
    # DATA_CSUM/S3.1-cluster fix : cluster_attack must POSE the target_block_range
    # that cluster_setup computed. Without this the range stayed unset on /data,
    # every bio was REJECT_BLOCK (skipped_filter), and emufi never injected
    # (call_count=0). Recompute from filefrag on this node's own target file
    # (no cross-SSH var propagation) and apply, mirroring the multifs site.
    CL_TARGET_FILE="$SUBDIR/dir-B/file-B2.bin"
    if command -v filefrag >/dev/null 2>&1 && [ -f "$CL_TARGET_FILE" ] \
           && sudo test -e ${INJECTOR_DBG}/target_block_range_start; then
        CA_FRAG=$(sudo filefrag -v -b4096 "$CL_TARGET_FILE" 2>/dev/null)
        CA_STARTS=$(echo "$CA_FRAG" | awk '/^ +[0-9]+:/ {gsub(/[.:]/, "", $4); print $4}')
        CA_ENDS=$(echo "$CA_FRAG" | awk '/^ +[0-9]+:/ {gsub(/[.:]/, "", $5); print $5}')
        CA_EXTENTS="$CA_STARTS"
        if [ -n "$CA_EXTENTS" ]; then
            CA_RMIN=$(echo "$CA_STARTS" | sort -n | head -1)
            CA_RMAX=$(echo "$CA_ENDS" | sort -n | tail -1)
            echo $((CA_RMIN * 8))       | sudo tee ${INJECTOR_DBG}/target_block_range_start >/dev/null
            echo $(((CA_RMAX + 1) * 8)) | sudo tee ${INJECTOR_DBG}/target_block_range_end   >/dev/null
        fi
    fi

    # v0.7.4 : emufi 0.3.0 envvars (no auto-compute on metadata site).
    if [ -n "${FLIP_LOCALITY:-}" ] && sudo test -e ${INJECTOR_DBG}/flip_locality; then
        echo ${FLIP_LOCALITY} | sudo tee ${INJECTOR_DBG}/flip_locality >/dev/null
    fi
    if [ -n "${BURST_SYMBOLS:-}" ] && sudo test -e ${INJECTOR_DBG}/burst_symbols; then
        echo ${BURST_SYMBOLS} | sudo tee ${INJECTOR_DBG}/burst_symbols >/dev/null
    fi
    if [ -n "${TARGET_STRUCT:-}" ] && sudo test -e ${INJECTOR_DBG}/target_struct; then
        echo ${TARGET_STRUCT} | sudo tee ${INJECTOR_DBG}/target_struct >/dev/null
    fi
    if [ -n "${TARGET_STRUCT_BLOCK_NO:-}" ] && sudo test -e ${INJECTOR_DBG}/target_struct_block_no; then
        echo ${TARGET_STRUCT_BLOCK_NO} | sudo tee ${INJECTOR_DBG}/target_struct_block_no >/dev/null
    fi
    if [ -n "${SEFI_PROBABILITY:-}" ] && sudo test -e ${INJECTOR_DBG}/sefi_probability; then
        echo ${SEFI_PROBABILITY} | sudo tee ${INJECTOR_DBG}/sefi_probability >/dev/null
    fi
    if [ -n "${SEFI_WINDOW_MS:-}" ] && sudo test -e ${INJECTOR_DBG}/sefi_window_ms; then
        echo ${SEFI_WINDOW_MS} | sudo tee ${INJECTOR_DBG}/sefi_window_ms >/dev/null
    fi

    echo 1          | sudo tee ${INJECTOR_DBG}/hook_blk     >/dev/null
    echo 1          | sudo tee ${INJECTOR_DBG}/enabled      >/dev/null

    # bench-2 redesign (substep 10) : pristine-read under RadFI live attack
    # on the cluster /data/beamfs-bench-<TS> subdir. Same semantics as the
    # multifs attack) action ; namespace CLUSTER|, dev /dev/vdb fixed.
    TARGET_REL="dir-B/file-B2.bin"
    TARGET_FILE="$SUBDIR/$TARGET_REL"
    HASHES_FILE="$SUBDIR/dir-B/HASHES.sha256"
    HASH_PRE=$(sudo awk '$2 == "file-B2.bin" {print $1}' "$HASHES_FILE" 2>/dev/null)
    [ -z "$HASH_PRE" ] && HASH_PRE=missing
    HASH_POST=""  # B.2 : explicit init so umount/mount failure can pre-set
    DMESG_MARK="bench2-cluster-$(hostname)-$PROB_VAL-$$-$(date +%s%N)"
    sudo bash -c "echo \"$DMESG_MARK\" > /dev/kmsg" 2>/dev/null || true

    # B.3 (M1 C4) : save pristine copy of TARGET_FILE BEFORE umount cycle.
    # RadFI temporarily disarmed (see multifs branch comment).
    echo 0 | sudo tee ${INJECTOR_DBG}/enabled >/dev/null
    sudo cat "$TARGET_FILE" > /tmp/pre-cat-cluster-$$.bin 2>/dev/null
    PRE_SIZE=$(stat -c '%s' /tmp/pre-cat-cluster-$$.bin 2>/dev/null || echo 0)
    # v0.12.4 : see the multifs site -- distinguishes "protected" from
    # "already corrupt before the attack window".
    HASH_PRECAT=$(sha256sum /tmp/pre-cat-cluster-$$.bin 2>/dev/null | awk '{print $1}')
    [ -z "$HASH_PRECAT" ] && HASH_PRECAT=missing
    echo 1 | sudo tee ${INJECTOR_DBG}/enabled >/dev/null

    # B.2 (M1 C1) : umount + drop_caches + mount cycle for /data (beamfs).
    # Same rationale as multifs B.1 : without this, sync + drop_caches alone
    # leaves the icache populated and pagecache pages get repopulated from
    # disk bypassing the RadFI hook on first read. The cycle forces VFS to
    # reread SB, root inode, target inode, and data blocks via submit_bio.
    sudo sync
    sudo umount /data 2>/tmp/umount-err-cluster-$$.log
    UMOUNT_RC=$?
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    sudo mount -t beamfs /dev/vdb /data 2>/tmp/mount-err-cluster-$$.log
    MOUNT_RC=$?
    if [ $MOUNT_RC -ne 0 ]; then
        CAT_RC=255
        HASH_POST=mount_failed
    else
        sudo cat "$TARGET_FILE" > /tmp/post-cat-cluster-$$.bin 2>/tmp/cat-err-cluster-$$.log
        CAT_RC=$?
        sudo cat $SUBDIR/dir-A/file-A1.bin > /dev/null 2>&1
        sudo cat $SUBDIR/dir-C/file-C3.bin > /dev/null 2>&1
    fi

    CALL_A=$(sudo cat ${INJECTOR_DBG}/call_count)
    FLIP_A=$(sudo cat ${INJECTOR_DBG}/${FLIP_COUNT_KEY})

    echo 0 | sudo tee ${INJECTOR_DBG}/enabled  >/dev/null
    echo 0 | sudo tee ${INJECTOR_DBG}/hook_blk >/dev/null

    CALL_DELTA=$((CALL_A - CALL_B))
    FLIP_DELTA=$((FLIP_A - FLIP_B))

    # B.2 : do not overwrite HASH_POST if it was already set (e.g.
    # mount_failed), only compute from /tmp/post-cat-cluster-$$.bin if untouched.
    if [ -z "$HASH_POST" ]; then
        if [ $CAT_RC -eq 0 ] && [ -s /tmp/post-cat-cluster-$$.bin ]; then
            HASH_POST=$(sha256sum /tmp/post-cat-cluster-$$.bin 2>/dev/null | awk '{print $1}')
        else
            HASH_POST=cat_failed
        fi
        [ -z "$HASH_POST" ] && HASH_POST=missing
    fi

    # B.3 (M1 C4) : same bit-level metrics as multifs scope.
    BITS_DIFF=0
    FRAC_CORRUPT=0
    HAMM_BLOCKS=0
    if [ -s /tmp/pre-cat-cluster-$$.bin ] && [ -s /tmp/post-cat-cluster-$$.bin ]; then
        METRICS=$(sudo python3 -c "
pre = open('/tmp/pre-cat-cluster-$$.bin', 'rb').read()
post = open('/tmp/post-cat-cluster-$$.bin', 'rb').read()
n = min(len(pre), len(post))
bits = 0
blocks = set()
for i in range(n):
    x = pre[i] ^ post[i]
    if x:
        bits += bin(x).count('1')
        blocks.add(i // 4096)
total_bits = max(n * 8, 1)
frac_bp = (bits * 10000) // total_bits
print(f'{bits} {frac_bp} {len(blocks)}')
" 2>/dev/null)
        if [ -n "$METRICS" ]; then
            BITS_DIFF=$(echo "$METRICS" | awk '{print $1}')
            FRAC_CORRUPT=$(echo "$METRICS" | awk '{print $2}')
            HAMM_BLOCKS=$(echo "$METRICS" | awk '{print $3}')
        fi
    fi

    DMESG_SLICE=$(sudo dmesg 2>/dev/null | awk -v m="$DMESG_MARK" '$0 ~ m {found=1; next} found')
    RS_CORRECTED=$(echo "$DMESG_SLICE" | grep -cE 'beamfs(/inline)?:.*symbol\(s\) corrected' | tr -d '\n')
    DMESG_UNCORR=$(echo "$DMESG_SLICE" | grep -ciE 'beamfs.*uncorrectable|beamfs.*RS decode failed|beamfs/inline.*(corrupted|unallocated) (direct|indirect|dindirect|tindirect) pointer|beamfs/inline.*(corrupted|unallocated) .* block|beamfs/inline.*data_csum mismatch|beamfs/inline.*data_selfid mismatch|beamfs/inline.*bad descriptor' | tr -d '\n')
    DMESG_EIO=$(echo "$DMESG_SLICE" | grep -ciE 'beamfs.*-EIO|beamfs.*Input/output error' | tr -d '\n')
    [ -z "$RS_CORRECTED" ] && RS_CORRECTED=0
    [ -z "$DMESG_UNCORR" ] && DMESG_UNCORR=0
    [ -z "$DMESG_EIO" ] && DMESG_EIO=0

    sudo rm -f /tmp/pre-cat-cluster-$$.bin /tmp/post-cat-cluster-$$.bin /tmp/cat-err-cluster-$$.log 2>/dev/null || true

    echo "CLUSTER|HOST=$(hostname)|PROB=$PROB_VAL|CALL_DELTA=$CALL_DELTA|FLIP_DELTA=$FLIP_DELTA|TARGET=$TARGET_REL|HASH_PRE=$HASH_PRE|HASH_PRECAT=$HASH_PRECAT|HASH_POST=$HASH_POST|CAT_RC=$CAT_RC|RS_CORRECTED=$RS_CORRECTED|DMESG_UNCORRECTABLE=$DMESG_UNCORR|DMESG_EIO=$DMESG_EIO|BITS_DIFF=$BITS_DIFF|FRAC_CORRUPT=$FRAC_CORRUPT|HAMM_BLOCKS=$HAMM_BLOCKS|FILE_SIZE=$PRE_SIZE"
    ;;

cluster_verify)
    TS_TAG="$ARG2"
    SUBDIR="/data/beamfs-bench-$TS_TAG"
    if [ ! -d "$SUBDIR" ]; then
        echo "CLUSTER|HOST=$(hostname)|VERIFY=ERROR|reason=subdir_missing"
        exit 1
    fi
    PRE_FILE="/tmp/pre-cluster-$TS_TAG.txt"
    POST_FILE="/tmp/post-cluster-$TS_TAG.txt"
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    sudo find "$SUBDIR" -type f -exec sha256sum {} \; 2>/dev/null | sort > "$POST_FILE"
    DIFFS=$(diff "$PRE_FILE" "$POST_FILE" 2>/dev/null | grep -c '^[<>]')
    DIFFS=${DIFFS:-0}

    N=$((DIFFS / 2))

    # bench-2 redesign (substep 10) : factual observation only ; verdict
    # derivation lives in synthesis.rs. cluster_verify reports raw diff
    # count + count of changed files. RECOVERED/CORRUPTED interpretation
    # is computed from this and the cluster_attack record.
    VERDICT="VERIFIED"
    DETAILS="diff counted ; $N of 12 file(s) hash-changed on /data"

    sudo rm -rf "$SUBDIR" 2>/dev/null || true
    sudo rm -f "$PRE_FILE" "$POST_FILE" 2>/dev/null || true

    echo "CLUSTER|HOST=$(hostname)|VERDICT=$VERDICT|DIFFS=$DIFFS|N_FILES_CHANGED=$N|details=$DETAILS"
    ;;

bootstrap_data)
    ensure_modules
    # beamfs is built-in (CONFIG_BEAMFS_FS=y); detect via /proc/filesystems.
    if ! grep -qw beamfs /proc/filesystems; then
        echo "CLUSTER|HOST=$(hostname)|BOOTSTRAP=ERROR|reason=beamfs not in /proc/filesystems"
        exit 1
    fi
    # reed_solomon is built-in; detect via exported symbol in /proc/kallsyms.
    if ! sudo grep -qE '^[0-9a-f]+ [Tt] encode_rs8$' /proc/kallsyms; then
        echo "CLUSTER|HOST=$(hostname)|BOOTSTRAP=ERROR|reason=reed_solomon symbol absent"
        exit 1
    fi
    if mountpoint -q /data; then
        sudo umount /data 2>/dev/null || sudo umount -l /data 2>/dev/null || true
    fi
    if [ ! -b /dev/vdb ]; then
        echo "CLUSTER|HOST=$(hostname)|BOOTSTRAP=ERROR|reason=/dev/vdb missing"
        exit 1
    fi
    # v0.7.5 : per_inode_rs is now the default for irrefutable proof.
    # Activates v5 PER_INODE_RS (bit 8 s_feat_incompat) so that the
    # root inode and all inodes are RS-protected. Without this flag,
    # inode 1 CRC32 mismatch under attack at high probability is
    # uncorrectable and the mount fails (compute03 R19 v0.7.4).
    if ! sudo mkfs.beamfs $(mkfs_beamfs_args) /dev/vdb >/tmp/mkfs-bootstrap.log 2>&1; then
        TAIL=$(tail -3 /tmp/mkfs-bootstrap.log | tr '\n' ' ')
        echo "CLUSTER|HOST=$(hostname)|BOOTSTRAP=ERROR|reason=mkfs failed|details=$TAIL"
        exit 1
    fi
    sudo mkdir -p /data
    if ! sudo mount -t beamfs /dev/vdb /data 2>/tmp/mount-bootstrap.log; then
        TAIL=$(tail -3 /tmp/mount-bootstrap.log | tr '\n' ' ')
        echo "CLUSTER|HOST=$(hostname)|BOOTSTRAP=ERROR|reason=mount failed|details=$TAIL"
        exit 1
    fi
    if ! mountpoint -q /data; then
        echo "CLUSTER|HOST=$(hostname)|BOOTSTRAP=ERROR|reason=/data not mounted post-mount"
        exit 1
    fi
    DATA_INFO=$(df -h /data 2>/dev/null | awk 'NR==2 {print $2"/"$3}')
    echo "CLUSTER|HOST=$(hostname)|BOOTSTRAP=OK|fs=beamfs|dev=/dev/vdb|info=$DATA_INFO"
    ;;
bitrot_setup)
    TS_TAG="$ARG2"
    SUBDIR="/data/bitrot-$TS_TAG"
    ensure_modules
    # If /data is not mounted (e.g. metadata test left vdb in incoherent state),
    # auto-bootstrap by re-formatting vdb + mounting /data. This makes bitrot
    # standalone re-runnable without requiring a fresh bootstrap_data invocation.
    if ! mountpoint -q /data; then
        echo "BITROT|HOST=$(hostname)|SETUP=INFO|reason=/data not mounted, auto-bootstrapping"
        if [ ! -b /dev/vdb ]; then
            echo "BITROT|HOST=$(hostname)|SETUP=ERROR|reason=/dev/vdb missing"
            exit 1
        fi
        if ! sudo mkfs.beamfs $(mkfs_beamfs_args) /dev/vdb >/tmp/bitrot-mkfs.log 2>&1; then
            TAIL=$(tail -3 /tmp/bitrot-mkfs.log | tr '\n' ' ')
            echo "BITROT|HOST=$(hostname)|SETUP=ERROR|reason=auto_mkfs_failed|details=$TAIL"
            exit 1
        fi
        sudo mkdir -p /data
        if ! sudo mount -t beamfs /dev/vdb /data 2>/tmp/bitrot-mount.log; then
            TAIL=$(tail -3 /tmp/bitrot-mount.log | tr '\n' ' ')
            echo "BITROT|HOST=$(hostname)|SETUP=ERROR|reason=auto_mount_failed|details=$TAIL"
            exit 1
        fi
        if ! mountpoint -q /data; then
            echo "BITROT|HOST=$(hostname)|SETUP=ERROR|reason=auto_bootstrap_failed_postmount"
            exit 1
        fi
    fi
    sudo rm -rf "$SUBDIR" 2>/dev/null || true
    sudo mkdir -p "$SUBDIR"
    # 5 fichiers de 4 KB chacun (1 block beamfs chacun)
    for n in 1 2 3 4 5; do
        sudo bash -c "head -c 4096 /dev/urandom > $SUBDIR/file-$n.bin"
    done
    sudo sync
    # Baseline sha256
    sudo find "$SUBDIR" -type f -exec sha256sum {} \; 2>/dev/null | sort > "/tmp/bitrot-pre-$TS_TAG.txt"
    HASH_PRE=$(sudo cat "/tmp/bitrot-pre-$TS_TAG.txt" | sha256sum | awk '{print $1}')
    # Detection dynamique : scan /dev/vdb pour trouver le block de file-3.bin
    TARGET_FILE="$SUBDIR/file-3.bin"
    PATTERN=$(sudo head -c 16 "$TARGET_FILE" | xxd -p)
    TARGET_BLOCK=0
    sudo sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    for blk in $(seq 5 200); do
        BYTE_OFFSET=$((blk * 4096))
        BLOCK_HEAD=$(sudo dd if=/dev/vdb bs=1 skip=$BYTE_OFFSET count=16 2>/dev/null | xxd -p)
        if [ "$BLOCK_HEAD" = "$PATTERN" ]; then
            TARGET_BLOCK=$blk
            break
        fi
    done
    if [ "$TARGET_BLOCK" = "0" ]; then
        echo "BITROT|HOST=$(hostname)|SETUP=ERROR|reason=could not locate file-3.bin on disk"
        exit 1
    fi
    # Persist target block for inject step (clean re-mount safe)
    echo "$TARGET_BLOCK" | sudo tee "/tmp/bitrot-target-$TS_TAG.txt" >/dev/null
    echo "BITROT|HOST=$(hostname)|SETUP=OK|SUBDIR=$SUBDIR|FILES=5|HASH_PRE=$HASH_PRE|TARGET_FILE=$TARGET_FILE|TARGET_BLOCK=$TARGET_BLOCK"
    ;;
bitrot_inject)
    TS_TAG="$ARG2"
    BYTES="${ARG3:-1}"
    # Lire le block cible detecte par setup
    TARGET_FILE="/tmp/bitrot-target-$TS_TAG.txt"
    if [ ! -f "$TARGET_FILE" ]; then
        echo "BITROT|HOST=$(hostname)|INJECT=ERROR|reason=target block file missing"
        exit 1
    fi
    BLOCK_OFFSET=$(sudo cat "$TARGET_FILE")
    # Flush + umount aveugle
    sudo sync
    if mountpoint -q /data; then
        sudo umount /data 2>/dev/null || sudo umount -l /data 2>/dev/null
    fi
    BYTE_OFFSET=$((BLOCK_OFFSET * 4096))
    # dd random bytes a l'offset detecte
    sudo dd if=/dev/urandom of=/dev/vdb bs=1 count=$BYTES seek=$BYTE_OFFSET conv=notrunc 2>/dev/null
    sudo sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    sudo mount -t beamfs /dev/vdb /data 2>/tmp/bitrot-remount.log
    REMOUNT_RC=$?
    if [ $REMOUNT_RC -ne 0 ]; then
        TAIL=$(tail -3 /tmp/bitrot-remount.log | tr '\n' ' ')
        echo "BITROT|HOST=$(hostname)|INJECT=FAIL_REMOUNT|bytes=$BYTES|byte_offset=$BYTE_OFFSET|block=$BLOCK_OFFSET|details=$TAIL"
        exit 0
    fi
    echo "BITROT|HOST=$(hostname)|INJECT=OK|bytes=$BYTES|byte_offset=$BYTE_OFFSET|block=$BLOCK_OFFSET"
    ;;
bitrot_verify)
    TS_TAG="$ARG2"
    SUBDIR="/data/bitrot-$TS_TAG"
    if [ ! -d "$SUBDIR" ]; then
        echo "BITROT|HOST=$(hostname)|VERIFY=ERROR|reason=subdir_missing"
        exit 1
    fi
    # Capture dmesg for kernel RS recovery markers
    DMESG_RECOVERED=$(sudo dmesg --since "1 minute ago" 2>/dev/null | grep -ciE 'beamfs.*corrected by RS|beamfs.*RS recovery|beamfs/inline:.*symbol\(s\) corrected' | tr -d '\n')
    DMESG_UNCORR=$(sudo dmesg --since "1 minute ago" 2>/dev/null | grep -ciE 'beamfs.*UNCORRECTABLE|beamfs.*RS decode failed|beamfs/inline:.*uncorrectable|beamfs:.*RS block uncorrectable' | tr -d '\n')
    DMESG_EIO=$(sudo dmesg --since "1 minute ago" 2>/dev/null | grep -ciE 'beamfs.*-EIO|beamfs.*Input/output error' | tr -d '\n')
    [ -z "$DMESG_RECOVERED" ] && DMESG_RECOVERED=0
    [ -z "$DMESG_UNCORR" ] && DMESG_UNCORR=0
    [ -z "$DMESG_EIO" ] && DMESG_EIO=0
    # Read tous les fichiers (force IO path)
    READ_OK=0
    READ_FAIL=0
    for n in 1 2 3 4 5; do
        if sudo cat "$SUBDIR/file-$n.bin" > /dev/null 2>&1; then
            READ_OK=$((READ_OK+1))
        else
            READ_FAIL=$((READ_FAIL+1))
        fi
    done
    # SHA-256 post
    sudo sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    sudo find "$SUBDIR" -type f -exec sha256sum {} \; 2>/dev/null | sort > "/tmp/bitrot-post-$TS_TAG.txt"
    DIFFS=$(awk '
        FNR==NR { hash_pre[$2]=$1; next }
        { if ($1 != hash_pre[$2]) mismatch++ }
        END { print mismatch+0 }
    ' "/tmp/bitrot-pre-$TS_TAG.txt" "/tmp/bitrot-post-$TS_TAG.txt" 2>/dev/null)
    [ -z "$DIFFS" ] && DIFFS=0
    # Read scheme from kernel dmesg of the most recent mount.
    # Kernel prints "beamfs: mounted v1 ... scheme=N ..." at every mount.
    # This is the canonical source of truth (independent of on-disk
    # offset version drift between format revisions).
    SCHEME=$(sudo dmesg 2>/dev/null | grep 'beamfs: mounted' | tail -1 \
             | grep -oE 'scheme=[0-9]+' | tail -1 | cut -d= -f2)
    [ -z "$SCHEME" ] && SCHEME=unknown

    # Parse RS journal as 64 events of 40 bytes each (struct beamfs_rs_event v4)
    RSJ_BYTES=$((64 * 40))
    RSJ_HEX=$(sudo dd if=/dev/vdb bs=1 skip=116 count=$RSJ_BYTES 2>/dev/null | xxd -p -c 40)
    RSJ_NONZERO=$(echo "$RSJ_HEX" | grep -cv '^0\+$' | tr -d '\n')
    [ -z "$RSJ_NONZERO" ] && RSJ_NONZERO=0

    # Emit pure observation record (no PASS/FAIL judgment)
    echo "BITROT|HOST=$(hostname)|SCHEME=$SCHEME|READ_OK=$READ_OK|READ_FAIL=$READ_FAIL|DATA_HASH_DIFF=$DIFFS|DMESG_RS_CORRECTED=$DMESG_RECOVERED|DMESG_UNCORRECTABLE=$DMESG_UNCORR|DMESG_EIO=$DMESG_EIO|RS_JOURNAL_NEW_ENTRIES=$RSJ_NONZERO"
    sudo rm -rf "$SUBDIR" 2>/dev/null || true
    sudo rm -f "/tmp/bitrot-pre-$TS_TAG.txt" "/tmp/bitrot-post-$TS_TAG.txt" "/tmp/bitrot-target-$TS_TAG.txt" 2>/dev/null
    echo "BITROT|HOST=$(hostname)|VERDICT=$VERDICT|read_ok=$READ_OK|read_fail=$READ_FAIL|diffs=$DIFFS|dmesg_rec=$DMESG_RECOVERED|dmesg_uncorr=$DMESG_UNCORR|rsj_entries=$RSJ_NONZERO|details=$DETAILS"
    ;;

metadata_setup)
    TS_TAG="$ARG2"
    FS="$ARG3"
    VD="$ARG4"
    DEV="/dev/$VD"
    MNT="/mnt/meta-$FS-$TS_TAG"
    SUBDIR="$MNT/test"

    if [ ! -b "$DEV" ]; then
        echo "METADATA|HOST=$(hostname)|SETUP=ERROR|reason=device_missing|dev=$DEV"
        exit 1
    fi

    # Aggressive cleanup: previous tests (multifs, crash) may have left
    # stale mountpoints, kernel state, or superblock metadata on $DEV.
    # We umount any mountpoint that references $DEV, then wipe the first
    # 1MB of $DEV (kills FS superblock + parent superblock for beamfs).
    # This makes metadata_setup re-runnable across FS transitions.
    sudo umount "$MNT" 2>/dev/null
    # Find any other mountpoint using $DEV and umount it (e.g. multifs left
    # /mnt/test-beamfs mounted on vdg, which blocks subsequent mkfs).
    for m in $(mount | grep -E "^$DEV " | awk '{print $3}'); do
        sudo umount "$m" 2>/dev/null || sudo umount -l "$m" 2>/dev/null
    done
    sudo rm -rf "$MNT"
    sudo mkdir -p "$MNT"
    # Wipe first 1MB to clear any FS superblock (ext*, btrfs, beamfs all
    # store SB in the first sectors). Idempotent for next mkfs.
    sudo dd if=/dev/zero of="$DEV" bs=1M count=1 conv=notrunc status=none 2>/dev/null
    sudo sync

    case "$FS" in
        ext4)     sudo mkfs.ext4  -F -q "$DEV" >/dev/null 2>&1 ;;
        ext3)     sudo mkfs.ext3  -F -q "$DEV" >/dev/null 2>&1 ;;
        btrfs)    sudo mkfs.btrfs -f    "$DEV" >/dev/null 2>&1 ;;
        squashfs) sudo bash -c "mkdir -p /tmp/sq-$TS_TAG && head -c 1M /dev/urandom > /tmp/sq-$TS_TAG/data.bin && mksquashfs /tmp/sq-$TS_TAG $DEV -noappend -quiet" >/dev/null 2>&1 && rm -rf /tmp/sq-$TS_TAG ;;
        beamfs)
            ensure_modules
            MKFS_LOG=$(sudo mkfs.beamfs $(mkfs_beamfs_args) "$DEV" 2>&1)
            MKFS_RC=$?
            if [ $MKFS_RC -ne 0 ]; then
                echo "METADATA|HOST=$(hostname)|SETUP=ERROR|reason=mkfs_failed|fs=beamfs|dev=$DEV|mkfs_rc=$MKFS_RC|mkfs_log=$MKFS_LOG"
                exit 1
            fi
            ;;
        *) echo "METADATA|HOST=$(hostname)|SETUP=ERROR|reason=unknown_fs|fs=$FS"; exit 1 ;;
    esac

    if [ "$FS" = "squashfs" ]; then
        sudo mount -t squashfs -o loop,ro "$DEV" "$MNT" 2>/dev/null
    else
        sudo mount "$DEV" "$MNT" 2>/dev/null
    fi
    if ! mountpoint -q "$MNT"; then
        echo "METADATA|HOST=$(hostname)|SETUP=ERROR|reason=mount_failed|fs=$FS|dev=$DEV"
        exit 1
    fi

    if [ "$FS" != "squashfs" ]; then
        sudo mkdir -p "$SUBDIR"
        for i in 1 2 3; do
            sudo bash -c "head -c 4096 /dev/urandom > $SUBDIR/file-$i.bin"
        done
        sudo sync
    fi

    HASH_PRE=$(find "$MNT" -type f -exec sha256sum {} \; 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
    echo "METADATA|HOST=$(hostname)|SETUP=OK|fs=$FS|dev=$DEV|mnt=$MNT|hash_pre=$HASH_PRE"
    ;;

metadata_inject)
    TS_TAG="$ARG2"
    FS="$ARG3"
    VD="$ARG4"
    BLOCK="$ARG5"
    PROB_VAL="$ARG6"
    DEV="/dev/$VD"
    MNT="/mnt/meta-$FS-$TS_TAG"

    # Observation factuelle : si pas monte avant cet inject, c'est que
    # le FS a sature lors d'une iter precedente. On ne peut pas
    # ajouter une corruption a un FS qui n'est plus accessible. On
    # emet une observation explicite (pas une erreur) pour que le
    # bench puisse continuer et l'analyste comprenne le data point.
    if ! mountpoint -q "$MNT"; then
        echo "METADATA|HOST=$(hostname)|INJECT=SKIP|reason=saturation_reached_no_remount|mnt=$MNT"
        exit 0
    fi

    ensure_modules
    if ! sudo test -d "${INJECTOR_DBG}"; then
        echo "METADATA|HOST=$(hostname)|INJECT=SKIP|reason=${INJECTOR}_unavailable"
        exit 0
    fi

    DEV_MAJ=$((0x$(stat -c '%t' $DEV)))
    DEV_MIN=$((0x$(stat -c '%T' $DEV)))
    DEV_NUM=$(( (DEV_MAJ << 20) | DEV_MIN ))

    echo 0 | sudo tee ${INJECTOR_DBG}/enabled  >/dev/null
    echo 0 | sudo tee ${INJECTOR_DBG}/hook_blk >/dev/null

    CALL_B=$(sudo cat ${INJECTOR_DBG}/call_count)
    FLIP_B=$(sudo cat ${INJECTOR_DBG}/${FLIP_COUNT_KEY})

    echo $DEV_NUM    | sudo tee ${INJECTOR_DBG}/target_dev   >/dev/null
    echo $BLOCK      | sudo tee ${INJECTOR_DBG}/target_block >/dev/null
    echo $PROB_VAL   | sudo tee ${INJECTOR_DBG}/probability  >/dev/null
    echo 1           | sudo tee ${INJECTOR_DBG}/inject_on_read >/dev/null
    echo 1           | sudo tee ${INJECTOR_DBG}/hook_blk     >/dev/null
    echo 1           | sudo tee ${INJECTOR_DBG}/enabled      >/dev/null

    # Force re-read of metadata: umount + drop caches + remount + traverse
    sudo umount "$MNT" 2>/dev/null
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null

    if [ "$FS" = "squashfs" ]; then
        sudo mount -t squashfs -o loop,ro "$DEV" "$MNT" 2>/dev/null
    else
        sudo mount "$DEV" "$MNT" 2>/dev/null
    fi
    MOUNT_RC=$?

    if [ $MOUNT_RC -eq 0 ]; then
        sudo find "$MNT" -type f -exec cat {} > /dev/null 2>&1 \;
    fi

    CALL_A=$(sudo cat ${INJECTOR_DBG}/call_count)
    FLIP_A=$(sudo cat ${INJECTOR_DBG}/${FLIP_COUNT_KEY})

    echo 0 | sudo tee ${INJECTOR_DBG}/enabled  >/dev/null
    echo 0 | sudo tee ${INJECTOR_DBG}/hook_blk >/dev/null
    echo 0 | sudo tee ${INJECTOR_DBG}/inject_on_read >/dev/null
    echo 0 | sudo tee ${INJECTOR_DBG}/target_block >/dev/null

    CALL_DELTA=$((CALL_A - CALL_B))
    FLIP_DELTA=$((FLIP_A - FLIP_B))

    echo "METADATA|HOST=$(hostname)|INJECT=OK|fs=$FS|dev=$DEV|target_block=$BLOCK|prob=$PROB_VAL|call_delta=$CALL_DELTA|flip_delta=$FLIP_DELTA|mount_rc=$MOUNT_RC"
    ;;

metadata_verify)
    TS_TAG="$ARG2"
    FS="$ARG3"
    VD="$ARG4"
    DEV="/dev/$VD"
    MNT="/mnt/meta-$FS-$TS_TAG"

    # Read scheme from kernel dmesg of most recent mount (canonical source)
    SCHEME=$(sudo dmesg 2>/dev/null | grep 'beamfs: mounted' | tail -1 \
             | grep -oE 'scheme=[0-9]+' | tail -1 | cut -d= -f2)
    [ -z "$SCHEME" ] && SCHEME=na

    # Parse dmesg for FEC events
    DMESG_RECOVERED=$(sudo dmesg 2>/dev/null | grep -ciE 'beamfs.*corrected by RS|beamfs/inline:.*symbol\(s\) corrected' | tr -d '\n')
    [ -z "$DMESG_RECOVERED" ] && DMESG_RECOVERED=0
    DMESG_UNCORR=$(sudo dmesg 2>/dev/null | grep -ciE 'beamfs/inline:.*uncorrectable|beamfs:.*RS block uncorrectable|beamfs.*-EIO' | tr -d '\n')
    [ -z "$DMESG_UNCORR" ] && DMESG_UNCORR=0
    DMESG_EIO=$(sudo dmesg 2>/dev/null | grep -ciE 'beamfs.*EIO|beamfs.*input/output error' | tr -d '\n')
    [ -z "$DMESG_EIO" ] && DMESG_EIO=0
    DMESG_PANIC=$(sudo dmesg 2>/dev/null | grep -ciE 'kernel panic|Oops:|Call trace' | tr -d '\n')
    [ -z "$DMESG_PANIC" ] && DMESG_PANIC=0

    if mountpoint -q "$MNT"; then
        MOUNTED=1
        READ_OK=$(sudo find "$MNT" -type f 2>/dev/null | wc -l | tr -d '\n')
        HASH_POST=$(find "$MNT" -type f -exec sha256sum {} \; 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
    else
        MOUNTED=0
        READ_OK=0
        HASH_POST=na
    fi

    # Parse RS journal (beamfs only)
    RSJ_NONZERO=0
    if [ "$FS" = "beamfs" ]; then
        RSJ_BYTES=$((64 * 40))
        RSJ_HEX=$(sudo dd if=$DEV bs=1 skip=116 count=$RSJ_BYTES 2>/dev/null | xxd -p -c 40)
        RSJ_NONZERO=$(echo "$RSJ_HEX" | grep -cv '^0\+$' | tr -d '\n')
        [ -z "$RSJ_NONZERO" ] && RSJ_NONZERO=0
    fi

    echo "METADATA|HOST=$(hostname)|VERIFY=OK|fs=$FS|scheme=$SCHEME|mounted=$MOUNTED|read_ok=$READ_OK|hash_post=$HASH_POST|dmesg_rs_corrected=$DMESG_RECOVERED|dmesg_uncorrectable=$DMESG_UNCORR|dmesg_eio=$DMESG_EIO|dmesg_panic=$DMESG_PANIC|rs_journal_new_entries=$RSJ_NONZERO"

    # Cleanup
    sudo umount "$MNT" 2>/dev/null
    sudo rm -rf "$MNT"
    ;;


crash_setup)
    TS_TAG="$ARG2"
    FS="$ARG3"
    VD="$ARG4"
    DEV="/dev/$VD"
    MNT="/mnt/crash-$FS-$TS_TAG"

    if [ ! -b "$DEV" ]; then
        echo "CRASH|HOST=$(hostname)|SETUP=ERROR|reason=device_missing|dev=$DEV"
        exit 1
    fi

    sudo umount "$MNT" 2>/dev/null
    sudo rm -rf "$MNT"
    sudo mkdir -p "$MNT"

    case "$FS" in
        ext4)     sudo mkfs.ext4  -F -q "$DEV" >/dev/null 2>&1 ;;
        ext3)     sudo mkfs.ext3  -F -q "$DEV" >/dev/null 2>&1 ;;
        btrfs)    sudo mkfs.btrfs -f    "$DEV" >/dev/null 2>&1 ;;
        squashfs)
            # squashfs is RO: skip (cannot test crash mid-write on RO FS)
            echo "CRASH|HOST=$(hostname)|SETUP=SKIP|fs=squashfs|reason=read_only_filesystem"
            exit 0
            ;;
        beamfs)
            ensure_modules
            MKFS_LOG=$(sudo mkfs.beamfs $(mkfs_beamfs_args) "$DEV" 2>&1)
            MKFS_RC=$?
            if [ $MKFS_RC -ne 0 ]; then
                echo "CRASH|HOST=$(hostname)|SETUP=ERROR|reason=mkfs_failed|fs=beamfs|dev=$DEV|mkfs_rc=$MKFS_RC|mkfs_log=$MKFS_LOG"
                exit 1
            fi
            ;;
        *) echo "CRASH|HOST=$(hostname)|SETUP=ERROR|reason=unknown_fs|fs=$FS"; exit 1 ;;
    esac

    sudo mount "$DEV" "$MNT" 2>/dev/null
    if ! mountpoint -q "$MNT"; then
        echo "CRASH|HOST=$(hostname)|SETUP=ERROR|reason=mount_failed|fs=$FS|dev=$DEV"
        exit 1
    fi

    # Populate 5 stable files (these are the "before crash" baseline)
    for i in 1 2 3 4 5; do
        sudo bash -c "head -c 4096 /dev/urandom > $MNT/stable-$i.bin"
    done
    sudo sync

    HASH_PRE=$(find "$MNT" -type f -exec sha256sum {} \; 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
    echo "CRASH|HOST=$(hostname)|SETUP=OK|fs=$FS|dev=$DEV|mnt=$MNT|hash_pre=$HASH_PRE"
    ;;

crash_start_writer)
    TS_TAG="$ARG2"
    FS="$ARG3"
    VD="$ARG4"
    MNT="/mnt/crash-$FS-$TS_TAG"

    if [ "$FS" = "squashfs" ]; then
        echo "CRASH|HOST=$(hostname)|WRITER=SKIP|fs=squashfs|reason=read_only_filesystem"
        exit 0
    fi

    if ! mountpoint -q "$MNT"; then
        echo "CRASH|HOST=$(hostname)|WRITER=ERROR|reason=not_mounted|mnt=$MNT"
        exit 1
    fi

    # Start a background writer that loops dd urandom into a file.
    # The bench will virsh-destroy compute01 ~500ms after this returns,
    # so dd is in-flight when power is cut.
    # Start writer in fully-detached background using setsid + nohup-like
    # redirection. Without these, the parent ssh connection blocks waiting
    # for the inherited FDs to close.
    sudo nohup bash -c "
        while true; do
            dd if=/dev/urandom of=$MNT/crash-write.bin bs=4096 count=128 oflag=direct 2>/dev/null
        done
    " </dev/null >/dev/null 2>&1 &
    PID=$!
    disown $PID 2>/dev/null || true
    echo $PID > /tmp/crash-writer-$TS_TAG.pid
    echo "CRASH|HOST=$(hostname)|WRITER=STARTED|fs=$FS|pid=$PID|mnt=$MNT"
    ;;

crash_verify)
    TS_TAG="$ARG2"
    FS="$ARG3"
    VD="$ARG4"
    DEV="/dev/$VD"
    MNT="/mnt/crash-$FS-$TS_TAG"

    if [ "$FS" = "squashfs" ]; then
        echo "CRASH|HOST=$(hostname)|VERIFY=SKIP|fs=squashfs|reason=read_only_filesystem"
        exit 0
    fi

    # Read scheme from dmesg (canonical, applies only to beamfs)
    SCHEME=$(sudo dmesg 2>/dev/null | grep 'beamfs: mounted' | tail -1 \
             | grep -oE 'scheme=[0-9]+' | tail -1 | cut -d= -f2)
    [ -z "$SCHEME" ] && SCHEME=na

    sudo mkdir -p "$MNT"

    # Try mount post-reboot
    if [ "$FS" = "beamfs" ]; then
        ensure_modules
    fi
    sudo mount "$DEV" "$MNT" 2>&1
    MOUNT_RC=$?

    # Parse dmesg for journal replay / EIO / panic events
    DMESG_JOURNAL_REPLAY=$(sudo dmesg 2>/dev/null | grep -ciE 'recovery|journal.*recovered|replay|orphan inode' | tr -d '\n')
    [ -z "$DMESG_JOURNAL_REPLAY" ] && DMESG_JOURNAL_REPLAY=0
    DMESG_EIO=$(sudo dmesg 2>/dev/null | grep -ciE 'EIO|input/output error' | tr -d '\n')
    [ -z "$DMESG_EIO" ] && DMESG_EIO=0
    DMESG_FSCK_NEEDED=$(sudo dmesg 2>/dev/null | grep -ciE 'fsck.*needed|fsck.*recommended|run.*fsck|forced.*recovery' | tr -d '\n')
    [ -z "$DMESG_FSCK_NEEDED" ] && DMESG_FSCK_NEEDED=0
    DMESG_PANIC=$(sudo dmesg 2>/dev/null | grep -ciE 'kernel panic|Oops:|Call trace' | tr -d '\n')
    [ -z "$DMESG_PANIC" ] && DMESG_PANIC=0

    if mountpoint -q "$MNT"; then
        MOUNTED=1
        STABLE_OK=$(find "$MNT" -name 'stable-*.bin' -type f 2>/dev/null | wc -l | tr -d '\n')
        HASH_STABLE=$(find "$MNT" -name 'stable-*.bin' -type f -exec sha256sum {} \; 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
        CRASH_FILE_PRESENT=0
        [ -f "$MNT/crash-write.bin" ] && CRASH_FILE_PRESENT=1
    else
        MOUNTED=0
        STABLE_OK=0
        HASH_STABLE=na
        CRASH_FILE_PRESENT=0
    fi

    echo "CRASH|HOST=$(hostname)|VERIFY=OK|fs=$FS|scheme=$SCHEME|mount_rc=$MOUNT_RC|mounted=$MOUNTED|stable_files_ok=$STABLE_OK|hash_stable=$HASH_STABLE|crash_file_present=$CRASH_FILE_PRESENT|dmesg_journal_replay=$DMESG_JOURNAL_REPLAY|dmesg_eio=$DMESG_EIO|dmesg_fsck_needed=$DMESG_FSCK_NEEDED|dmesg_panic=$DMESG_PANIC"

    sudo umount "$MNT" 2>/dev/null
    sudo rm -rf "$MNT"
    ;;

fsck_check)
    TS_TAG="$ARG2"
    FS="$ARG3"
    VD="$ARG4"
    DEV="/dev/$VD"

    if [ "$FS" = "squashfs" ]; then
        echo "FSCK|HOST=$(hostname)|CHECK=SKIP|fs=squashfs|reason=read_only_filesystem_no_fsck"
        exit 0
    fi

    case "$FS" in
        ext4|ext3)
            FSCK_BIN="fsck.$FS"
            FSCK_ARGS="-f -y"
            ;;
        btrfs)
            FSCK_BIN="btrfs"
            FSCK_ARGS="check"
            ;;
        beamfs)
            # fsck.beamfs landed 2026-08-25 (beamfs.git e73926d): five
            # passes, indirection-tree walk, RS encoder. --repair is what
            # Test D exercises: check-only would only report, and the
            # point here is post-FS_PANIC recovery.
            FSCK_BIN="fsck.beamfs"
            FSCK_ARGS="--repair --verbose"
            ;;
        *) echo "FSCK|HOST=$(hostname)|CHECK=ERROR|reason=unknown_fs|fs=$FS"; exit 1 ;;
    esac

    if ! command -v "$FSCK_BIN" >/dev/null 2>&1; then
        echo "FSCK|HOST=$(hostname)|CHECK=ERROR|fs=$FS|reason=fsck_binary_missing|bin=$FSCK_BIN"
        exit 1
    fi

    # Make sure the fs is unmounted before fsck
    sudo umount "/dev/$VD" 2>/dev/null || true

    # Capture the fsck exit code, not the exit code of the pipeline tail.
    # $? after a pipe reports tr(1), which is always 0, so every fsck run
    # previously recorded fsck_rc=0 regardless of what fsck actually
    # returned -- including the fsck(8) codes Test D exists to check
    # (1 = errors corrected, 4 = errors left uncorrected).
    FSCK_RAW=$(sudo "$FSCK_BIN" $FSCK_ARGS "$DEV" 2>&1)
    FSCK_RC=$?
    FSCK_OUT=$(printf '%s' "$FSCK_RAW" | head -20 | tr '\n' ';')

    echo "FSCK|HOST=$(hostname)|CHECK=OK|fs=$FS|dev=$DEV|fsck_rc=$FSCK_RC|fsck_summary=$FSCK_OUT"
    ;;

tindirect_setup)
    # Args: ARG2=tag
    # Build a 4 GiB sparse loop-backed beamfs volume on tmpfs (/tmp).
    # Sparse-mounted tmpfs only allocates pages on actual write, so the
    # apparent 4 GiB volume costs only a few MiB of RAM for the metadata
    # blocks + sparse data writes.
    TS_TAG="$ARG2"
    IMG="/tmp/tindirect-$TS_TAG.img"
    MNT="/mnt/tindirect-$TS_TAG"
    ensure_modules
    # Build sparse 4 GiB backing file. truncate -s creates a sparse file
    # in O(1) without writing zero bytes; the actual disk usage stays
    # near zero until pages are written.
    sudo rm -f "$IMG"
    sudo truncate -s 4G "$IMG"
    LOOP=$(sudo losetup --find --show "$IMG" 2>&1)
    if [ -z "$LOOP" ] || [ ! -b "$LOOP" ]; then
        echo "TINDIRECT|HOST=$(hostname)|SETUP=ERROR|reason=losetup_failed|out=$LOOP"
        exit 1
    fi
    MKFS_OUT=$(sudo mkfs.beamfs -N 8192 "$LOOP" 2>&1 | tail -5 | tr '
' ';')
    if [ $? -ne 0 ]; then
        sudo losetup -d "$LOOP" 2>/dev/null || true
        echo "TINDIRECT|HOST=$(hostname)|SETUP=ERROR|reason=mkfs_failed|out=$MKFS_OUT"
        exit 1
    fi
    sudo mkdir -p "$MNT"
    if ! sudo mount -t beamfs "$LOOP" "$MNT" 2>&1; then
        sudo losetup -d "$LOOP" 2>/dev/null || true
        echo "TINDIRECT|HOST=$(hostname)|SETUP=ERROR|reason=mount_failed"
        exit 1
    fi
    # Persist loop dev + mountpoint for later phases.
    echo "$LOOP" | sudo tee "/tmp/tindirect-$TS_TAG.loop" >/dev/null
    echo "$MNT"  | sudo tee "/tmp/tindirect-$TS_TAG.mnt"  >/dev/null
    echo "TINDIRECT|HOST=$(hostname)|SETUP=OK|tag=$TS_TAG|loop=$LOOP|mnt=$MNT|mkfs=$MKFS_OUT"
    ;;

tindirect_test)
    # Args: ARG2=tag, ARG3=iblock
    # Sparse-write 4 disk blocks (16 KiB) at the given iblock,
    # compute sha256 of the 16 KiB slice on the still-mounted FS
    # (page cache reads), then drop_caches + umount + mount, then
    # recompute sha256 from cold reads. Emit MATCH or MISMATCH.
    TS_TAG="$ARG2"
    IBLOCK="$ARG3"
    LOOP=$(sudo cat "/tmp/tindirect-$TS_TAG.loop" 2>/dev/null)
    MNT=$(sudo cat "/tmp/tindirect-$TS_TAG.mnt" 2>/dev/null)
    if [ -z "$LOOP" ] || [ -z "$MNT" ]; then
        echo "TINDIRECT|HOST=$(hostname)|VERDICT=ERROR|reason=missing_state_for_tag_$TS_TAG"
        exit 1
    fi
    if ! mountpoint -q "$MNT"; then
        echo "TINDIRECT|HOST=$(hostname)|VERDICT=ERROR|reason=not_mounted"
        exit 1
    fi
    F="$MNT/test-$IBLOCK.bin"
    # 16 KiB slice = 4 disk blocks at iblock N.
    # `dd seek=$IBLOCK bs=4096 count=4 if=/dev/urandom` writes 4 blocks
    # at iblock N..N+3, leaving everything before as HOLE.
    DD_OUT=$(sudo dd if=/dev/urandom of="$F" bs=4096 seek="$IBLOCK" count=4 conv=notrunc status=none 2>&1)
    DD_RC=$?
    if [ $DD_RC -ne 0 ]; then
        echo "TINDIRECT|HOST=$(hostname)|VERDICT=ERROR|reason=dd_write_rc=$DD_RC|out=$DD_OUT"
        exit 1
    fi
    sudo sync
    # sha256 of the 16 KiB slice at offset iblock*4096 (warm cache).
    SLICE_OFFSET=$(( IBLOCK * 4096 ))
    SHA_WARM=$(sudo dd if="$F" bs=4096 skip="$IBLOCK" count=4 status=none 2>/dev/null | sha256sum | awk '{print $1}')
    if [ -z "$SHA_WARM" ]; then
        echo "TINDIRECT|HOST=$(hostname)|VERDICT=ERROR|reason=sha_warm_empty"
        exit 1
    fi
    # Cold cycle: drop_caches + umount + mount.
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    if ! sudo umount "$MNT" 2>&1; then
        echo "TINDIRECT|HOST=$(hostname)|VERDICT=ERROR|reason=umount_failed|sha_warm=$SHA_WARM"
        exit 1
    fi
    if ! sudo mount -t beamfs "$LOOP" "$MNT" 2>&1; then
        echo "TINDIRECT|HOST=$(hostname)|VERDICT=ERROR|reason=remount_failed|sha_warm=$SHA_WARM"
        exit 1
    fi
    SHA_COLD=$(sudo dd if="$F" bs=4096 skip="$IBLOCK" count=4 status=none 2>/dev/null | sha256sum | awk '{print $1}')
    DMESG_TAIL=$(sudo dmesg | tail -20 | grep -cE "beyond|EOPNOTSUPP|EUCLEAN|BUG|Oops|WARN" 2>/dev/null | head -1 | tr -d "\n")
    if [ "$SHA_WARM" = "$SHA_COLD" ]; then
        echo "TINDIRECT|HOST=$(hostname)|VERDICT=MATCH|iblock=$IBLOCK|offset=$SLICE_OFFSET|sha_warm=$SHA_WARM|sha_cold=$SHA_COLD|dmesg_anomaly=$DMESG_TAIL"
    else
        echo "TINDIRECT|HOST=$(hostname)|VERDICT=MISMATCH|iblock=$IBLOCK|offset=$SLICE_OFFSET|sha_warm=$SHA_WARM|sha_cold=$SHA_COLD|dmesg_anomaly=$DMESG_TAIL"
    fi
    ;;

tindirect_cleanup)
    # Args: ARG2=tag
    TS_TAG="$ARG2"
    LOOP=$(sudo cat "/tmp/tindirect-$TS_TAG.loop" 2>/dev/null)
    MNT=$(sudo cat "/tmp/tindirect-$TS_TAG.mnt" 2>/dev/null)
    IMG="/tmp/tindirect-$TS_TAG.img"
    if [ -n "$MNT" ] && mountpoint -q "$MNT"; then
        sudo umount "$MNT" 2>/dev/null || true
        sudo rmdir "$MNT" 2>/dev/null || true
    fi
    if [ -n "$LOOP" ] && [ -b "$LOOP" ]; then
        sudo losetup -d "$LOOP" 2>/dev/null || true
    fi
    sudo rm -f "$IMG" "/tmp/tindirect-$TS_TAG.loop" "/tmp/tindirect-$TS_TAG.mnt"
    echo "TINDIRECT|HOST=$(hostname)|CLEANUP=OK|tag=$TS_TAG"
    ;;

*)
    echo "ERROR: unknown action $ACTION" >&2
    echo "Valid actions: discover_devices, discover_cluster, setup, attack, verify," >&2
    echo "               cluster_setup, cluster_attack, cluster_verify, bootstrap_data,"
    echo "               metadata_setup, metadata_inject, metadata_verify,"
    echo "               crash_setup, crash_start_writer, crash_verify, fsck_check," >&2
    echo "               bitrot_setup, bitrot_inject, bitrot_verify," >&2
    echo "               tindirect_setup, tindirect_test, tindirect_cleanup" >&2
    exit 2
    ;;

esac
