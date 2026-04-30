#!/bin/bash
# beamfs-bench multifs/analyse worker — embedded as include_str! in the Rust binary.
#
# Deployed to /tmp/beamfs-bench-worker.sh on the master VM (and on each compute
# for cluster scope) via scp, then invoked once per (action, ...) tuple.
#
# Actions (read-only, safe to call before any destructive op):
#   discover_devices          : list /dev/vd[c-z] with size + mountpoint + fstype
#   discover_cluster          : show /data state + radfi loaded? + kernel version
#
# Actions (multifs scope, master only, single-FS targeted):
#   setup  <fs> <vd>          : format + populate one FS on /dev/<vd>
#   attack <fs> <vd> <prob>   : arm RadFI on <vd> + trigger I/O on dir-B/file-B2.bin
#   verify <fs> <vd>          : recompute hashes + classify verdict
#
# Actions (cluster scope, master + all 3 computes, BEAMFS on /data):
#   cluster_setup  <ts>       : create /data/beamfs-bench-<ts>/ test layout
#   cluster_attack <ts> <prob>: arm RadFI on /dev/vdb + I/O on /data/beamfs-bench-<ts>/
#   cluster_verify <ts>       : check integrity + cleanup
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

ACTION="${1:-}"
ARG2="${2:-}"
ARG3="${3:-}"
ARG4="${4:-}"

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
    echo "RADFI_LOADED=$(lsmod | grep -q '^radfi' && echo yes || echo no)"
    echo "BEAMFS_LOADED=$(lsmod | grep -q '^beamfs' && echo yes || echo no)"
    echo "RADFI_KO_PRESENT=$([ -f /lib/modules/$(uname -r)/updates/radfi.ko ] && echo yes || echo no)"
    echo "PERF_AVAILABLE=$(command -v perf >/dev/null 2>&1 && echo yes || echo no)"
    echo "FTRACE_DEBUGFS=$(sudo test -d /sys/kernel/debug/tracing && echo yes || echo no)"
    exit 0
fi

# ============================================================
# Helper : ensure radfi.ko + beamfs.ko + (btrfs.ko if needed) loaded.
# ============================================================
ensure_modules() {
    local fs="${1:-}"
    sudo depmod -a 2>/dev/null
    if [ "$fs" = "btrfs" ]; then
        sudo modprobe btrfs 2>/dev/null || true
    fi
    if ! lsmod | grep -q '^radfi'; then
        sudo /sbin/insmod /lib/modules/$(uname -r)/updates/radfi.ko 2>/dev/null || true
    fi
}

# ============================================================
# multifs scope : setup / attack / verify (master-only, USB targets)
# Args: $1=action $2=fs $3=vd $4=prob
# ============================================================
case "$ACTION" in

setup)
    FS="$ARG2"
    VD="$ARG3"
    DEV="/dev/$VD"
    MNT="/mnt/test-$FS"

    ensure_modules "$FS"
    sudo umount $MNT 2>/dev/null || true
    sudo rm -rf $MNT
    sudo mkdir -p $MNT

    case "$FS" in
        ext4)     sudo mkfs.ext4 -F -q $DEV ;;
        ext3)     sudo mkfs.ext3 -F -q $DEV ;;
        btrfs)    sudo mkfs.btrfs -f $DEV >/dev/null ;;
        squashfs) ;;
        beamfs)   sudo mkfs.beamfs -s inline $DEV >/dev/null ;;
        *)        echo "ERROR: unknown FS $FS" >&2; exit 1 ;;
    esac

    if [ "$FS" != "squashfs" ]; then
        sudo mount -t $FS $DEV $MNT
        for letter in A B C; do
            sudo mkdir -p $MNT/dir-$letter
            for n in 1 2 3; do
                sudo bash -c "head -c 3072 /dev/urandom > $MNT/dir-$letter/file-${letter}${n}.bin"
            done
            sudo bash -c "cd $MNT/dir-$letter && sha256sum file-${letter}1.bin file-${letter}2.bin file-${letter}3.bin > HASHES.sha256"
        done
        sudo sync

        TARGET_FILE=$MNT/dir-B/file-B2.bin
        if command -v filefrag >/dev/null 2>&1 && [ "$FS" != "beamfs" ]; then
            TARGET_BLOCK=$(sudo filefrag -b4096 $TARGET_FILE 2>/dev/null | awk '/^ +0:/ {gsub(/[.:]/, "", $4); print $4; exit}')
        else
            TARGET_BLOCK=0
        fi
        [ -z "$TARGET_BLOCK" ] && TARGET_BLOCK=0

        echo "FS=$FS|VD=$VD|MNT=$MNT|TARGET_FILE=$TARGET_FILE|TARGET_BLOCK=$TARGET_BLOCK"
        sudo find $MNT -type f -exec sha256sum {} \; | sort > /tmp/pre-attack-$FS.txt
    else
        TMPSRC=/tmp/squashfs-src-$$
        sudo rm -rf $TMPSRC
        sudo mkdir -p $TMPSRC
        for letter in A B C; do
            sudo mkdir -p $TMPSRC/dir-$letter
            for n in 1 2 3; do
                sudo bash -c "head -c 3072 /dev/urandom > $TMPSRC/dir-$letter/file-${letter}${n}.bin"
            done
            sudo bash -c "cd $TMPSRC/dir-$letter && sha256sum file-${letter}1.bin file-${letter}2.bin file-${letter}3.bin > HASHES.sha256"
        done
        sudo mksquashfs $TMPSRC /tmp/sqimg.sqfs -noappend -comp xz >/dev/null 2>&1
        sudo dd if=/tmp/sqimg.sqfs of=$DEV bs=1M conv=notrunc status=none
        sudo rm -rf $TMPSRC /tmp/sqimg.sqfs
        sudo mount -t squashfs -o ro $DEV $MNT

        TARGET_FILE=$MNT/dir-B/file-B2.bin
        echo "FS=squashfs|VD=$VD|MNT=$MNT|TARGET_FILE=$TARGET_FILE|TARGET_BLOCK=0"
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

    echo 0 | sudo tee /sys/kernel/debug/radfi/enabled  >/dev/null
    echo 0 | sudo tee /sys/kernel/debug/radfi/hook_blk >/dev/null

    CALL_B=$(sudo cat /sys/kernel/debug/radfi/call_count)
    FLIP_B=$(sudo cat /sys/kernel/debug/radfi/flip_count)

    echo $DEV_NUM | sudo tee /sys/kernel/debug/radfi/target_dev   >/dev/null
    echo 0        | sudo tee /sys/kernel/debug/radfi/target_block >/dev/null
    echo $PROB    | sudo tee /sys/kernel/debug/radfi/probability  >/dev/null
    echo 1        | sudo tee /sys/kernel/debug/radfi/hook_blk     >/dev/null
    echo 1        | sudo tee /sys/kernel/debug/radfi/enabled      >/dev/null

    if [ "$FS" = "squashfs" ]; then
        sudo umount $MNT 2>/dev/null
        echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
        sudo mount -t squashfs -o ro $DEV $MNT 2>/dev/null || true
        sudo cat $MNT/dir-B/file-B2.bin > /dev/null 2>&1
        sudo cat $MNT/dir-A/file-A1.bin > /dev/null 2>&1
        sudo cat $MNT/dir-C/file-C3.bin > /dev/null 2>&1
    else
        sudo bash -c "head -c 3072 /dev/urandom > $MNT/dir-B/file-B2.bin"
        sudo sync
        echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
        sudo cat $MNT/dir-B/file-B2.bin > /dev/null
        sudo cat $MNT/dir-A/file-A1.bin > /dev/null
        sudo cat $MNT/dir-C/file-C3.bin > /dev/null
    fi

    CALL_A=$(sudo cat /sys/kernel/debug/radfi/call_count)
    FLIP_A=$(sudo cat /sys/kernel/debug/radfi/flip_count)

    echo 0 | sudo tee /sys/kernel/debug/radfi/enabled  >/dev/null
    echo 0 | sudo tee /sys/kernel/debug/radfi/hook_blk >/dev/null

    CALL_DELTA=$((CALL_A - CALL_B))
    FLIP_DELTA=$((FLIP_A - FLIP_B))

    echo "FS=$FS|PROB=$PROB|CALL_DELTA=$CALL_DELTA|FLIP_DELTA=$FLIP_DELTA"
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

    if [ "$FS" != "squashfs" ]; then
        sudo umount $MNT 2>/dev/null
        sudo mount -t $FS $DEV $MNT 2>/dev/null
        REMOUNT_OK=$?
    else
        sudo umount $MNT 2>/dev/null
        sudo mount -t squashfs -o ro $DEV $MNT 2>/dev/null
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

    if [ $DIFFS_REMOUNT -eq 0 ]; then
        VERDICT="RECOVERED"
        DETAILS="all 12 files match pre-attack after umount/remount"
    elif [ $DIFFS_REMOUNT -lt 6 ]; then
        N_FILES_CHANGED=$((DIFFS_REMOUNT / 2))
        VERDICT="CORRUPTED_DATA"
        DETAILS="$N_FILES_CHANGED file(s) changed hash post-attack"
    else
        N_FILES_CHANGED=$((DIFFS_REMOUNT / 2))
        VERDICT="CORRUPTED_HEAVY"
        DETAILS="$N_FILES_CHANGED file(s) changed (heavy corruption)"
    fi

    echo "FS=$FS|VERDICT=$VERDICT|DIFFS_PRE_POST=$DIFFS|DIFFS_PRE_REMOUNT=$DIFFS_REMOUNT|details=$DETAILS"
    ;;

# ============================================================
# Cluster scope : run on each node (master + computes), targets BEAMFS on /data.
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
            sudo bash -c "head -c 3072 /dev/urandom > $SUBDIR/dir-$letter/file-${letter}${n}.bin"
        done
        sudo bash -c "cd $SUBDIR/dir-$letter && sha256sum file-${letter}1.bin file-${letter}2.bin file-${letter}3.bin > HASHES.sha256"
    done
    sudo sync
    sudo find "$SUBDIR" -type f -exec sha256sum {} \; 2>/dev/null | sort > "/tmp/pre-cluster-$TS_TAG.txt"
    echo "CLUSTER|HOST=$(hostname)|SETUP=OK|SUBDIR=$SUBDIR|FILES=12"
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
    # Ensure radfi.ko loaded before testing debugfs presence
    ensure_modules
    if ! sudo test -d /sys/kernel/debug/radfi; then
        echo "CLUSTER|HOST=$(hostname)|ATTACK=SKIP|reason=radfi_debugfs_unavailable"
        exit 0
    fi

    DEV_MAJ=$((0x$(stat -c '%t' $DEV_VDB)))
    DEV_MIN=$((0x$(stat -c '%T' $DEV_VDB)))
    DEV_NUM=$(( (DEV_MAJ << 20) | DEV_MIN ))

    echo 0 | sudo tee /sys/kernel/debug/radfi/enabled  >/dev/null
    echo 0 | sudo tee /sys/kernel/debug/radfi/hook_blk >/dev/null

    CALL_B=$(sudo cat /sys/kernel/debug/radfi/call_count)
    FLIP_B=$(sudo cat /sys/kernel/debug/radfi/flip_count)

    echo $DEV_NUM   | sudo tee /sys/kernel/debug/radfi/target_dev   >/dev/null
    echo 0          | sudo tee /sys/kernel/debug/radfi/target_block >/dev/null
    echo $PROB_VAL  | sudo tee /sys/kernel/debug/radfi/probability  >/dev/null
    echo 1          | sudo tee /sys/kernel/debug/radfi/hook_blk     >/dev/null
    echo 1          | sudo tee /sys/kernel/debug/radfi/enabled      >/dev/null

    sudo bash -c "head -c 3072 /dev/urandom > $SUBDIR/dir-B/file-B2.bin" 2>/dev/null
    sudo sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    sudo cat $SUBDIR/dir-B/file-B2.bin > /dev/null 2>&1
    sudo cat $SUBDIR/dir-A/file-A1.bin > /dev/null 2>&1
    sudo cat $SUBDIR/dir-C/file-C3.bin > /dev/null 2>&1

    CALL_A=$(sudo cat /sys/kernel/debug/radfi/call_count)
    FLIP_A=$(sudo cat /sys/kernel/debug/radfi/flip_count)

    echo 0 | sudo tee /sys/kernel/debug/radfi/enabled  >/dev/null
    echo 0 | sudo tee /sys/kernel/debug/radfi/hook_blk >/dev/null

    CALL_DELTA=$((CALL_A - CALL_B))
    FLIP_DELTA=$((FLIP_A - FLIP_B))

    echo "CLUSTER|HOST=$(hostname)|PROB=$PROB_VAL|CALL_DELTA=$CALL_DELTA|FLIP_DELTA=$FLIP_DELTA"
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

    if [ $DIFFS -eq 0 ]; then
        VERDICT="RECOVERED"
        DETAILS="all 12 files match pre-attack on /data"
    elif [ $DIFFS -lt 6 ]; then
        N=$((DIFFS / 2))
        VERDICT="CORRUPTED_DATA"
        DETAILS="$N file(s) changed hash"
    else
        N=$((DIFFS / 2))
        VERDICT="CORRUPTED_HEAVY"
        DETAILS="$N file(s) changed (heavy corruption)"
    fi

    sudo rm -rf "$SUBDIR" 2>/dev/null || true
    sudo rm -f "$PRE_FILE" "$POST_FILE" 2>/dev/null || true

    echo "CLUSTER|HOST=$(hostname)|VERDICT=$VERDICT|DIFFS=$DIFFS|details=$DETAILS"
    ;;

*)
    echo "ERROR: unknown action $ACTION" >&2
    echo "Valid actions: discover_devices, discover_cluster, setup, attack, verify," >&2
    echo "               cluster_setup, cluster_attack, cluster_verify" >&2
    exit 2
    ;;

esac
