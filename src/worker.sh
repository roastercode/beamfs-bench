#!/bin/bash
# beamfs-bench multifs worker — embedded as include_str! in the Rust binary.
# Deployed to /tmp/beamfs-bench-worker.sh on the master VM via scp, then
# invoked once per (action, fs, vd, prob) tuple. Format-identical to the
# legacy Tir-multifs.sh worker so the run output remains diff-compatible
# with reference run Tir-multifs-20260430-141008.
set -u

# Args: $1 = action (setup|attack|verify), $2 = FS, $3 = vd, $4 = prob (for attack)
ACTION="$1"
FS="$2"
VD="$3"
PROB="${4:-0}"
DEV="/dev/$VD"
MNT="/mnt/test-$FS"

ensure_modules() {
    sudo depmod -a 2>/dev/null
    if [ "$FS" = "btrfs" ]; then
        sudo modprobe btrfs 2>/dev/null || true
    fi
    if ! lsmod | grep -q '^radfi'; then
        sudo /sbin/insmod /lib/modules/$(uname -r)/updates/radfi.ko 2>/dev/null || true
    fi
}

case "$ACTION" in

setup)
    ensure_modules
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

esac
