#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
sat_check.py -- verify a saturation event against Theorem v2.2.

Reads the JSON produced by decode_raf_journal.py and checks the four
things the theorem asserts, printing one SAT| line per finding so the
orchestrator parses them like every other worker output.

The subblock is not a field of its own: a data-block event encodes it
arithmetically as block_no = phys * 16 + subblock. That is worth
knowing before reading a journal dump, since re_block_no does not hold
a block number on those entries despite its name.
"""
import json
import sys

SUBBLOCKS_PER_BLOCK = 16
FLAG_ENTROPY_VALID = 1 << 0
FLAG_UNCORRECTABLE = 1 << 1


def main(argv):
    if len(argv) != 4:
        print("SAT|JOURNAL_ERROR=usage", flush=True)
        return 0
    path, phys, sub = argv[1], int(argv[2]), int(argv[3])
    want = phys * SUBBLOCKS_PER_BLOCK + sub

    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"SAT|JOURNAL_ERROR={exc}", flush=True)
        return 0

    events = doc.get("events", doc if isinstance(doc, list) else [])
    live = [e for e in events if not e.get("is_empty")]
    print(f"SAT|JOURNAL_ENTRIES={len(live)}")
    print(f"SAT|JOURNAL_WANT_BLOCK_NO={want}")

    hit = [e for e in live if e.get("block_no") == want]
    if not hit:
        seen = ",".join(str(e.get("block_no")) for e in live[:5])
        print(f"SAT|JOURNAL_MATCH=0|SEEN={seen}")
        return 0

    ev = hit[0]
    flags = ev.get("flags", 0)

    # The decoder names the field "symbols", and reports entropy_valid
    # and crc_ok in decoded form. Both are checked: format-v4.md 6.5
    # requires symbols == 0 and ENTROPY_VALID cleared whenever
    # UNCORRECTABLE is set, and an entry whose own CRC fails would say
    # nothing reliable about either.
    print(
        f"SAT|JOURNAL_MATCH=1"
        f"|UNCORRECTABLE={1 if flags & FLAG_UNCORRECTABLE else 0}"
        f"|SYMBOLS={ev.get('symbols')}"
        f"|ENTROPY_VALID={1 if flags & FLAG_ENTROPY_VALID else 0}"
        f"|CRC_OK={1 if ev.get('crc_ok') else 0}"
        f"|SENTINELS_OK={1 if ev.get('sentinels_ok') else 0}"
    )

    # One line the orchestrator can act on without re-deriving the
    # contract: every clause of Theorem v2.2 that the journal can
    # witness, in one verdict.
    ok = (
        bool(flags & FLAG_UNCORRECTABLE)
        and ev.get("symbols") == 0
        and not flags & FLAG_ENTROPY_VALID
        and ev.get("crc_ok")
    )
    print(f"SAT|THEOREM_V2_2={'PASS' if ok else 'FAIL'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
