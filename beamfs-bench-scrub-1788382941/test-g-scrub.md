# Test G -- scrubber under dose

- deployment: medical-linac-vault
- symbols injected: 6
- samples: 6

| sweep | s | blocks | corrected | uncorr | interval | factor | wear |
|---|---|---|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 0 | 100 | 1 | 0 |
| 1 | 186 | 223 | 1 | 0 | 50 | 2 | 128 |
| 2 | 350 | 395 | 1 | 0 | 62 | 1 | 255 |
| 3 | 523 | 595 | 1 | 0 | 74 | 1 | 384 |
| 4 | 701 | 810 | 1 | 0 | 86 | 1 | 512 |
| 5 | 880 | 991 | 1 | 0 | 98 | 1 | 640 |

## Observations

- corrections per sweep: 0.20
- peak rate factor: 2
- final rate factor: 1
- digest before: 9169068c1e1b0320c1a521124ed271df
- digest after:  9169068c1e1b0320c1a521124ed271df
- data identical: true

## Reading these numbers

Corrections per sweep near the count of damaged blocks means each
was repaired once. A figure that stays near the damaged-block count
sweep after sweep means repairs are not reaching the disk: the same
blocks are being found again, and their margin is being consumed
rather than restored.

A peak factor above 1 means the rate responded to what was found. A
final factor of 1 means it settled once there was nothing left to
find. Peak 1 under a non-zero injection means the loop did not
engage, which is a defect in the loop rather than in the volume.

Whether these values are acceptable for a given deployment is a
question for synthesis, not for this file.
