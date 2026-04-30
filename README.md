# beamfs-bench

Unified bench harness for beamfs resilience testing under RadFI live
fault injection. Replaces the legacy bash harness (`bin/Tir-*.sh`,
~1176 lines) with a single Rust binary.

## Build

cd beamfs-bench
cargo build --release
./target/release/beamfs-bench version


## Subcommands

| Subcommand | Status | Replaces |
|---|---|---|
| `version` | 0.1.0 | (new) |
| `multifs` | not yet implemented | `bin/Tir-multifs.sh` |
| `analyse` | not yet implemented | `bin/Tir-analyse-multifs.sh` |
| `bench` | not yet implemented | `bin/Tir.sh` / `bin/hpc-benchmark-beamfs.sh` |
| `metadata` | not yet implemented (new) | — |
| `crash` | not yet implemented (new) | — |
| `bitrot` | not yet implemented (new) | — |
| `fsck` | not yet implemented (new) | — |

## Migration plan

See `~/git/beamfs/context/TODO.md` (TODO 2) in the private
beamfs-devel repository.

## License

GPL-2.0-only — same as the BEAMFS kernel module.
