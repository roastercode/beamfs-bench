# beamfs-bench code analysis gate

`src/code_analysis.rs` is phase 0.0bis of `beamfs-bench full`. It runs
before the lab is touched, on the whole module and on this bench, and
every check of it has to run and pass: a tool that is not installed, or
a kernel tree or a layer that is not found, fails the gate as a finding
does.

| Check | What runs | Needs |
|-------|-----------|-------|
| checkpatch_strict | checkpatch with spdxcheck, on the module sources laid out as one patch | the kernel repository; a python3 that imports ply and git |
| sparse | sparse -Wsparse-all -Wbitwise on each module source; an error fails | sparse; a kernel tree |
| clang_werror | clang -fsyntax-only -Wall -Wextra on each module source; a warning fails | clang; a kernel tree |
| gpg_verify | git verify-commit on the last 20 commits of beamfs and of the bench | gpg and the keys of the signers |
| cargo_clippy_pedantic | cargo clippy --all-targets --all-features -- -D warnings on the bench | clippy |
| kernel_doc | kernel-doc -none on each module source and header | the kernel repository |
| naming_r17 | the retired names of the project, in the sources and the documentation | |
| emdash_r16 | typographic dashes, arrows and quotes, in the same files | |
| lockstep_r9 | the module sources against the copy in the layer, byte for byte | the layer |

checkpatch and kernel-doc come from a worktree of
`BEAMFS_BENCH_LINUX_BASE` (origin/master by default) of
`BEAMFS_BENCH_LINUX_REPO` (`~/git/linux` by default). sparse and clang
read the kernel tree the layer builds, with its generated headers, or
`/usr/src/linux` when there is none.

Until 0.16.1 a tool that was not installed was reported SKIP and the
pipeline went on, and the gate listed tools that never ran in it:
smatch, coccinelle, gcc -fanalyzer, gitleaks and cargo audit in its
first tier, and a second and a third tier of stubs.

## Not in the gate

smatch, coccinelle, sparse and kernel-doc through Kbuild, checkstack,
the builds and the documentation build run in `beamfs-bench upstream`,
on the series: that is the check of kernel.org. gcc -fanalyzer,
gitleaks, cargo audit, cppcheck, flawfinder, semgrep, cargo geiger, the
MISRA addon, Frama-C, scan-build and lcov are run nowhere.

## checkpatch, since 0.15.0

The Tier 1 checkpatch is the one of the kernel repository named by
`BEAMFS_BENCH_LINUX_REPO` (`~/git/linux` by default), run on the module
sources laid out as one new-file patch, with spdxcheck. Every ERROR and
every WARNING blocks; FILE_PATH_CHANGES is ignored, the patch being
synthetic. The `--strict` CHECKs are written to the log, counted by type.
The report keeps the name `checkpatch_strict` for baseline continuity.

Until 0.15.0 the gate ran the host kernel's checkpatch with `--no-tree`
on `--file`, and counted ERROR lines only. In `--file` mode a line over
100 columns is a CHECK, and without a tree spdxcheck does not run: the
ten long lines of beamfs 0.1.26 passed every gate and were found when
the RFC series was checked by hand on 2026-10-09.

spdxcheck imports ply and git. checkpatch runs it through `python3`, and
a `python3` that lacks them makes it die on stderr while checkpatch
reports nothing. The interpreter is now looked for, through `EPYTHON`
where python-exec chooses it, and the gate fails when none imports both.

## beamfs-bench upstream

The checks a kernel patch series has to pass before it is mailed, run on
the series branch: the commits, checkpatch on every patch, the mails and
the cover letter, MAINTAINERS, Kconfig, the documentation of the
userspace interfaces, builds under several configurations with W=1,
sparse, kernel-doc and checkstack, the identity of the compiled code
with a measured release, the merge into the newer trees, and the
documentation build against the base. See beamfs-bench(1).

Every check has to run: one left out, arm64 with `--no-cross` or the
newer trees with an empty `--newer`, leaves the series not ready to
mail, and the run exits 3 as when a check fails. A check with nothing
to check says N/A.
