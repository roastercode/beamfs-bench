# beamfs-bench code-analysis tools -- spartian-1 install matrix

This document lists every external tool invoked by `code_analysis.rs`
with the corresponding Gentoo emerge command, version constraint, and
verification step. Run `bin/check-code-analysis-deps.sh` (TODO) to
audit the host before enabling the gate.

## Tier 1 -- FATAL

| Tool             | Gentoo package                          | Verify command                          |
|------------------|------------------------------------------|------------------------------------------|
| checkpatch.pl    | sys-kernel/gentoo-sources OR upstream    | `which checkpatch.pl`                    |
| sparse           | dev-util/sparse                          | `sparse --version`                       |
| smatch           | dev-util/smatch (overlay) or git build   | `smatch --version`                       |
| coccinelle       | dev-util/coccinelle                      | `spatch --version`                       |
| clang            | sys-devel/clang (>= 17)                  | `clang --version`                        |
| gcc -fanalyzer   | sys-devel/gcc (>= 13)                    | `gcc --version` (need >= 13 for fanalyzer)|
| gpg              | app-crypt/gnupg                          | `gpg --version`                          |
| gitleaks         | dev-util/gitleaks (overlay) or go install| `gitleaks version`                       |
| cargo-audit      | `cargo install cargo-audit`              | `cargo audit --version`                  |
| cargo clippy     | dev-lang/rust (component)                | `cargo clippy --version`                 |
| kernel-doc       | sys-kernel/gentoo-sources                | `which scripts/kernel-doc`               |

### Emerge bundle

```bash
emerge -av \
    dev-util/sparse \
    dev-util/coccinelle \
    sys-devel/clang \
    sys-devel/gcc \
    app-crypt/gnupg

cargo install cargo-audit cargo-deny cargo-geiger
```

`smatch`, `gitleaks`, `cargo-deny` may require overlays:

```bash
# smatch: build from upstream
git clone https://repo.or.cz/smatch.git ~/src/smatch
cd ~/src/smatch && make && sudo make install

# gitleaks: official release
curl -L https://github.com/zricethezav/gitleaks/releases/latest/download/gitleaks_8.18.0_linux_x64.tar.gz | tar xz
sudo install gitleaks /usr/local/bin/
```

## Tier 2 -- WARN

| Tool             | Gentoo package                          | Verify command                          |
|------------------|------------------------------------------|------------------------------------------|
| cppcheck         | dev-util/cppcheck                        | `cppcheck --version`                     |
| flawfinder       | dev-util/flawfinder                      | `flawfinder --version`                   |
| semgrep          | `pip install semgrep` or container       | `semgrep --version`                      |
| cargo geiger     | `cargo install cargo-geiger`             | `cargo geiger --version`                 |
| MISRA addon      | bundled with cppcheck                    | `cppcheck --addon=misra --help`          |

### Emerge bundle

```bash
emerge -av dev-util/cppcheck dev-util/flawfinder
pip install --user semgrep
cargo install cargo-geiger
```

## Tier 3 -- REPORT (full mode)

| Tool             | Gentoo package                          | Notes                                   |
|------------------|------------------------------------------|------------------------------------------|
| Frama-C          | dev-tex/frama-c (overlay) or opam        | Heavy, ~minutes per file                 |
| scan-build       | sys-devel/clang (component)              | Comes with clang                         |
| lcov             | dev-util/lcov                            | Gated on selftests presence              |

### Emerge bundle

```bash
emerge -av dev-util/lcov
# Frama-C via opam:
opam install frama-c
```

## Verification script (TODO)

`bin/check-code-analysis-deps.sh` should:

1. `which` each binary, return list of missing tools
2. Check version >= minimum (e.g. gcc >= 13 for -fanalyzer)
3. Emit JSON to `/tmp/code-analysis-deps-status.json` for CI use

When a Tier 1 tool is missing on spartian-1, `code_analysis.rs::run()`
will report `ToolOutcome::Skip` for that tool. The pipeline does NOT
abort on Skip alone -- partial coverage is better than no coverage --
but every Skip in Tier 1 should be followed up.

## kernel.org submission gate

Phase 7 DoD (mainline-scope.md sec 5) requires:

- [ ] checkpatch.pl --strict zero on every .c/.h
- [ ] sparse zero warnings under `make C=2`
- [ ] smatch zero warnings under `make CHECK=smatch C=2`
- [ ] No coccicheck failures from kernel-shipped semantic patches
- [ ] kernel-doc zero warnings on all public API
- [ ] checkpatch on full series (not just diff) via `git format-patch`

When code_analysis.rs Tier 1 = all PASS in `--full` mode, the project
is checkpatch-eligible for RFC submission. This gate does not replace
the manual `git format-patch | checkpatch.pl` on the cover letter, but
it ensures the working tree is always submission-ready.
