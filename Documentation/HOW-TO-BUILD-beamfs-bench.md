# How to build beamfs-bench

This document is the canonical reference for building, installing, and
releasing **beamfs-bench**. It exists because v0.x bumps repeatedly
hit the same friction points (live vs versioned ebuild selection,
sudo + GPG agent ownership, overlay Manifest gitignored, etc.). If
you find yourself improvising any of the steps below, please patch
this file rather than re-deriving the procedure.

---

## 1. Prerequisites

- **Host** : Gentoo Linux with Portage and an overlay layer.
- **Overlay path** : `/var/db/repos/beamfs-overlay`, with the package
  at `sys-fs/beamfs-bench/`. Owned by `aurelien:aurelien`. Remote :
  `git@github.com:roastercode/beamfs-overlay.git` (private).
- **Bench source path** : `~/git/beamfs-bench`. Remote :
  `git@github.com:roastercode/beamfs-bench.git` (private).
- **Build deps** :
  - Rust `>= 1.75` (`dev-lang/rust` or `dev-lang/rust-bin`).
  - Cargo (bundled with Rust).
- **Runtime deps** (declared in ebuild RDEPEND, typically already in) :
  - `app-emulation/libvirt`, `app-emulation/qemu`,
    `net-misc/openssh`, `sys-fs/e2fsprogs`, `sys-fs/btrfs-progs`,
    `sys-fs/squashfs-tools`.
- **Group** : user must be in the `libvirt` group
  (`gpasswd -a aurelien libvirt`, then re-login).
- **GPG** : signing key configured for git commits. The agent cache
  state is shown by `gpg-connect-agent 'KEYINFO --list' /bye` ;
  `state=1` means the cache is populated (signing works without a
  passphrase prompt), `state=P` means a preauth is needed (see
  section 5.0).

---

## 2. Build modes

There are **four** distinct ways to build beamfs-bench. Pick the one
that matches your use case, do not mix them.

### Mode A : dev iteration (no install)

Use when : iterating on src/ files, running `cargo test`, debugging,
or producing a binary you will run directly without installing.

```
cd ~/git/beamfs-bench
cargo check                       # fast type check
cargo build --release             # produces target/release/beamfs-bench
cargo test                        # runs unit tests
./target/release/beamfs-bench --version
```

The binary at `target/release/beamfs-bench` is fully functional. It
does not touch `/usr/bin/` or `/etc/portage/`. This mode is the
fastest and is the right choice during a sprint **before** the bump
commit.

### Mode B : live install via the 9999 ebuild

Use when : you have committed your changes locally on `main` and want
to install the current `HEAD` system-wide (`/usr/bin/beamfs-bench`)
without bumping a version.

```
sudo emerge -1 sys-fs/beamfs-bench
```

Portage selects `sys-fs/beamfs-bench-9999.ebuild`, which has
`EGIT_REPO_URI="file:///home/aurelien/git/beamfs-bench"` and
`EGIT_BRANCH="main"`. It rebuilds against your local working tree's
**main branch** (committed state, not the working tree itself).

Caveat : the 9999 ebuild has `KEYWORDS=""` (live), so portage may
emit a warning. That is expected.

### Mode C : install a specific version

Use when : you want to install a specific tagged release, typically
to validate that a published version works end-to-end.

```
sudo emerge -1 =sys-fs/beamfs-bench-0.7.0
```

Portage selects the matching versioned ebuild
(`beamfs-bench-0.7.0.ebuild` in this case), which pins
`EGIT_COMMIT="v0.7.0"` and pulls the GPG-signed tag.

If both the 9999 ebuild and a versioned ebuild are eligible (no mask,
both keyworded), portage picks the **highest version number**, with
9999 always being highest. So in practice, to force a versioned
selection you may need to mask 9999 temporarily (see section 4).

### Mode D : full release (bump + tag + ebuild + emerge)

Use when : you are publishing a new version. This is the canonical
release procedure. Detailed in section 5.

---

## 3. Quick reference : "I just want my latest commits in /usr/bin/"

```
cd ~/git/beamfs-bench
git status                        # working tree must be clean
git push                          # ensure main is up to date
sudo emerge -1 sys-fs/beamfs-bench
beamfs-bench --version            # confirm
```

Mode B (live ebuild). Picks up whatever is on `main`. No version bump.

---

## 4. Forcing version selection : the 9999 mask

Versioned ebuilds (e.g. `0.7.0`) and the live `9999` ebuild coexist
in the overlay. Portage normally picks the highest version, and 9999
is always the highest. To force selection of a specific versioned
ebuild :

```
echo "=sys-fs/beamfs-bench-9999" | sudo tee /etc/portage/package.mask/beamfs-bench-9999
sudo emerge -1 =sys-fs/beamfs-bench-0.7.0
sudo rm /etc/portage/package.mask/beamfs-bench-9999     # do not forget !
```

`sprint-phase4a-emerge.sh` automates this with a `trap` that removes
the mask on exit, so a failed emerge never leaves the mask behind.
If you do this manually, **always** clean the mask afterwards or
future emerges will skip 9999 silently.

---

## 5. Full release procedure (bump 0.X.Y -> 0.X.Y+1 or 0.X+1.0)

This is the procedure followed for the v0.7.0 release (2026-05-06
quality sprint). It maps to the four `sprint-phase{1,2,3,4a,4b}.sh`
scripts in `/tmp/` after a sprint.

### 5.0 Pre-flight

- Working trees must be clean :
  - `cd ~/git/beamfs-bench && git status --short` empty.
  - `cd /var/db/repos/beamfs-overlay && git status --short` shows
    no `M ` (modified) entries ; `??` untracked are tolerable.
- VMs all `shut off` :
  ```
  sudo virsh list --all | grep beamfs
  ```
- USB sticks : as many `RW` healthy as the libvirt XML declares.
  ```
  lsblk -o NAME,SIZE,RO,MODEL,SERIAL,TRAN | grep DataTraveler
  ```
- GPG cache state=1 (preauth done) :
  ```
  gpg-connect-agent 'KEYINFO --list' /bye | head -2
  ```
  If state=P, do an interactive preauth in your TTY :
  ```
  echo "preauth" | gpg -S --output /tmp/preauth.sig -
  rm /tmp/preauth.sig
  ```
  pinentry will pop up, enter the passphrase. Cache is then populated
  for 3600s.

### 5.1 Bump Cargo.toml + commit + tag (beamfs-bench repo)

```
cd ~/git/beamfs-bench
sed -i 's/^version = "0.6.0"$/version = "0.7.0"/' Cargo.toml
cargo check                       # regenerates Cargo.lock with new version
git add Cargo.toml Cargo.lock src/
git commit -S -m "feat/fix(bench): <semantic message>

phase=N
DoD: <one-line>

<details paragraph>

Signed-off-by: Aurelien DESBRIERES <aurelien@hackers.camp>
Assisted-by: Claude:claude-opus-4-7"

git tag -s -a v0.7.0 -m "beamfs-bench v0.7.0 -- <one-line summary>

<details>"
```

Any combination of files can be staged. The standard convention is :
**one commit per semantic concern** (one feat OR one fix per commit).
A bump is typically 1-3 commits + 1 tag.

### 5.2 Push beamfs-bench

```
git --no-pager remote -v          # verify origin = roastercode/beamfs-bench (PRIVATE)
git push origin main
git push origin v0.7.0
```

### 5.3 Create the versioned ebuild in the overlay

The pattern : copy the previous version's ebuild, change three things.

```
cd /var/db/repos/beamfs-overlay/sys-fs/beamfs-bench/
cp beamfs-bench-0.5.1.ebuild beamfs-bench-0.7.0.ebuild
$EDITOR beamfs-bench-0.7.0.ebuild
```

Three edits required :
1. `EGIT_COMMIT="v0.7.0"` (the new tag).
2. `pkg_postinst()` :
   - `elog "beamfs-bench v0.7.0 installed. Quick start:"` (version line).
   - Replace the release notes block with what's new in this version.
3. The `CRATES=""` block at the top : check if `Cargo.lock` changed
   between the old and new version. If not, leave as-is. If yes,
   regenerate with :
   ```
   cd ~/git/beamfs-bench
   cargo metadata --format-version=1 \
     | python3 -c 'import json, sys
   d = json.load(sys.stdin)
   pkgs = [p for p in d["packages"] if p["name"] != "beamfs-bench"]
   for p in sorted(pkgs, key=lambda x: x["name"]):
       print(f"\t{p[\"name\"]}-{p[\"version\"]}")'
   ```
   and paste the output between the `CRATES="` quotes.

A `diff <0.5.1.ebuild> <0.7.0.ebuild>` should look exactly like :
```
133c133  # tag v0.X.Y in comment
136c136  EGIT_COMMIT
156c156  # tag v0.X.Y in comment (src_unpack)
189c189  pkg_postinst version line
201,204c201,...  release notes block
```
Anything else means an unintended diff and should be reviewed.

### 5.4 Regenerate the overlay Manifest

The `Manifest` file is **gitignored** (see overlay's `.gitignore`).
It must be regenerated locally before emerge but is never committed.

```
cd /var/db/repos/beamfs-overlay/sys-fs/beamfs-bench/
sudo ebuild beamfs-bench-0.7.0.ebuild manifest
# or, if pkgdev is available :
# sudo pkgdev manifest
```

### 5.5 Commit the overlay (ebuild only, NOT the Manifest)

The overlay must be committed by **aurelien**, NOT by root. Doing
`sudo git ...` will fail with `gpg: WARNING: unsafe ownership on
homedir '/home/aurelien/.gnupg'` because the GPG agent is bound to
the user that started it (aurelien), not root.

If the previous step left files owned by root (because of `sudo
ebuild`, `sudo cp`, etc.), fix ownership first :

```
sudo chown aurelien:aurelien .git/index
sudo chown aurelien:aurelien sys-fs/beamfs-bench/beamfs-bench-0.7.0.ebuild
```

Then commit as aurelien :

```
cd /var/db/repos/beamfs-overlay
git add sys-fs/beamfs-bench/beamfs-bench-0.7.0.ebuild
git -c user.email="aurelien@hackers.camp" \
    -c user.name="Aurelien Desbrieres" \
    commit -S -m "sys-fs/beamfs-bench: bump 0.X.Y -> 0.7.0 (<reason>)

<details>

Tracks upstream beamfs-bench tag v0.7.0.

Signed-off-by: Aurelien Desbrieres <aurelien@hackers.camp>"
```

### 5.6 Push overlay

```
git --no-pager remote -v          # verify origin = roastercode/beamfs-overlay
git push origin main
```

### 5.7 Emerge with mask 9999

```
echo "=sys-fs/beamfs-bench-9999" | sudo tee /etc/portage/package.mask/beamfs-bench-9999
sudo emerge -1 sys-fs/beamfs-bench
sudo rm /etc/portage/package.mask/beamfs-bench-9999
```

Validate :
```
beamfs-bench --version            # must show 0.7.0
ls -la /usr/bin/beamfs-bench      # mtime should be just now
```

### 5.8 R19 final validation

```
cd ~/git/yocto-beamfs              # R24 invocation point
beamfs-bench full --auto-confirm   # 30-60 min, run inside tmux
echo "exit code : $?"              # must be 0
```

---

## 6. Common pitfalls and their fixes

### 6.1 "gpg failed to sign the data: unsafe ownership"

You ran `sudo git commit -S` somewhere. Don't. The GPG agent is owned
by the calling user, not root. Always commit as aurelien (with
`chown` to fix file ownership beforehand if needed). See section 5.5.

### 6.2 emerge picks 9999 instead of versioned

You forgot to mask 9999. See section 4. The 9999 ebuild always wins
unless masked.

### 6.3 emerge complains about Manifest

`Manifest` is gitignored. If you cloned the overlay fresh, it doesn't
exist yet. Regenerate with `sudo ebuild <foo>.ebuild manifest`.
Never commit the Manifest.

### 6.4 "Repo unmasked but ebuild not visible"

Check `KEYWORDS` in your ebuild. Versioned ebuilds use `~amd64 ~arm64`
(testing keyword). The user must accept testing for `sys-fs/beamfs-bench`,
typically via :
```
echo "sys-fs/beamfs-bench ~amd64" | sudo tee -a /etc/portage/package.accept_keywords/beamfs-bench
# (or ~arm64 depending on host architecture)
```

### 6.5 Cargo.lock changed but didn't regenerate CRATES

`emerge` will fail with "no SRC_URI for crate X" because the ebuild's
CRATES list is stale. Regenerate CRATES (section 5.3) and re-create
the Manifest (section 5.4).

### 6.6 USB pre-flight fails ("0 healthy slots")

Your physical USB sticks have changed (added, removed, or one died).
The bench is fully adaptive : it counts `<disk type='block'>` entries
in the libvirt XML of `beamfs-compute01` and expects that many
healthy slots. Either :
- replace the dead sticks (re-plug + verify with `lsblk -o
  NAME,RO,TRAN,MODEL,SERIAL`) ; or
- remove the dead slots from the libvirt XML so the bench's expected
  count matches reality :
  ```
  sudo virsh edit beamfs-compute01
  ```
  and remove the offending `<disk>` blocks.

When new USBs arrive, the converse : add `<disk type='block'>`
entries to the libvirt XML. The bench picks them up at next run with
no code change required (FS_PRIORITY in src/usb_health.rs determines
the FS-to-vd mapping).

---

## 7. Per-version release notes

See the `pkg_postinst()` block of each versioned ebuild for the
release notes specific to that version. The release notes also
appear when you run `emerge` for that version.

The git history of `~/git/beamfs-bench` is the authoritative log :
```
cd ~/git/beamfs-bench
git --no-pager log --oneline v0.6.0..v0.7.0
```
