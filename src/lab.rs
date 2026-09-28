// SPDX-License-Identifier: GPL-2.0-only
//
// Author: Aurelien DESBRIERES <aurelien@hackers.camp>

//! Where the lab is, so the harness can be somewhere else.
//!
//! Every path this tool needs was a constant naming one account on one
//! station: three source trees under `/home/aurelien/git`, a Yocto
//! build directory, an SSH key, a user, four addresses. Thirty-seven of
//! them across twenty files. The tool worked, and it worked nowhere
//! else -- which matters now that it is packaged, and matters more for
//! the campaigns at IFJ PAN, where somebody else's hardware runs the
//! filesystem and a harness that only runs here is a harness they
//! cannot use.
//!
//! ## Nothing moves unless asked
//!
//! Each value keeps the exact default it had, derived from `HOME` so
//! that on the station it resolves to the same string it was compiled
//! with. With no variable set the behaviour is identical; the
//! environment only ever widens what was possible.
//!
//! That is deliberate. Centralising paths is the kind of change that
//! breaks a run three phases in, on a machine nobody is watching, and
//! the only defence is that the untouched case cannot have changed.

/// A value from the environment, or a default built from `HOME`.
///
/// `HOME` missing is not a normal condition -- a cron entry without a
/// login shell is the usual cause -- so the fallback names the station
/// rather than failing, which is what the constants did before.
fn from_home(var: &str, suffix: &str) -> String {
    if let Ok(v) = std::env::var(var) {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/aurelien".to_string());
    format!("{home}{suffix}")
}

/// Plain override with a literal default.
fn from_env(var: &str, default: &str) -> String {
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => default.to_string(),
    }
}

/// The kernel module's source tree.
#[must_use]
fn calc_beamfs_repo() -> String {
    from_home("BEAMFS_BENCH_BEAMFS_REPO", "/git/beamfs")
}

/// The Yocto layer, which also holds the run archive.
#[must_use]
fn calc_yocto_repo() -> String {
    from_home("BEAMFS_BENCH_YOCTO_REPO", "/git/yocto-beamfs")
}

/// This harness's own tree, read by the code analysis gate.
#[must_use]
fn calc_bench_repo() -> String {
    from_home("BEAMFS_BENCH_BENCH_REPO", "/git/beamfs-bench")
}

/// Where bitbake is run from.
#[must_use]
fn calc_poky_dir() -> String {
    from_home("BEAMFS_BENCH_POKY_DIR", "/yocto/poky")
}

/// The build directory inside poky.
///
/// Two exist on this station -- one per architecture -- and the
/// pipeline has always built the arm64 one while the x86 machines run
/// an image from the other. Naming it here is what makes that visible.
///
/// Derived from the machine unless said otherwise. The two are a pair,
/// and setting one without the other yields a path that does not
/// exist -- a poor way to learn that a campaign is aimed at the wrong
/// architecture. One variable selects a chain.
#[must_use]
fn calc_build_dir_name() -> String {
    if let Ok(v) = std::env::var("BEAMFS_BENCH_BUILD_DIR") {
        let v = v.trim();
        if !v.is_empty() {
            return v.to_string();
        }
    }
    match calc_machine().as_str() {
        "qemuarm64" => "build-qemu-arm64".to_string(),
        "qemux86-64" => "build-qemux86".to_string(),
        // An unknown machine gets bitbake's own layout rather than a
        // guess.
        m => format!("build-{m}"),
    }
}

/// The Yocto MACHINE the build targets.
#[must_use]
fn calc_machine() -> String {
    from_env("BEAMFS_BENCH_MACHINE", "qemuarm64")
}

/// The image recipe name.
#[must_use]
fn calc_image_name() -> String {
    from_env("BEAMFS_BENCH_IMAGE", "hpc-arm64-research-beamfs")
}

/// Full path of the build directory.
#[must_use]
fn calc_build_dir() -> String {
    format!("{}/{}", calc_poky_dir(), calc_build_dir_name())
}

/// The image the pipeline treats as canonical.
#[must_use]
fn calc_canonical_image() -> String {
    format!(
        "{}/tmp/deploy/images/{m}/{i}-{m}.beamfs",
        calc_build_dir(),
        m = calc_machine(),
        i = calc_image_name()
    )
}

/// The kernel sources the build unpacked, read by the analysers.
#[must_use]
fn calc_kernel_source() -> String {
    format!("{}/tmp/work-shared/{}/kernel-source", calc_build_dir(), calc_machine())
}

/// Where run archives and signed manifests are written.
#[must_use]
fn calc_runs_dir() -> String {
    from_env(
        "BEAMFS_BENCH_RUNS_DIR",
        &format!("{}/Documentation/runs", calc_yocto_repo()),
    )
}

/// The private key that reaches the lab.
///
/// A key dedicated to the lab and to nothing else, which is what makes
/// it publishable alongside the harness: a reader who wants to
/// reproduce a campaign needs one that opens the machines the campaign
/// describes, and one that opens nothing else costs nothing to give
/// away.
#[must_use]
fn calc_ssh_key() -> String {
    from_home("BEAMFS_BENCH_SSH_KEY", "/.ssh/hpclab_admin")
}

/// The account the harness logs in as.
#[must_use]
fn calc_ssh_user() -> String {
    from_env("BEAMFS_BENCH_SSH_USER", "hpcadmin")
}


/// The module version the Yocto recipe mirrors.
///
/// It appears in a path -- recipes-kernel/beamfs/files/beamfs-<v> --
/// so a version bump moves a directory the lockstep check reads. It
/// was a literal inside that path, which meant the check silently
/// compared nothing once the sources moved on; then it was a default
/// of "0.1.3" behind an environment variable, and on 2026-09-28 the
/// lockstep phase failed a clean run because the layer held 0.1.22.
/// Now it is read from the layer: the highest beamfs-<v> directory
/// under recipes-kernel/beamfs/files. The environment still wins when
/// set, for a run against another layer.
fn calc_module_version() -> String {
    if let Ok(v) = std::env::var("BEAMFS_BENCH_MODULE_VERSION") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    let files = format!("{}/recipes-kernel/beamfs/files", calc_yocto_repo());
    let mut versions: Vec<Vec<u32>> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&files) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(v) = name.strip_prefix("beamfs-") {
                let parts: Vec<u32> = v.split('.').filter_map(|p| p.parse().ok()).collect();
                if !parts.is_empty() && parts.len() == v.split('.').count() {
                    versions.push(parts);
                }
            }
        }
    }
    versions.sort();
    versions.last().map_or_else(
        || "0.1.3".to_string(),
        |v| v.iter().map(ToString::to_string).collect::<Vec<_>>().join("."))
}

/// The mirrored kernel sources inside the Yocto layer.
fn calc_yocto_kernel_files() -> String {
    format!(
        "{}/recipes-kernel/beamfs/files/beamfs-{}",
        calc_yocto_repo(),
        calc_module_version()
    )
}

/// Each value is resolved once and then shared.
///
/// The sites that use these want a `&str` -- `Command::args`,
/// `PathBuf::from`, `current_dir`, and eight `format!` interpolations.
/// Returning a `String` would mean touching every one of them, and a
/// refactor that touches thirty sites is a refactor that breaks one.
/// Resolving once also means a run cannot see two different values for
/// the same path because something changed the environment halfway.
macro_rules! once {
    ($vis:vis $name:ident, $calc:ident) => {
        #[must_use]
        $vis fn $name() -> &'static str {
            static V: std::sync::OnceLock<String> = std::sync::OnceLock::new();
            V.get_or_init($calc).as_str()
        }
    };
}

once!(pub beamfs_repo, calc_beamfs_repo);
once!(pub yocto_repo, calc_yocto_repo);
once!(pub bench_repo, calc_bench_repo);
once!(pub poky_dir, calc_poky_dir);
once!(pub build_dir_name, calc_build_dir_name);
once!(pub machine, calc_machine);
once!(pub image_name, calc_image_name);
once!(pub build_dir, calc_build_dir);
once!(pub canonical_image, calc_canonical_image);
once!(pub kernel_source, calc_kernel_source);
once!(pub runs_dir, calc_runs_dir);
once!(pub ssh_key, calc_ssh_key);
once!(pub ssh_user, calc_ssh_user);
once!(pub yocto_kernel_files, calc_yocto_kernel_files);

#[cfg(test)]
mod tests {
    use super::*;

    /// The environment belongs to the process, and cargo runs tests in
    /// threads. Two tests setting the same variable at the same time
    /// read each other's value -- which is how the defaults test failed
    /// against a path the machine test had just set. Every test that
    /// touches the environment takes this first.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// With nothing set, every path is what the constants held.
    ///
    /// The station's HOME is /home/aurelien, so these are the literals
    /// that were compiled in before this module existed. That equality
    /// is the whole safety argument for the change.
    #[test]
    fn the_machine_alone_selects_a_chain() {
        // Setting the machine without the build directory used to give
        // a path that does not exist. One variable now names a chain,
        // which is what running the x86 one without the arm64 one
        // requires.
        let _g = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for v in ["BEAMFS_BENCH_MACHINE", "BEAMFS_BENCH_BUILD_DIR"] {
            unsafe { std::env::remove_var(v) };
        }
        assert_eq!(calc_build_dir_name(), "build-qemu-arm64");
        unsafe { std::env::set_var("BEAMFS_BENCH_MACHINE", "qemux86-64") };
        assert_eq!(calc_build_dir_name(), "build-qemux86");
        assert!(calc_canonical_image().contains("build-qemux86"));
        assert!(calc_canonical_image().ends_with("qemux86-64.beamfs"));
        unsafe { std::env::remove_var("BEAMFS_BENCH_MACHINE") };
    }

    #[test]
    fn an_explicit_build_dir_still_wins() {
        let _g = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe { std::env::set_var("BEAMFS_BENCH_MACHINE", "qemux86-64") };
        unsafe { std::env::set_var("BEAMFS_BENCH_BUILD_DIR", "build-ailleurs") };
        assert_eq!(calc_build_dir_name(), "build-ailleurs");
        for v in ["BEAMFS_BENCH_MACHINE", "BEAMFS_BENCH_BUILD_DIR"] {
            unsafe { std::env::remove_var(v) };
        }
    }

    #[test]
    fn the_defaults_are_the_old_constants() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("HOME", "/home/aurelien") };
        for v in [
            "BEAMFS_BENCH_BEAMFS_REPO",
            "BEAMFS_BENCH_YOCTO_REPO",
            "BEAMFS_BENCH_BENCH_REPO",
            "BEAMFS_BENCH_POKY_DIR",
            "BEAMFS_BENCH_RUNS_DIR",
            "BEAMFS_BENCH_SSH_KEY",
            "BEAMFS_BENCH_SSH_USER",
            "BEAMFS_BENCH_BUILD_DIR",
            "BEAMFS_BENCH_MACHINE",
            "BEAMFS_BENCH_IMAGE",
        ] {
            unsafe { std::env::remove_var(v) };
        }
        assert_eq!(calc_beamfs_repo(), "/home/aurelien/git/beamfs");
        assert_eq!(calc_yocto_repo(), "/home/aurelien/git/yocto-beamfs");
        assert_eq!(calc_bench_repo(), "/home/aurelien/git/beamfs-bench");
        assert_eq!(calc_poky_dir(), "/home/aurelien/yocto/poky");
        assert_eq!(calc_runs_dir(), "/home/aurelien/git/yocto-beamfs/Documentation/runs");
        assert_eq!(calc_ssh_key(), "/home/aurelien/.ssh/hpclab_admin");
        assert_eq!(calc_ssh_user(), "hpcadmin");
        assert_eq!(
            calc_canonical_image(),
            "/home/aurelien/yocto/poky/build-qemu-arm64/tmp/deploy/images/qemuarm64/hpc-arm64-research-beamfs-qemuarm64.beamfs"
        );
        assert_eq!(
            calc_kernel_source(),
            "/home/aurelien/yocto/poky/build-qemu-arm64/tmp/work-shared/qemuarm64/kernel-source"
        );
    }

    /// A variable replaces the default outright, not partly.
    #[test]
    fn a_variable_replaces_the_default() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("BEAMFS_BENCH_BEAMFS_REPO", "/srv/beamfs") };
        assert_eq!(calc_beamfs_repo(), "/srv/beamfs");
        unsafe { std::env::remove_var("BEAMFS_BENCH_BEAMFS_REPO") };
    }

    /// An empty or blank value is not an override.
    ///
    /// A variable exported and left empty by a script would otherwise
    /// point every path at the filesystem root.
    #[test]
    fn a_blank_variable_is_not_an_override() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("HOME", "/home/aurelien") };
        unsafe { std::env::set_var("BEAMFS_BENCH_SSH_USER", "   ") };
        assert_eq!(calc_ssh_user(), "hpcadmin");
        unsafe { std::env::set_var("BEAMFS_BENCH_YOCTO_REPO", "") };
        assert_eq!(calc_yocto_repo(), "/home/aurelien/git/yocto-beamfs");
        unsafe { std::env::remove_var("BEAMFS_BENCH_SSH_USER") };
        unsafe { std::env::remove_var("BEAMFS_BENCH_YOCTO_REPO") };
    }

    /// The build directory and the machine compose into the image path.
    #[test]
    fn the_image_path_follows_the_machine() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("HOME", "/home/aurelien") };
        unsafe { std::env::set_var("BEAMFS_BENCH_BUILD_DIR", "build-qemux86") };
        unsafe { std::env::set_var("BEAMFS_BENCH_MACHINE", "qemux86-64") };
        assert_eq!(
            calc_canonical_image(),
            "/home/aurelien/yocto/poky/build-qemux86/tmp/deploy/images/qemux86-64/hpc-arm64-research-beamfs-qemux86-64.beamfs"
        );
        unsafe { std::env::remove_var("BEAMFS_BENCH_BUILD_DIR") };
        unsafe { std::env::remove_var("BEAMFS_BENCH_MACHINE") };
    }
}
