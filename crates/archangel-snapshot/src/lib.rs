//! Filesystem snapshot / recovery-point abstraction — threat-model layer
//! #16.
//!
//! The security property this delivers is **"no mutation without a
//! recovery point"**: before an action that mutates persistent state
//! runs, a snapshot of the affected path must be created successfully; if
//! no backend exists or the snapshot fails, the action is refused
//! (fail-closed — the caller, the executor, enforces this).
//!
//! Scope honesty (v0.2): BTRFS read-only snapshots are created and can be
//! discarded. **Automatic rollback-on-regression is not yet performed by
//! this build** — the recovery point exists for a deliberate operator
//! restore; `rollback` returns [`SnapshotError::Unsupported`]. Automated
//! health-check rollback (#16's recovery half) is a later increment. We
//! state this rather than imply a guarantee we do not yet provide.
//!
//! No `unsafe`: backends shell out to the filesystem's own tools.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

/// Snapshot subsystem errors.
pub mod error;
pub use error::SnapshotError;

/// Opaque handle to a created recovery point (the snapshot's path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotId(pub String);

/// A filesystem that can take a pre-mutation recovery point.
pub trait Snapshotter: Send + Sync {
    /// Backend name for logs/audit (e.g. `"btrfs"`).
    fn backend(&self) -> &'static str;

    /// Create a recovery point of `target`. On `Ok` the action may
    /// proceed; on `Err` the caller MUST refuse the mutating action.
    fn snapshot(&self, target: &Path) -> Result<SnapshotId, SnapshotError>;

    /// Restore a snapshot. v0.2: not automated (see module docs).
    fn rollback(&self, id: &SnapshotId) -> Result<(), SnapshotError>;

    /// Delete a snapshot that is no longer needed.
    fn discard(&self, id: &SnapshotId) -> Result<(), SnapshotError>;
}

/// Return the filesystem type mounted at the longest path-prefix of
/// `path`, parsed from `/proc/mounts`-format `mounts`. Pure & testable.
///
/// "Longest path-prefix" so that, e.g., a BTRFS subvolume mounted at
/// `/data` is detected for `/data/x` even if `/` is ext4.
#[must_use]
pub fn fs_type_for<'a>(mounts: &'a str, path: &str) -> Option<&'a str> {
    let mut best: Option<(&str, &str)> = None; // (mountpoint, fstype)
    for line in mounts.lines() {
        let mut f = line.split_whitespace();
        let (Some(_dev), Some(mp), Some(fstype)) = (f.next(), f.next(), f.next())
        else {
            continue;
        };
        if is_path_prefix(mp, path) {
            match best {
                Some((bmp, _)) if bmp.len() >= mp.len() => {}
                _ => best = Some((mp, fstype)),
            }
        }
    }
    best.map(|(_, fstype)| fstype)
}

/// `prefix` is a path-component prefix of `path` (so `/a` matches `/a/b`
/// and `/a`, but not `/ab`). `/` matches everything.
fn is_path_prefix(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Detect a snapshotter for `target`, reading the live `/proc/mounts`.
/// Returns `None` if the filesystem has no supported backend — the caller
/// then fails closed for any mutating action.
#[must_use]
pub fn detect_for(target: &Path, snapshot_root: PathBuf) -> Option<Box<dyn Snapshotter>> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    let p = target.to_str()?;
    match fs_type_for(&mounts, p)? {
        "btrfs" => Some(Box::new(BtrfsSnapshotter { snapshot_root })),
        _ => None,
    }
}

fn run(cmd: &mut Command) -> Result<(), SnapshotError> {
    let out = cmd
        .output()
        .map_err(|e| SnapshotError::Io(e.to_string()))?;
    if out.status.success() {
        Ok(())
    } else {
        let mut msg = String::from_utf8_lossy(&out.stderr).into_owned();
        msg.truncate(256);
        Err(SnapshotError::BackendFailed(msg))
    }
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

/// BTRFS backend.
///
/// Creates a **read-only** subvolume snapshot (a safe, immutable recovery
/// point) under `snapshot_root`. Needs the privilege to run `btrfs` (the
/// executor service is granted the minimal caps for this); failures are
/// surfaced fail-closed.
pub struct BtrfsSnapshotter {
    /// Directory (on a BTRFS filesystem) where snapshots are created.
    pub snapshot_root: PathBuf,
}

impl Snapshotter for BtrfsSnapshotter {
    fn backend(&self) -> &'static str {
        "btrfs"
    }

    fn snapshot(&self, target: &Path) -> Result<SnapshotId, SnapshotError> {
        let stem = target
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("root");
        let dest = self
            .snapshot_root
            .join(format!("{stem}.{}", unique_suffix()));
        std::fs::create_dir_all(&self.snapshot_root)
            .map_err(|e| SnapshotError::Io(e.to_string()))?;
        run(Command::new("btrfs")
            .arg("subvolume")
            .arg("snapshot")
            .arg("-r")
            .arg(target)
            .arg(&dest))?;
        Ok(SnapshotId(dest.to_string_lossy().into_owned()))
    }

    fn rollback(&self, _id: &SnapshotId) -> Result<(), SnapshotError> {
        // Honest: automated subvolume-swap rollback is filesystem-topology
        // sensitive and dangerous to do blindly. v0.2 keeps the recovery
        // point for a deliberate operator restore; automated rollback is a
        // later increment.
        Err(SnapshotError::Unsupported(
            "automatic rollback is not performed in this build; the \
             read-only snapshot is preserved for manual restore"
                .to_owned(),
        ))
    }

    fn discard(&self, id: &SnapshotId) -> Result<(), SnapshotError> {
        run(Command::new("btrfs")
            .arg("subvolume")
            .arg("delete")
            .arg(&id.0))
    }
}

/// In-memory snapshotter for downstream tests (no real filesystem).
#[cfg(feature = "test-util")]
pub mod testutil {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{Path, SnapshotError, SnapshotId, Snapshotter};

    /// Configurable mock: succeed, or fail every snapshot.
    pub struct MockSnapshotter {
        /// If `false`, every `snapshot` fails (to test fail-closed).
        pub healthy: bool,
        counter: AtomicU64,
    }

    impl MockSnapshotter {
        /// A mock that takes snapshots successfully.
        #[must_use]
        pub const fn working() -> Self {
            Self {
                healthy: true,
                counter: AtomicU64::new(0),
            }
        }

        /// A mock whose snapshots always fail (fail-closed testing).
        #[must_use]
        pub const fn failing() -> Self {
            Self {
                healthy: false,
                counter: AtomicU64::new(0),
            }
        }
    }

    impl Snapshotter for MockSnapshotter {
        fn backend(&self) -> &'static str {
            "mock"
        }
        fn snapshot(&self, _t: &Path) -> Result<SnapshotId, SnapshotError> {
            if self.healthy {
                let n = self.counter.fetch_add(1, Ordering::Relaxed);
                Ok(SnapshotId(format!("mock-snap-{n}")))
            } else {
                Err(SnapshotError::BackendFailed("mock failure".to_owned()))
            }
        }
        fn rollback(&self, _id: &SnapshotId) -> Result<(), SnapshotError> {
            Ok(())
        }
        fn discard(&self, _id: &SnapshotId) -> Result<(), SnapshotError> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{fs_type_for, is_path_prefix};

    const MOUNTS: &str = "\
sysfs /sys sysfs rw 0 0
/dev/sda1 / ext4 rw 0 0
/dev/sda2 /data btrfs rw,subvol=/@ 0 0
/dev/sda2 /data/nested btrfs rw 0 0
";

    #[test]
    fn path_prefix_is_component_wise() {
        assert!(is_path_prefix("/", "/anything"));
        assert!(is_path_prefix("/data", "/data"));
        assert!(is_path_prefix("/data", "/data/x/y"));
        assert!(!is_path_prefix("/data", "/database"));
        assert!(!is_path_prefix("/data", "/dat"));
    }

    #[test]
    fn longest_mountpoint_wins() {
        assert_eq!(fs_type_for(MOUNTS, "/etc/x"), Some("ext4"));
        assert_eq!(fs_type_for(MOUNTS, "/data/file"), Some("btrfs"));
        // Deeper mount must win over the shallower /data.
        assert_eq!(fs_type_for(MOUNTS, "/data/nested/z"), Some("btrfs"));
        assert_eq!(fs_type_for(MOUNTS, "/"), Some("ext4"));
    }

    #[test]
    fn unknown_path_has_no_fs() {
        assert_eq!(fs_type_for("garbage line\n", "/x"), None);
    }
}
