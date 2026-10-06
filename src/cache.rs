//! Change detection for cached repository status.
//!
//! [`Guard`] records enough about a repository to tell, cheaply, whether the answer of a previous
//! full scan is still valid:
//!
//! * the index and `HEAD` are unchanged, which keeps staged changes, the checked out branch and
//!   in-progress operations stable,
//! * no tracked file differs from its index entry, and
//! * no file appeared or disappeared anywhere in the worktree, judged by the mtime of every
//!   directory that could contain it.
//!
//! The last point is what makes this cheap: instead of walking the worktree to look for untracked
//! files, only the directories that were seen during the previous full scan are inspected again.
//!
//! A status is only reused for [`trust_window()`], because a filesystem that doesn't update
//! directory mtimes (some network ones) would otherwise never notice a new file.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use gix::ThreadSafeRepository;

use crate::server::env_u64;
use crate::status;

/// How many directories can be watched before a repository is considered too large to watch.
const MAX_WATCHED_DIRS: usize = 64 * 1024;

/// How a cached status fares against the current state of its repository.
pub enum Verdict {
    /// Nothing that can change the cached status has changed.
    Unchanged,
    /// The worktree changed, so the status is [`Status::Change`](status::Status::Change).
    Changed,
    /// Too much changed to tell; the status has to be computed again.
    Unknown,
}

/// A snapshot that allows proving that a repository didn't change.
pub struct Guard {
    repo: ThreadSafeRepository,

    /// See [`status::Report::staged`].
    staged: bool,

    /// Files whose mtime keeps staged changes, the checked out branch and the index stable.
    fingerprint: Vec<FileStamp>,

    /// Every directory that could gain or lose a file, with the mtime it had when the guard was
    /// created.
    dirs: Vec<(PathBuf, Option<SystemTime>)>,

    created: Instant,
}

impl Guard {
    /// Record the state of the repository that `report` was computed for.
    ///
    /// Returns `None` if the repository can't be watched for changes reliably, in which case the
    /// caller has to fall back to keeping its result for a fixed amount of time.
    pub fn capture(repo: &status::Repo, report: &status::Report) -> Option<Guard> {
        let shared = &repo.repo;
        let tl = shared.to_thread_local();
        let git_dir = tl.git_dir().to_owned();
        tl.workdir()?;

        let mut fingerprint = vec![
            FileStamp::read(tl.index_path()),
            FileStamp::read(git_dir.join("HEAD")),
        ];
        fingerprint.extend(head_stamps(&git_dir, tl.common_dir())?);

        Some(Guard {
            repo: shared.clone(),
            staged: report.staged,
            fingerprint,
            dirs: watch_dirs(shared, report)?,
            created: Instant::now(),
        })
    }

    /// Whether the guard may still be used, see [`trust_window()`].
    pub fn fresh(&self) -> bool {
        self.created.elapsed() < trust_window()
    }

    /// The repository the cached status was computed for.
    pub fn shared(&self) -> &ThreadSafeRepository {
        &self.repo
    }

    /// Compare the repository against the recorded state.
    pub fn check(&self) -> Verdict {
        if self.fingerprint.iter().any(|stamp| !stamp.matches()) {
            return Verdict::Unknown;
        }

        // Staged changes are the difference between the tree `HEAD` points at and the index, both
        // of which are unchanged.
        if self.staged {
            return Verdict::Unchanged;
        }

        match self.worktree_changed() {
            Ok(true) => return Verdict::Changed,
            Ok(false) => {}
            Err(_) => return Verdict::Unknown,
        }

        if !dirs_unchanged(&self.dirs) {
            return Verdict::Unknown;
        }

        Verdict::Unchanged
    }

    /// Whether any tracked file differs from its index entry.
    ///
    /// This skips the directory walk entirely, which is why it is much cheaper than a full status.
    fn worktree_changed(&self) -> Result<bool> {
        let repo = self.repo.to_thread_local();
        let items = repo
            .status(gix::progress::Discard)?
            .index_worktree_rewrites(None)
            .index_worktree_submodules(gix::status::Submodule::AsConfigured { check_dirty: true })
            .index_worktree_options_mut(|opts| opts.dirwalk_options = None)
            .into_index_worktree_iter(Vec::new())?;

        for item in items {
            if status::worktree_change(&item?) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// The metadata of a file, as far as it matters to detect that it changed.
#[derive(Clone, PartialEq, Eq)]
struct FileStamp {
    path: PathBuf,
    /// `None` if the file doesn't exist or can't be inspected.
    state: Option<(SystemTime, u64, u64)>,
}

impl FileStamp {
    fn read(path: impl Into<PathBuf>) -> FileStamp {
        let path = path.into();
        let state = std::fs::symlink_metadata(&path).ok().map(|meta| {
            (
                meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                meta.len(),
                meta.ino(),
            )
        });

        FileStamp { path, state }
    }

    fn matches(&self) -> bool {
        FileStamp::read(self.path.clone()) == *self
    }
}

/// The files to watch to notice `HEAD` moving: the reference it points at, and `packed-refs` as
/// the other place a reference can live.
///
/// Without them, change detection would keep answering with the old status when commits are made or
/// the branch is switched. A reference backend that keeps references somewhere else (reftable) has
/// nothing to watch and gets no guard at all.
fn head_stamps(git_dir: &Path, common_dir: &Path) -> Option<Vec<FileStamp>> {
    let head = git_dir.join("HEAD");
    let content = std::fs::read(&head).ok()?;
    let content = content.strip_suffix(b"\n").unwrap_or(&content);

    let Some(name) = content.strip_prefix(b"ref: ") else {
        // A detached HEAD stores the commit id itself, and that file is watched already.
        return Some(Vec::new());
    };
    let name = Path::new(OsStr::from_bytes(name));
    if name.is_absolute() || name.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }

    // References live next to the common directory, as linked worktrees share them. Both places a
    // reference can be stored are watched: committing on a packed branch creates the loose file,
    // and packing references updates `packed-refs`.
    let loose = common_dir.join(name);
    let packed = common_dir.join("packed-refs");
    if loose.symlink_metadata().is_err() && packed.symlink_metadata().is_err() {
        return None;
    }

    Some(vec![FileStamp::read(loose), FileStamp::read(packed)])
}

/// Every directory that could gain or lose a file, with its current mtime.
///
/// A new file always changes the mtime of the directory holding it. If that directory is new as
/// well, one of its parents changed instead, and the worktree root is always watched, so files
/// appearing or disappearing are found even when the directory holding them is unknown.
fn watch_dirs(
    shared: &ThreadSafeRepository,
    report: &status::Report,
) -> Option<Vec<(PathBuf, Option<SystemTime>)>> {
    let repo = shared.to_thread_local();
    let workdir = repo.workdir()?.to_owned();

    let mut rel: HashSet<Vec<u8>> = HashSet::new();
    rel.insert(Vec::new());

    if let Ok(index) = repo.index_or_empty() {
        for entry in index.entries() {
            let path = entry.path(&index);
            if let Some(pos) = path.iter().rposition(|b| *b == b'/') {
                rel.insert(path[..pos].to_vec());
            }
        }
    }

    // Anything the directory walk reported as untracked is watched as well, so that files vanishing
    // from an untracked directory (and with it the untracked status) are noticed.
    for path in &report.untracked {
        rel.insert(path.to_vec());
        if let Some(pos) = path.iter().rposition(|b| *b == b'/') {
            rel.insert(path[..pos].to_vec());
        }
    }

    if rel.len() > MAX_WATCHED_DIRS {
        return None;
    }

    let mut dirs: Vec<PathBuf> = rel
        .into_iter()
        .map(|path| workdir.join(OsStr::from_bytes(&path)))
        .collect();
    dirs.sort();

    Some(par_map(&dirs, |dir| (dir.clone(), mtime_of(dir))))
}

fn dirs_unchanged(dirs: &[(PathBuf, Option<SystemTime>)]) -> bool {
    par_map(dirs, |(path, mtime)| mtime_of(path) == *mtime)
        .into_iter()
        .all(std::convert::identity)
}

fn mtime_of(path: &Path) -> Option<SystemTime> {
    std::fs::symlink_metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
}

/// Apply `f` to every item, using all available cores.
fn par_map<T, U>(items: &[T], f: impl Fn(&T) -> U + Sync) -> Vec<U>
where
    T: Sync,
    U: Send,
{
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let chunk = items.len().div_ceil(threads);
    if chunk == 0 {
        return Vec::new();
    }

    std::thread::scope(|scope| {
        let workers: Vec<_> = items
            .chunks(chunk)
            .map(|chunk| scope.spawn(|| chunk.iter().map(&f).collect::<Vec<_>>()))
            .collect();

        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("mapping doesn't panic"))
            .collect()
    })
}

/// How long a guard may be used without re-verifying the assumption that directory mtimes change
/// when files appear or disappear.
///
/// Filesystems that don't do that (some network ones) would otherwise keep a stale status for as
/// long as the daemon lives.
fn trust_window() -> Duration {
    Duration::from_secs(env_u64("BASH_GIT_STATUS_TRUST_SECS", 60))
}
