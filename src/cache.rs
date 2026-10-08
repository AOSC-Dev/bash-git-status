//! Change detection for cached repository status.
//!
//! [`Guard`] records enough about a repository to tell, cheaply, whether the answer of a previous
//! full scan is still valid:
//!
//! * the index and `HEAD` are unchanged, which keeps staged changes, the checked out branch and
//!   in-progress operations stable,
//! * no tracked file differs from its index entry, and
//! * no file appeared or disappeared anywhere in the worktree, judged by the mtime and inode of
//!   every directory that could contain it.
//!
//! The last point is what makes this cheap: instead of walking the worktree to look for untracked
//! files, only the directories that were seen during the previous full scan are inspected again.
//! The second point is answered from the stat information the index recorded for a file
//! ([`Guard::tracked_files()`]), which is a few stat calls per entry instead of the pathspec and
//! attribute handling every entry goes through in a full status.
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
use rayon::prelude::*;

use crate::server::env_u64;
use crate::status::{self, Status};

/// How many directories can be watched before a repository is considered too large to watch.
const MAX_WATCHED_DIRS: usize = 64 * 1024;

/// Below this many items a check runs in the thread that asked for it: waking up another one costs
/// more than the `stat` calls it would take over.
const PARALLEL_THRESHOLD: usize = 64;

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

    /// The exit code of the status this guard was captured for, so that a guard which said the
    /// worktree differs from the index can tell that the difference is gone.
    code: i32,

    /// See [`status::Report::staged`].
    staged: bool,

    /// Files whose mtime keeps staged changes, the checked out branch and the index stable.
    fingerprint: Vec<FileStamp>,

    /// Every directory that could gain or lose a file, with the metadata it had when the guard was
    /// captured.
    dirs: Vec<FileStamp>,

    /// When the status this guard was captured for was computed.
    created: Instant,
}

/// What a cheap look at the tracked files concluded.
///
/// The variants are ordered, so that the results for the entries of an index can be combined by
/// taking the largest one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tracked {
    /// Every entry matches the file it points at.
    Unchanged,
    /// A file that the index tracks is gone from the worktree.
    Removed,
    /// The recorded stat information doesn't settle it, so gix has to be asked.
    Unknown,
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
            code: report.status.into(),
            staged: report.staged,
            fingerprint,
            dirs: watch_dirs(shared, report)?,
            created: Instant::now(),
        })
    }

    /// The exit code of the status the guard was captured for.
    pub fn code(&self) -> i32 {
        self.code
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
            // The worktree still differs from the index, which is what the cached status says; the
            // untracked files can't change the answer any more.
            Ok(true) if self.code == Status::Change.into() => return Verdict::Unchanged,
            Ok(true) => return Verdict::Changed,
            // The cached status said the worktree differed from the index, and it doesn't any
            // more: whatever it was computed for is gone, and only a new status can tell what is
            // left.
            Ok(false) if self.code == Status::Change.into() => return Verdict::Unknown,
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
        match self.tracked_files() {
            Tracked::Unchanged => return Ok(false),
            Tracked::Removed => return Ok(true),
            Tracked::Unknown => {}
        }

        self.worktree_changed_exactly()
    }

    /// Compare the tracked files to the stat information their index entries recorded.
    ///
    /// gix decides this by looking at the pathspecs and attributes of every entry, which costs an
    /// order of magnitude more than the `stat` call the check ends in. Comparing the recorded
    /// information directly is enough for the answer: a file whose size, mtime, ctime and inode are
    /// the ones the index wrote down for it is the file the index was written for, unless it was
    /// changed after that within the granularity the filesystem reports times with - the racy case
    /// of `racy-git.txt`, which is why an entry whose mtime is at or after the index timestamp is
    /// left to gix.
    ///
    /// Anything else - a mode a filesystem reports differently, a kind of entry that needs more
    /// than the file itself to be judged - is [`Tracked::Unknown`], which leaves the answer to the
    /// exact comparison of gix.
    fn tracked_files(&self) -> Tracked {
        let repo = self.repo.to_thread_local();
        let (Ok(index), Some(workdir)) = (repo.index_or_empty(), repo.workdir()) else {
            return Tracked::Unknown;
        };

        // An entry is racy when its file was written at or after the index was, in which case a
        // change after the index was written can be invisible in the stat information that was
        // recorded. Nanoseconds are compared as well, so that entries written earlier in the same
        // second as the index are trusted, as `git status` trusts them where it has nanoseconds to
        // compare; a filesystem that reports none has zeroes on both sides, and its entries stay
        // racy, which only costs the exact comparison below.
        let written_at = index.timestamp();
        let index_time = (written_at.unix_seconds(), written_at.nanoseconds());
        let is_racy = |mtime: gix::index::entry::stat::Time| is_racy(index_time, mtime);

        index
            .entries()
            .par_iter()
            .with_min_len(PARALLEL_THRESHOLD)
            .map(|entry| entry_state(entry, &index, workdir, &is_racy))
            .max()
            .unwrap_or(Tracked::Unchanged)
    }

    /// The exact answer, for the entries [`tracked_files()`](Self::tracked_files()) can't judge.
    fn worktree_changed_exactly(&self) -> Result<bool> {
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

/// What the file `entry` points at says about it.
///
/// `is_racy` answers whether a file with the given mtime may have been written after the index was,
/// see [`Guard::tracked_files()`].
fn entry_state(
    entry: &gix::index::Entry,
    index: &gix::index::State,
    workdir: &Path,
    is_racy: &impl Fn(gix::index::entry::stat::Time) -> bool,
) -> Tracked {
    use gix::index::entry::{Flags, Stat, stat};

    // These flags tell gix to skip an entry, and what it does with the entry is what matters here.
    if entry.flags.intersects(
        Flags::UPTODATE | Flags::SKIP_WORKTREE | Flags::ASSUME_VALID | Flags::FSMONITOR_VALID,
    ) {
        return Tracked::Unchanged;
    }

    // Conflicts, intent-to-add and submodules need more than the file itself to be judged.
    if entry.stage_raw() != 0
        || entry.flags.contains(Flags::INTENT_TO_ADD)
        || entry.mode.is_submodule()
    {
        return Tracked::Unknown;
    }

    // git marks a file whose content it had to read as having size 0, and an entry that records the
    // empty blob although it isn't empty is inconsistent in the same way; gix reads both.
    if (entry.stat.size == 0) != entry.id.is_empty_blob() {
        return Tracked::Unknown;
    }

    let path = workdir.join(OsStr::from_bytes(entry.path(index)));
    let metadata = match gix::index::fs::Metadata::from_path_no_follow(&path) {
        Ok(metadata) => metadata,
        // A file that isn't there any more is the removal gix reports as well.
        Err(e) if is_missing(&e) => return Tracked::Removed,
        Err(_) => return Tracked::Unknown,
    };

    // A file that turned into a directory is a removal as well.
    if metadata.is_dir() {
        return Tracked::Removed;
    }

    let Ok(stat) = Stat::from_fs(&metadata) else {
        // The clock was off when the file was last changed.
        return Tracked::Unknown;
    };

    // The index only records the lower 32 bits of a size, which is not enough to compare a file
    // that is bigger than that.
    if metadata.len() != u64::from(entry.stat.size) {
        return Tracked::Unknown;
    }

    // Whether the file is still of the kind the entry describes, executable bit included. The
    // capabilities gix uses for this depend on the platform and the repository, so a filesystem
    // they don't describe only costs the exact comparison below.
    if entry
        .mode
        .change_to_match_fs(&metadata, true, true)
        .is_some()
    {
        return Tracked::Unknown;
    }

    let options = stat::Options {
        check_stat: true,
        trust_ctime: true,
        use_nsec: false,
        use_stdev: false,
    };

    // `matches` can be told to ignore nanoseconds; this comparison doesn't, so a file that was
    // rewritten quickly enough to keep its mtime in the same second is still noticed.
    let same = stat.matches(&entry.stat, options)
        && stat.mtime.nsecs == entry.stat.mtime.nsecs
        && stat.ctime.nsecs == entry.stat.ctime.nsecs;

    if !same || is_racy(stat.mtime) {
        return Tracked::Unknown;
    }

    Tracked::Unchanged
}

/// Whether an error means the file can't be reached, which gix reports as a removal as well.
fn is_missing(err: &std::io::Error) -> bool {
    // A path component that isn't a directory makes the file unreachable in the same way as a
    // missing one.
    matches!(
        err.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// Whether a file whose entry recorded `mtime` could have been written after the index was written
/// at `index`, as whole seconds with nanoseconds.
///
/// Everything written before the index is trustworthy, and a file written in the same second as the
/// index is only trustworthy when the nanoseconds place it before the index. Where those are
/// missing, both sides have zeroes and the file stays racy: the exact comparison has to decide.
fn is_racy(index: (i64, u32), mtime: gix::index::entry::stat::Time) -> bool {
    let (index_secs, index_nanos) = index;

    index_secs < i64::from(mtime.secs)
        || (index_secs == i64::from(mtime.secs) && index_nanos <= mtime.nsecs)
}

/// The metadata of a file, as far as it matters to detect that it changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileStamp {
    pub(crate) path: PathBuf,
    /// `None` if the file doesn't exist or can't be inspected.
    pub(crate) state: Option<(SystemTime, u64, u64)>,
}

impl FileStamp {
    fn read(path: impl Into<PathBuf>) -> FileStamp {
        let path = path.into();
        let metadata = std::fs::symlink_metadata(&path).ok();

        FileStamp {
            state: metadata.as_ref().map(stamp_of),
            path,
        }
    }

    fn matches(&self) -> bool {
        FileStamp::read(self.path.clone()) == *self
    }

    /// Like [`matches()`](Self::matches), for a directory.
    ///
    /// The size of a directory is not meaningful on every filesystem, so only the mtime and the
    /// inode are compared. That the path still is a directory is compared as well: a directory
    /// replaced by a symbolic link to another one reports the metadata of its target, which would
    /// otherwise be indistinguishable from itself.
    fn dir_matches(&self) -> bool {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return self.state.is_none();
        };

        let (mtime, _, ino) = stamp_of(&metadata);
        metadata.is_dir()
            && self
                .state
                .as_ref()
                .is_some_and(|(m, _, i)| *m == mtime && *i == ino)
    }
}

fn stamp_of(metadata: &std::fs::Metadata) -> (SystemTime, u64, u64) {
    (
        metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        metadata.len(),
        metadata.ino(),
    )
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

/// Every directory that could gain or lose a file, as it is now.
///
/// A new file always changes the mtime of the directory holding it, so watching every parent of a
/// tracked or untracked entry is enough to notice files appearing and disappearing anywhere,
/// including in directories that are new: the parent of a new directory is watched, and the
/// worktree root is watched as well.
///
/// The inode is watched along with the mtime, so that a directory which was replaced - by a
/// symbolic link, another directory, or a file - is noticed even when the mtime it reports through
/// the replacement happens to be the one that was recorded.
fn watch_dirs(shared: &ThreadSafeRepository, report: &status::Report) -> Option<Vec<FileStamp>> {
    let repo = shared.to_thread_local();
    let workdir = repo.workdir()?.to_owned();

    let mut rel: HashSet<Vec<u8>> = HashSet::new();
    rel.insert(Vec::new());

    if let Ok(index) = repo.index_or_empty() {
        for entry in index.entries() {
            insert_parents(&mut rel, entry.path(&index));
        }
    }

    // The parents of what the directory walk reported as untracked are watched as well, so that
    // files vanishing from an untracked directory (and with it the untracked status) are noticed.
    for path in &report.untracked {
        insert_parents(&mut rel, path);
    }

    if rel.len() > MAX_WATCHED_DIRS {
        return None;
    }

    let mut dirs: Vec<PathBuf> = rel
        .into_iter()
        .map(|path| workdir.join(OsStr::from_bytes(&path)))
        .collect();
    dirs.sort();

    Some(
        dirs.par_iter()
            .with_min_len(PARALLEL_THRESHOLD)
            .map(FileStamp::read)
            .collect(),
    )
}

/// Add every directory above `path` to `rel`.
///
/// With `path` relative to the worktree, these are the components of the path that end at a `/`,
/// which is every directory it can be in.
fn insert_parents(rel: &mut HashSet<Vec<u8>>, path: &[u8]) {
    for pos in (0..path.len()).filter(|pos| path[*pos] == b'/') {
        rel.insert(path[..pos].to_vec());
    }
}

fn dirs_unchanged(dirs: &[FileStamp]) -> bool {
    dirs.par_iter()
        .with_min_len(PARALLEL_THRESHOLD)
        .all(FileStamp::dir_matches)
}

/// How long a guard may be used without re-verifying the assumption that directory mtimes change
/// when files appear or disappear.
///
/// Filesystems that don't do that (some network ones) would otherwise keep a stale status for as
/// long as the daemon lives.
fn trust_window() -> Duration {
    Duration::from_secs(env_u64("BASH_GIT_STATUS_TRUST_SECS", 60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_directory_above_a_path_is_watched() {
        let mut rel = HashSet::new();
        insert_parents(&mut rel, b"a/b/c.txt");

        assert_eq!(rel.len(), 2);
        assert!(rel.contains(b"a".as_slice()));
        assert!(rel.contains(b"a/b".as_slice()));

        // A path in the root of the worktree has no directory of its own; the root is watched
        // separately.
        insert_parents(&mut rel, b"top.txt");
        assert_eq!(rel.len(), 2);
    }

    #[test]
    fn a_file_written_in_the_index_second_is_racy() {
        let time = |secs, nsecs| gix::index::entry::stat::Time { secs, nsecs };

        assert!(!is_racy((100, 0), time(99, 999_999_999)));
        assert!(!is_racy((100, 500), time(100, 499)));
        assert!(is_racy((100, 500), time(100, 500)));
        assert!(is_racy((100, 500), time(100, 501)));
        assert!(is_racy((100, 0), time(101, 0)));
        // A filesystem that reports no nanoseconds leaves whole seconds racy.
        assert!(is_racy((100, 0), time(100, 0)));
    }
}
