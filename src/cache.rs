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
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use gix::ThreadSafeRepository;
use gix::config::Source;
use gix::config::source::Kind;
use rayon::prelude::*;

use crate::server::env_u64;
use crate::status::{self, Status};

/// How many directories can be watched before a repository is considered too large to watch.
const MAX_WATCHED_DIRS: usize = 64 * 1024;

/// Below this many items a check runs in the thread that asked for it: waking up another one costs
/// more than the `stat` calls it would take over.
const PARALLEL_THRESHOLD: usize = 64;

/// How a cached status fares against the current state of its repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// The directories that could gain or lose a file, and the rule files beside them, with the
    /// metadata they had when the guard was captured, see [`watch_dirs()`]. Shared, because the next
    /// capture of this repository can take them over instead of walking the worktree again.
    worktree: Arc<Stamped>,

    /// The ignore rules and the configuration that selects them, which can change what a scan
    /// reports without changing a directory, see [`rule_stamps()`].
    rules: Vec<FileStamp>,

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
    /// Compute the status of `repo`, and record the state it was computed for.
    ///
    /// The recording comes first, down to the walk that finds the directories a scan will descend
    /// into: a stamp taken while the status is computed can record a change the status hasn't seen,
    /// and the guard would then look valid for a status that is older than its stamps. That is why
    /// the worktree is walked before the scan rather than beside it, even though both walk it.
    ///
    /// The guard is `None` when the repository can't be watched for changes reliably, in which case
    /// the caller has to compute its status again for every request.
    pub fn record(
        repo: &status::Repo,
        status: impl FnOnce(&status::Repo) -> status::Report,
        previous: Option<&Guard>,
    ) -> (status::Report, Option<Guard>) {
        let recorded = Guard::recorded(repo);
        // A repository that can't be recorded can't be watched, and walking it would be a waste.
        let watch = match recorded {
            Some(_) => previous
                .and_then(|guard| guard.reusable_worktree(&repo.repo))
                .or_else(|| watch_dirs(&repo.repo).map(Arc::new)),
            None => None,
        };

        let report = status(repo);
        let guard = match (recorded, watch) {
            (Some(recorded), Some(watched)) => Guard::capture(repo, &report, recorded, watched),
            _ => None,
        };

        (report, guard)
    }

    /// Record what a status of `repo` is read with, and what could change it.
    ///
    /// Everything except the worktree is read here, and the worktree by [`watch_dirs()`], both before
    /// the status is computed, see [`record()`](Guard::record).
    ///
    /// Returns `None` if the repository can't be watched for changes reliably.
    fn recorded(repo: &status::Repo) -> Option<Recorded> {
        let shared = &repo.repo;
        let tl = shared.to_thread_local();
        let git_dir = tl.git_dir().to_owned();
        let workdir = tl.workdir()?.to_owned();

        let mut fingerprint = vec![
            FileStamp::read(tl.index_path()),
            FileStamp::read(git_dir.join("HEAD")),
        ];
        fingerprint.extend(head_stamps(&git_dir, tl.common_dir())?);

        // The files that say where the repository is: a checkout of `git worktree` and a repository
        // made with `--separate-git-dir` have a `.git` file instead of a directory, and a linked
        // worktree a `commondir` file. Both are rewritten in place when the repository they point at
        // is changed, while everything below them - the index, the references - is watched as the
        // files of the repository this guard was captured for.
        let dot_git = workdir.join(".git");
        if !dot_git.is_dir() {
            fingerprint.push(FileStamp::read(dot_git));
        }
        fingerprint.push(FileStamp::read(git_dir.join("commondir")));

        let config = tl.config_snapshot();
        let excluding = config.trusted_path("core.excludesFile").ok().flatten();
        let attributing = config.trusted_path("core.attributesFile").ok().flatten();

        Some(Recorded {
            fingerprint,
            rules: rule_stamps(
                &git_dir,
                tl.common_dir(),
                excluding.as_deref(),
                attributing.as_deref(),
            )?,
        })
    }

    /// Record the state of the repository that `report` was computed for.
    fn capture(
        repo: &status::Repo,
        report: &status::Report,
        recorded: Recorded,
        worktree: Arc<Stamped>,
    ) -> Option<Guard> {
        Some(Guard {
            repo: repo.repo.clone(),
            code: report.status.into(),
            staged: report.staged,
            fingerprint: recorded.fingerprint,
            rules: recorded.rules,
            worktree,
            created: Instant::now(),
        })
    }

    /// What this guard recorded of the worktree, if the worktree still holds it and it is still
    /// everything a status of this repository looks into.
    ///
    /// Asking costs a `stat` call per directory and per rule file, which is what makes taking it over
    /// worthwhile over the [walk](watch_dirs()) that found them: that one reads every entry of the
    /// worktree and matches it against the ignore rules.
    ///
    /// Reusing them is as sound as the verdict this was asked for: what they recorded is older than
    /// the status that is about to be computed, and a change they don't see leaves a stamp that
    /// doesn't match any more, so the next check computes the status again. What they recorded has to
    /// cover what the new status looks at, though, which is what the rules and the index are asked
    /// for: the walk leaves out directories that the rules cover completely, and both can take that
    /// back.
    fn reusable_worktree(&self, shared: &ThreadSafeRepository) -> Option<Arc<Stamped>> {
        let worktree = &self.worktree;
        let (dirs, rules) = rayon::join(
            || {
                worktree
                    .dirs
                    .par_iter()
                    .with_min_len(PARALLEL_THRESHOLD)
                    .all(FileStamp::dir_matches)
            },
            || {
                worktree
                    .rules
                    .par_iter()
                    .with_min_len(PARALLEL_THRESHOLD)
                    .all(FileStamp::matches)
                    && self
                        .rules
                        .par_iter()
                        .with_min_len(PARALLEL_THRESHOLD)
                        .all(FileStamp::matches)
            },
        );

        (dirs && rules && self.index_is_inside(shared)).then(|| Arc::clone(&self.worktree))
    }

    /// Whether the directories the index tracks files in are directories the walk recorded.
    ///
    /// A directory whose contents the rules cover and in which nothing is tracked is left out of the
    /// [walk](watch_dirs()) - everything that can appear in it is covered as well, so watching it
    /// would be a `stat` call that can never matter. A file below it that the index tracks takes that
    /// back, and the index is the only one that can say so: the walk that recorded the directory as
    /// one that can be left out ran against an index without that file.
    fn index_is_inside(&self, shared: &ThreadSafeRepository) -> bool {
        let repo = shared.to_thread_local();
        let Ok(index) = repo.index_or_empty() else {
            return false;
        };

        index.entries().iter().all(|entry| {
            let path = entry.path(&index);
            path.iter()
                .enumerate()
                .filter(|(_, byte)| **byte == b'/')
                .all(|(at, _)| self.worktree.walked.contains(&path[..at]))
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

        // The configuration and the files it decides with come before the worktree is looked at:
        // whether a file counts as modified, and which files are reported at all, is decided with
        // the configuration the status was computed with, so a change in it - `core.filemode`, or
        // which files are ignored - makes the answer unknown even when the worktree still holds
        // what was recorded. Both `worktree_changed()` and the comparison it falls back to would
        // otherwise answer with the configuration of the repository this guard holds, which is the
        // one that was read when the status was computed.
        let (dirs, rules) = rayon::join(
            || {
                self.worktree
                    .dirs
                    .par_iter()
                    .with_min_len(PARALLEL_THRESHOLD)
                    .all(FileStamp::dir_matches)
            },
            || {
                self.worktree
                    .rules
                    .iter()
                    .chain(&self.rules)
                    .collect::<Vec<_>>()
                    .par_iter()
                    .with_min_len(PARALLEL_THRESHOLD)
                    .all(|stamp| stamp.matches())
            },
        );
        if !(dirs && rules) {
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
    /// The same, of what the path points at if it is a symbolic link, however long the chain.
    ///
    /// A rule or a configuration file is read through a link, so a change in the file at the end of
    /// it changes the answer while the link itself stays as it was. A link that can't be resolved -
    /// broken, or leading back to itself - is recorded as a missing file, which is what a direct
    /// computation is told as well: the kernel is what resolves them for both.
    pub(crate) followed: Option<(SystemTime, u64, u64)>,
}

impl FileStamp {
    /// Record `path` with the metadata it has now, and, if it is a symbolic link, with the metadata
    /// of what it points at, resolved by the kernel the way `git` resolves it.
    fn read(path: impl Into<PathBuf>) -> FileStamp {
        let path = path.into();
        let state = std::fs::symlink_metadata(&path).ok();
        let followed = state
            .as_ref()
            .filter(|state| state.is_symlink())
            .and_then(|_| std::fs::metadata(&path).ok());

        FileStamp {
            state: state.as_ref().map(stamp_of),
            path,
            followed: followed.as_ref().map(stamp_of),
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

/// The files to watch to notice `HEAD` moving: every reference from `HEAD` to the one that holds
/// the commit, and `packed-refs` as the other place a reference can be stored.
///
/// Without them, change detection would keep answering with the old status when commits are made or
/// the branch is switched. A reference can name another reference, so the chain is followed to its
/// end, where a reference that doesn't exist is watched as a missing file - which is how a branch
/// that is created later is noticed. A chain that leads in a circle is watched in full, and one
/// that is longer than [`MAX_LINKS`](head_stamps::MAX_LINKS) leaves the repository unwatched, as
/// does a reference backend that keeps references somewhere else (reftable).
fn head_stamps(git_dir: &Path, common_dir: &Path) -> Option<Vec<FileStamp>> {
    /// How many references a chain may have, which also bounds one that leads in a circle.
    const MAX_LINKS: usize = 16;

    let head = git_dir.join("HEAD");
    let packed = common_dir.join("packed-refs");

    // A detached HEAD stores the commit id itself, and that file is watched already.
    let Some(mut name) = symbolic_target(&head) else {
        return Some(Vec::new());
    };

    let mut stamps = Vec::new();
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(name.clone()) {
            break;
        }
        if stamps.len() == MAX_LINKS {
            return None;
        }

        let reference = common_dir.join(&name);
        let next = symbolic_target(&reference);
        stamps.push(FileStamp::read(reference));

        match next {
            Some(next) => name = next,
            None => break,
        }
    }

    // Both places a reference can be stored are watched: committing on a packed branch creates the
    // loose file, and packing references updates `packed-refs`. Where there is neither, the
    // references live somewhere else and there is nothing to watch.
    if stamps.iter().all(|stamp| stamp.state.is_none()) && packed.symlink_metadata().is_err() {
        return None;
    }

    stamps.push(FileStamp::read(packed));
    Some(stamps)
}

/// The reference a file of `refs` names, if it holds a symbolic reference.
///
/// `None` for a file that holds a commit id, and for one that is not there: a reference that doesn't
/// exist yet, as a branch without commits has, is watched as a missing file.
fn symbolic_target(path: &Path) -> Option<PathBuf> {
    let content = std::fs::read(path).ok()?;
    let content = content.strip_suffix(b"\n").unwrap_or(&content);
    let name = Path::new(OsStr::from_bytes(content.strip_prefix(b"ref: ")?));

    // A reference names a path below `refs/`, which is never absolute and never climbs out of the
    // directory the references are stored in.
    if name.is_absolute() || name.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }

    Some(name.to_owned())
}

/// What [`Guard::record()`] recorded before the status it guards was computed.
pub struct Recorded {
    fingerprint: Vec<FileStamp>,
    rules: Vec<FileStamp>,
}

/// The directories of a worktree and the rule files beside them, with what they looked like.
struct Stamped {
    /// Every directory the walk descended into, relative to the worktree, so that the index can be
    /// asked later whether these are still all the directories a status has to look into, see
    /// [`Guard::index_is_inside()`].
    walked: HashSet<Vec<u8>>,

    dirs: Vec<FileStamp>,
    rules: Vec<FileStamp>,
}

/// Every directory that could gain or lose a file, and the rule files beside them, as they are now.
///
/// The walk runs before the status of the repository is computed, and a stamp is taken as soon as
/// the walk has what it stamps, because a stamp taken later than the reads it is meant to guard can
/// record a change the status hasn't seen, see [`Guard::record()`].
///
/// A new file changes the mtime of the directory holding it, so watching every directory a status
/// scan descends into is enough to notice files appearing and disappearing anywhere - including in
/// directories that held no file at the time: an empty directory is descended into just like any
/// other, and so is a directory whose contents are all ignored. Directories that are ignored
/// themselves are left out, as everything that can be created in them is ignored as well.
///
/// The inode is watched along with the mtime, so that a directory which was replaced - by a
/// symbolic link, another directory, or a file - is noticed even when the mtime it reports through
/// the replacement happens to be the one that was recorded.
fn watch_dirs(shared: &ThreadSafeRepository) -> Option<Stamped> {
    let repo = shared.to_thread_local();
    let workdir = repo.workdir()?.to_owned();
    let index = repo.index_or_empty().ok()?;

    let mut walked = WatchDirs::default();
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    repo.dirwalk(
        &index,
        Vec::<gix::bstr::BString>::new(),
        &should_interrupt,
        repo.dirwalk_options().ok()?,
        &mut walked,
    )
    .ok()?;

    let mut rel = walked.0;
    rel.insert(Vec::new());
    if rel.len() > MAX_WATCHED_DIRS {
        return None;
    }

    let mut dirs: Vec<PathBuf> = rel
        .iter()
        .map(|path| workdir.join(OsStr::from_bytes(path)))
        .collect();
    dirs.sort();

    let dir_stamps = stamp_all(&dirs);
    // Two metadata calls per directory, in parallel: listing one instead would cost a lookup per
    // entry it holds, which is more than the calls it saves. Only the ones that are there are kept -
    // a rule file that appears changes the mtime of the directory holding it, which is watched, so
    // watching the ones that exist is enough, and a stamp of a file that isn't there would be
    // looked at again on every check.
    let rule_stamps = dirs
        .par_iter()
        .with_min_len(PARALLEL_THRESHOLD)
        .flat_map_iter(|dir| {
            [dir.join(".gitignore"), dir.join(".gitattributes")]
                .into_iter()
                .map(FileStamp::read)
                .filter(|stamp| stamp.state.is_some())
        })
        .collect();

    Some(Stamped {
        walked: rel,
        dirs: dir_stamps,
        rules: rule_stamps,
    })
}

/// The metadata of every path, as it is now.
fn stamp_all(paths: &[PathBuf]) -> Vec<FileStamp> {
    paths
        .par_iter()
        .with_min_len(PARALLEL_THRESHOLD)
        .map(FileStamp::read)
        .collect()
}

/// The directories a directory walk descends into.
///
/// [`can_recurse()`](gix::dir::walk::Delegate::can_recurse) is called for every directory the walk
/// sees, so recording the ones that are entered describes the worktree without listing it again:
/// the walk itself has that answer, and it knows which directories are ignored.
#[derive(Default)]
struct WatchDirs(HashSet<Vec<u8>>);

impl gix::dir::walk::Delegate for WatchDirs {
    fn emit(
        &mut self,
        _entry: gix::dir::EntryRef<'_>,
        _collapsed: Option<gix::dir::entry::Status>,
    ) -> gix::dir::walk::Action {
        std::ops::ControlFlow::Continue(())
    }

    fn can_recurse(
        &mut self,
        entry: gix::dir::EntryRef<'_>,
        for_deletion: Option<gix::dir::walk::ForDeletionMode>,
        worktree_root_is_repository: bool,
    ) -> bool {
        let recurse = entry.status.can_recurse(
            entry.disk_kind,
            entry.pathspec_match,
            for_deletion,
            worktree_root_is_repository,
        );
        if recurse {
            self.0.insert(entry.rela_path.to_vec());
        }
        recurse
    }
}

/// The files that decide which files a status scan reports and how, and that can change without
/// any directory changing: the ignore and attributes rules of the repository, of the user and of the
/// system, and the configuration that selects them. The rules of the worktree are stamped by the
/// [walk](Watch) that finds them.
///
/// The configuration is watched because it says which global rule file applies, because it can turn
/// untracked reporting off, and because of what it includes, see [`config_files()`].
fn rule_stamps(
    git_dir: &Path,
    common_dir: &Path,
    global_excludes: Option<&Path>,
    global_attributes: Option<&Path>,
) -> Option<Vec<FileStamp>> {
    let mut rules = Vec::new();

    for path in [
        common_dir.join("info/exclude"),
        common_dir.join("info/attributes"),
    ] {
        rules.push(FileStamp::read(path));
    }

    // The rule files `core.excludesFile` and `core.attributesFile` point at, wherever they are.
    for configured in [global_excludes, global_attributes].into_iter().flatten() {
        rules.push(FileStamp::read(configured));
    }

    rules.extend(global_rule_files().into_iter().map(FileStamp::read));

    // The configuration, and the files it includes: what an `include.path` points at is read as if
    // it were written in the file that includes it, so a change there changes the status without
    // any watched file changing.
    rules.extend(
        config_files(config_roots(git_dir, common_dir))?
            .into_iter()
            .map(FileStamp::read),
    );

    Some(rules)
}

/// The rule files at the places git reads them without being told to: the attributes file of the
/// system, and the rule files of the user that `core.excludesFile` and `core.attributesFile` default
/// to - `$XDG_CONFIG_HOME/git/ignore|attributes`, which are `$HOME/.config/git/ignore|attributes`
/// when `$XDG_CONFIG_HOME` is unset.
fn global_rule_files() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|home| home.join(".config")));

    // The system attributes file, which is `/etc/gitattributes` on unix.
    let mut paths = vec![PathBuf::from("/etc/gitattributes")];
    if let Some(config_home) = &config_home {
        paths.push(config_home.join("git/ignore"));
        paths.push(config_home.join("git/attributes"));
    }

    paths
}

/// The configuration files git reads for a repository, in the places it looks for them.
///
/// Where they are is [`storage_location()`](Source::storage_location)'s knowledge, asked for instead
/// of written down here: which configuration a git installation brings along, whether the system one
/// is overridden, where the user's is, and that a `git worktree` has a configuration of its own, all
/// depend on the git binary of the environment and on variables that only that call reads.
fn config_roots(git_dir: &Path, common_dir: &Path) -> Vec<PathBuf> {
    /// The kinds of configuration a status is read with, in the order they are loaded.
    const KINDS: [Kind; 5] = [
        Kind::GitInstallation,
        Kind::System,
        Kind::Global,
        Kind::Repository,
        Kind::Override,
    ];

    let mut env = |name: &str| std::env::var_os(name);
    let mut paths = Vec::new();
    for kind in KINDS {
        for source in kind.sources() {
            let Some(path) = source.storage_location(&mut env) else {
                continue;
            };

            // The configuration of the repository itself is named relative to it: `common_dir` holds
            // the one that is shared by every worktree, `git_dir` the one of this checkout.
            paths.push(match source {
                Source::Local => common_dir.join(path),
                Source::Worktree => git_dir.join(path),
                _ => path,
            });
        }
    }

    paths
}

/// Every configuration file that is read, with the ones that are included from them.
///
/// `roots` are the files a [repository's configuration](config_roots()) is read from. The files
/// they include are read as if their content were part of them, so they are watched as well.
///
/// Includes can be conditional (`includeIf`), and the condition is not evaluated: watching a file
/// that turns out not to be read only means a change in it recomputes the status, which costs
/// little compared to missing a change in one that is read.
fn config_files(roots: impl IntoIterator<Item = PathBuf>) -> Option<Vec<PathBuf>> {
    /// How deep git follows includes.
    const MAX_DEPTH: usize = 10;

    let mut files = Vec::new();
    let mut seen = HashSet::new();
    let mut pending: Vec<(PathBuf, usize)> = roots.into_iter().map(|path| (path, 0)).collect();

    while let Some((path, depth)) = pending.pop() {
        if depth > MAX_DEPTH || !seen.insert(path.clone()) {
            continue;
        }

        pending.extend(
            include_paths(&path)?
                .into_iter()
                .map(|included| (included, depth + 1)),
        );
        files.push(path);
    }

    Some(files)
}

/// The files `path` includes, as the `path` of its `include` sections name them.
///
/// `None` when one of them can't be resolved the way the configuration resolves it, see
/// [`included_config()`].
fn include_paths(path: &Path) -> Option<Vec<PathBuf>> {
    let Ok(config) =
        gix::config::File::from_path_no_includes(path.to_owned(), gix::config::Source::Local)
    else {
        return Some(Vec::new());
    };

    config
        .sections()
        .filter(|section| {
            let name = section.header().name();

            name.eq_ignore_ascii_case(b"include")
                || name
                    .get(..b"includeIf".len())
                    .is_some_and(|name| name.eq_ignore_ascii_case(b"includeIf"))
        })
        .flat_map(|section| section.body().values("path"))
        .map(|value| included_config(value, path.parent()))
        .collect()
}

/// Resolve what an `include.path` says to the file it points at, the way the configuration resolves
/// it: `~/` is the home directory of the user, `~user` the home of that user, and `%(prefix)` the
/// directory the binary is in. What is left relative is relative to the file that says it.
///
/// `None` when the path can't be resolved - a user that doesn't exist, for instance - because what
/// the include would read is not known then.
fn included_config(value: impl AsRef<[u8]>, dir: Option<&Path>) -> Option<PathBuf> {
    let home = gix::path::env::home_dir();
    let installation = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_owned));

    let path = gix::config::Path::from(gix::bstr::BStr::new(value.as_ref()))
        .interpolate(gix::config::path::interpolate::Context {
            git_install_dir: installation.as_deref(),
            home_dir: home.as_deref(),
            home_for_user: Some(gix::config::path::interpolate::home_for_user),
        })
        .ok()?;

    match path.is_absolute() {
        true => Some(path),
        false => Some(dir?.join(path)),
    }
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
pub(crate) mod tests {
    use super::*;
    use gix::config::path::interpolate::home_for_user;

    /// A repository of its own, in a directory that is removed when the test ends.
    pub(crate) struct TempRepo {
        pub(crate) path: PathBuf,
    }

    impl TempRepo {
        pub(crate) fn new(name: &str) -> TempRepo {
            TempRepo::new_in(&std::env::temp_dir(), name)
        }

        fn new_in(parent: &Path, name: &str) -> TempRepo {
            let path = parent.join(format!(
                "bash-git-status-test-{}-{name}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            gix::init(&path).expect("a repository can be created");
            let repo = TempRepo { path };
            repo.init_commit();

            repo
        }

        fn open(&self) -> status::Repo {
            status::get_repo(&self.path).expect("the repository can be opened")
        }

        /// Give the repository a commit, so that `HEAD` points at a reference that can be watched.
        fn init_commit(&self) {
            let repo = self.open().repo.to_thread_local();
            let tree = repo
                .write_object(gix::objs::Tree::empty())
                .expect("an empty tree can be written")
                .detach();
            let who = gix::actor::SignatureRef {
                name: "test".into(),
                email: "test@example.com".into(),
                time: "0 +0000",
            };

            repo.commit_as(who, who, "HEAD", "init", tree, None::<gix::ObjectId>)
                .expect("a commit can be created");
        }

        /// Track `name`, which holds `content`, in both `HEAD` and the index, so that a change to
        /// it is a change to the worktree and nothing is staged. `name` may name a file in a
        /// directory, which is created as one.
        fn track(&self, name: &str, content: &str) {
            let repo = self.open().repo.to_thread_local();
            let mut oid = repo
                .write_blob(content)
                .expect("a blob can be written")
                .detach();
            let mut kind = gix::objs::tree::EntryKind::Blob;
            for component in name.rsplit('/') {
                let mut tree = gix::objs::Tree::empty();
                tree.entries.push(gix::objs::tree::Entry {
                    mode: kind.into(),
                    filename: component.into(),
                    oid,
                });
                oid = repo
                    .write_object(&tree)
                    .expect("a tree can be written")
                    .detach();
                kind = gix::objs::tree::EntryKind::Tree;
            }
            let who = gix::actor::SignatureRef {
                name: "test".into(),
                email: "test@example.com".into(),
                time: "0 +0000",
            };
            let parent = repo.head_commit().expect("the repository has a commit").id;

            repo.commit_as(who, who, "HEAD", "track a file", oid, Some(parent))
                .expect("a commit can be created");

            let mut index = repo
                .index_from_tree(&oid)
                .expect("an index can be built from the tree");
            index
                .write(gix::index::write::Options::default())
                .expect("the index can be written");
        }

        /// Guard the repository as it is now, as the daemon would.
        fn capture(&self) -> Guard {
            let repo = self.open();
            let (_, guard) = Guard::record(&repo, status::report, None);

            guard.expect("the repository can be watched")
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn an_ignored_directory_the_index_reaches_into_is_walked_again() {
        let repo = TempRepo::new("index-reaches-into-an-ignored-directory");
        std::fs::write(repo.path.join(".gitignore"), "ignored/\n")
            .expect("the rule can be written");
        std::fs::create_dir(repo.path.join("ignored")).expect("the directory can be created");
        std::fs::write(repo.path.join("ignored/a.txt"), "a\n").expect("the file can be written");

        let first = repo.capture();
        assert!(
            !first.worktree.walked.contains(b"ignored".as_slice()),
            "a directory the rules cover and nothing is tracked in is left out of the walk"
        );

        // `git add --force ignored/a.txt`: the index now tracks a file in there, so the rules and the
        // attributes of that directory decide what the status of a file in it is.
        repo.track("ignored/a.txt", "a\n");
        assert!(
            first.reusable_worktree(&repo.open().repo).is_none(),
            "a directory the walk left out that the index reaches into is not taken over"
        );

        let (_, second) = Guard::record(&repo.open(), status::report, Some(&first));
        let second = second.expect("the repository can be watched");
        assert!(
            second.worktree.walked.contains(b"ignored".as_slice()),
            "the directory the index tracks a file in is watched"
        );
    }

    #[test]
    fn a_guard_is_not_taken_over_when_the_rules_changed() {
        let repo = TempRepo::new("changed-rules");
        let guard = repo.capture();

        // The configuration decides which files the rules are read from, so what a directory holds
        // can stop being covered without anything in the worktree changing.
        let config = repo.path.join(".git/config");
        let mut text = std::fs::read_to_string(&config).expect("the configuration can be read");
        text.push_str("[core]\n\texcludesFile = /dev/null\n");
        std::fs::write(&config, text).expect("the configuration can be written");

        assert!(
            guard.reusable_worktree(&repo.open().repo).is_none(),
            "a configuration that changed can leave out a directory the walk recorded"
        );
    }

    #[test]
    fn a_recorded_worktree_is_taken_over_only_while_it_holds() {
        let repo = TempRepo::new("reusable-worktree");
        let guard = repo.capture();

        assert!(
            guard.reusable_worktree(&repo.open().repo).is_some(),
            "a worktree that still holds what was recorded of it can be taken over"
        );

        std::fs::write(repo.path.join("appeared.txt"), "appeared\n")
            .expect("the file can be written");
        assert!(
            guard.reusable_worktree(&repo.open().repo).is_none(),
            "a worktree that changed has to be walked again"
        );
    }

    #[test]
    fn a_guard_that_took_over_a_worktree_still_notices_a_change() {
        let repo = TempRepo::new("reused-worktree");
        let first = repo.capture();

        // A change outside the worktree leaves the directories the first guard recorded in place, so
        // the second one takes them over instead of walking them again.
        repo.track("added.txt", "added\n");
        assert!(
            first.reusable_worktree(&repo.open().repo).is_some(),
            "the directories still hold, so they can be taken over"
        );
        let (_, second) = Guard::record(&repo.open(), status::report, Some(&first));
        let second = second.expect("the repository can be watched");

        std::fs::write(repo.path.join("later.txt"), "later\n").expect("the file can be written");
        assert_ne!(
            second.check(),
            Verdict::Unchanged,
            "a file that appeared in a directory that was taken over is noticed"
        );
    }

    #[test]
    fn a_change_made_while_the_status_is_computed_leaves_the_guard_unknown() {
        let repo = TempRepo::new("changed-while-computing");
        let opened = repo.open();

        // Whatever the status computation does, the change it makes here is one that only the work
        // after it can see: the guard is recorded before any of it, so it must not look valid for a
        // status that came before the change.
        let (_, guard) = Guard::record(
            &opened,
            |repo| {
                std::fs::write(repo.cwd.join("appeared.txt"), "appeared\n")
                    .expect("the file can be written");

                status::report(repo)
            },
            None,
        );

        assert_ne!(
            guard.expect("the repository can be watched").check(),
            Verdict::Unchanged
        );
    }

    #[test]
    fn every_configuration_gix_reads_is_watched() {
        let repo = TempRepo::new("configuration-roots");
        let git_dir = repo.path.join(".git");
        let roots = config_roots(&git_dir, &git_dir);

        let mut env = |name: &str| std::env::var_os(name);
        for kind in [
            Kind::GitInstallation,
            Kind::System,
            Kind::Global,
            Kind::Repository,
        ] {
            for source in kind.sources() {
                let Some(path) = source.storage_location(&mut env) else {
                    continue;
                };
                let path = match source {
                    Source::Local => git_dir.join(path),
                    Source::Worktree => git_dir.join(path),
                    _ => path,
                };

                assert!(
                    roots.contains(&path),
                    "{} is read as configuration but not watched",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn a_file_in_an_empty_directory_is_noticed() {
        let repo = TempRepo::new("empty-directory");
        std::fs::create_dir(repo.path.join("empty")).expect("the directory can be created");
        let guard = repo.capture();

        std::fs::write(repo.path.join("empty/new.txt"), "new\n").expect("the file can be written");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn a_change_behind_a_link_is_noticed() {
        let repo = TempRepo::new("linked-attributes");
        let target = repo.path.join("attributes.target");
        std::fs::write(&target, "*.txt\t-text\n").expect("the rule can be written");
        let link = repo.path.join("attributes");
        std::os::unix::fs::symlink(&target, &link).expect("the rule can be linked to");
        let config = repo.path.join(".git/config");
        let mut content = std::fs::read_to_string(&config).expect("the configuration can be read");
        content.push_str(&format!("[core]\n\tattributesFile = {}\n", link.display()));
        std::fs::write(&config, content).expect("the configuration can be written");

        let guard = repo.capture();
        std::fs::write(&target, "*.txt\ttext\n").expect("the rule can be edited");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn a_branch_behind_a_reference_is_noticed() {
        let repo = TempRepo::new("aliased-head");
        let git_dir = repo.path.join(".git");
        std::fs::create_dir_all(git_dir.join("refs/heads")).expect("the directory can be created");
        std::fs::write(git_dir.join("refs/heads/alias"), "ref: refs/heads/main\n")
            .expect("the alias can be written");
        std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/alias\n")
            .expect("HEAD can be pointed at the alias");

        let guard = repo.capture();

        // The branch the alias finally points at, updated where the alias itself doesn't change.
        std::fs::write(
            git_dir.join("refs/heads/main"),
            format!("{}\n", "b".repeat(40)),
        )
        .expect("the branch can be updated");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn a_git_file_that_points_elsewhere_is_noticed() {
        let repo = TempRepo::new("gitfile");
        let git_dir = repo.path.join("git-dir");
        std::fs::rename(repo.path.join(".git"), &git_dir).expect("the git directory can be moved");
        let git_file = repo.path.join(".git");
        std::fs::write(&git_file, format!("gitdir: {}\n", git_dir.display()))
            .expect("the git directory can be pointed at");

        let guard = repo.capture();
        let other = TempRepo::new("gitfile-other");
        std::fs::write(
            &git_file,
            format!("gitdir: {}\n", other.path.join(".git").display()),
        )
        .expect("the git file can be rewritten");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn a_change_behind_a_long_link_chain_is_noticed() {
        let repo = TempRepo::new("deep-linked-attributes");
        let target = repo.path.join("attributes.target");
        std::fs::write(&target, "*.txt\t-text\n").expect("the rule can be written");

        // A chain longer than any limit we could pick, which the kernel resolves all the same.
        let mut link = target.clone();
        for level in 0..12 {
            let next = repo.path.join(format!("attributes.{level}"));
            std::os::unix::fs::symlink(&link, &next).expect("the rule can be linked to");
            link = next;
        }

        let config = repo.path.join(".git/config");
        let mut content = std::fs::read_to_string(&config).expect("the configuration can be read");
        content.push_str(&format!("[core]\n\tattributesFile = {}\n", link.display()));
        std::fs::write(&config, content).expect("the configuration can be written");

        let guard = repo.capture();
        std::fs::write(&target, "*.txt\ttext\n").expect("the rule can be edited");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn a_changed_attributes_file_is_noticed() {
        let repo = TempRepo::new("attributes-file");
        let attributes = repo.path.join("attributes");
        std::fs::write(&attributes, "*.txt\t-text\n").expect("the rule can be written");
        let config = repo.path.join(".git/config");
        let mut content = std::fs::read_to_string(&config).expect("the configuration can be read");
        content.push_str(&format!(
            "[core]\n\tattributesFile = {}\n",
            attributes.display()
        ));
        std::fs::write(&config, content).expect("the configuration can be written");

        let guard = repo.capture();
        std::fs::write(&attributes, "*.txt\ttext\n").expect("the rule can be edited");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn a_changed_configuration_is_noticed_while_the_worktree_differs() {
        use std::os::unix::fs::PermissionsExt;

        let repo = TempRepo::new("configured-worktree");
        let file = repo.path.join("file.txt");
        std::fs::write(&file, "one\n").expect("the file can be written");
        repo.track("file.txt", "one\n");

        // An executable bit is a difference between the worktree and the index, unless the
        // configuration says that it isn't one.
        let mut permissions = std::fs::metadata(&file)
            .expect("the file exists")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&file, permissions).expect("the file can be made executable");
        let guard = repo.capture();
        assert_eq!(
            guard.code,
            Status::Change.into(),
            "the worktree differs from the index"
        );

        let config = repo.path.join(".git/config");
        let mut content = std::fs::read_to_string(&config).expect("the configuration can be read");
        content.push_str("[core]\n\tfilemode = false\n");
        std::fs::write(&config, content).expect("the configuration can be written");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn a_changed_included_configuration_is_noticed() {
        let repo = TempRepo::new("included-config");
        let included = repo.path.join("included.cfg");
        std::fs::write(&included, "[status]\n\tshowUntrackedFiles = no\n")
            .expect("the included file can be written");
        let config = repo.path.join(".git/config");
        let mut content = std::fs::read_to_string(&config).expect("the configuration can be read");
        content.push_str(&format!("[include]\n\tpath = {}\n", included.display()));
        std::fs::write(&config, content).expect("the configuration can be written");

        let guard = repo.capture();
        std::fs::write(&included, "[status]\n\tshowUntrackedFiles = all\n")
            .expect("the included file can be edited");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn an_included_path_naming_a_user_is_resolved_through_that_user() {
        let home = PathBuf::from(std::env::var_os("HOME").expect("a home directory"));

        assert_eq!(
            included_config("~/rules.cfg", None),
            Some(home.join("rules.cfg"))
        );
        assert_eq!(
            included_config("~root/rules.cfg", None),
            home_for_user("root").map(|home| home.join("rules.cfg"))
        );
        assert_eq!(included_config("~no-such-user/rules.cfg", None), None);
        assert_eq!(
            included_config("rules.cfg", Some(Path::new("/etc"))),
            Some(PathBuf::from("/etc/rules.cfg"))
        );
        assert_eq!(included_config("rules.cfg", None), None);
    }

    #[test]
    fn a_changed_configuration_included_as_a_user_home_path_is_noticed() {
        let Ok(user) = std::env::var("USER") else {
            return;
        };
        let home = gix::path::env::home_dir().expect("a home directory");
        if home_for_user(&user).as_deref() != Some(home.as_path()) {
            return;
        }

        let repo = TempRepo::new_in(&home, "user-home-config");
        let included = repo.path.join("included.cfg");
        std::fs::write(&included, "[status]\n\tshowUntrackedFiles = no\n")
            .expect("the included file can be written");
        let named = format!(
            "~{user}/{}",
            included.strip_prefix(&home).unwrap().display()
        );
        let config = repo.path.join(".git/config");
        let mut content = std::fs::read_to_string(&config).expect("the configuration can be read");
        content.push_str(&format!("[include]\n\tpath = {named}\n"));
        std::fs::write(&config, content).expect("the configuration can be written");

        let guard = repo.capture();
        std::fs::write(&included, "[status]\n\tshowUntrackedFiles = all\n")
            .expect("the included file can be edited");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn a_configuration_that_can_not_be_resolved_is_not_watched() {
        let repo = TempRepo::new("unresolvable-config");
        let config = repo.path.join(".git/config");
        let mut content = std::fs::read_to_string(&config).expect("the configuration can be read");
        content.push_str("[include]\n\tpath = ~no-such-user/rules.cfg\n");
        std::fs::write(&config, content).expect("the configuration can be written");

        assert!(
            Guard::record(&repo.open(), status::report, None)
                .1
                .is_none(),
            "a configuration that can't be resolved must leave the repository unwatched"
        );
    }

    #[test]
    fn an_included_configuration_that_appears_is_noticed() {
        let repo = TempRepo::new("appearing-config");
        let included = repo.path.join("included.cfg");
        let config = repo.path.join(".git/config");
        let mut content = std::fs::read_to_string(&config).expect("the configuration can be read");
        content.push_str(&format!("[include]\n\tpath = {}\n", included.display()));
        std::fs::write(&config, content).expect("the configuration can be written");

        let guard = repo.capture();
        std::fs::write(&included, "[status]\n\tshowUntrackedFiles = no\n")
            .expect("the included file can be written");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn an_edited_rule_file_is_noticed() {
        let repo = TempRepo::new("edited-rule");
        let rule = repo.path.join("sub/.gitignore");
        std::fs::create_dir(repo.path.join("sub")).expect("the directory can be created");
        std::fs::write(&rule, "*.log\n").expect("the rule can be written");
        let guard = repo.capture();

        std::fs::write(&rule, "*\n").expect("the rule can be edited");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn a_rule_file_that_appears_is_noticed() {
        let repo = TempRepo::new("new-rule");
        std::fs::create_dir(repo.path.join("sub")).expect("the directory can be created");
        let guard = repo.capture();

        std::fs::write(repo.path.join("sub/.gitignore"), "*.log\n")
            .expect("the rule can be written");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn a_changed_ignore_rule_is_noticed() {
        let repo = TempRepo::new("ignore-rule");
        let exclude = repo.path.join(".git/info/exclude");
        std::fs::write(&exclude, "*.log\n").expect("the rule can be written");
        let guard = repo.capture();

        std::fs::write(&exclude, "").expect("the rule can be taken back");

        assert_ne!(guard.check(), Verdict::Unchanged);
    }

    #[test]
    fn empty_directories_are_watched_and_ignored_ones_are_not() {
        let repo = TempRepo::new("watched-directories");
        std::fs::write(repo.path.join(".gitignore"), "ignored/\n")
            .expect("the rule can be written");
        std::fs::create_dir(repo.path.join("empty")).expect("the directory can be created");
        std::fs::create_dir(repo.path.join("ignored")).expect("the directory can be created");

        let Stamped { dirs, .. } =
            watch_dirs(&repo.open().repo).expect("the worktree can be walked");

        assert!(dirs.iter().any(|dir| dir.path == repo.path.join("empty")));
        assert!(!dirs.iter().any(|dir| dir.path.ends_with("ignored")));
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
