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

    /// Every directory that could gain or lose a file, with the metadata it had when the guard was
    /// captured.
    dirs: Vec<FileStamp>,

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
    /// Record the state of the repository that `report` was computed for.
    ///
    /// Returns `None` if the repository can't be watched for changes reliably, in which case the
    /// caller has to fall back to keeping its result for a fixed amount of time.
    pub fn capture(repo: &status::Repo, report: &status::Report, watch: Watch) -> Option<Guard> {
        let shared = &repo.repo;
        let tl = shared.to_thread_local();
        let git_dir = tl.git_dir().to_owned();
        tl.workdir()?;

        let mut fingerprint = vec![
            FileStamp::read(tl.index_path()),
            FileStamp::read(git_dir.join("HEAD")),
        ];
        fingerprint.extend(head_stamps(&git_dir, tl.common_dir())?);

        let dirs = watch.dirs()?;
        let global_rules = tl
            .config_snapshot()
            .trusted_path("core.excludesFile")
            .ok()
            .flatten();

        Some(Guard {
            repo: shared.clone(),
            code: report.status.into(),
            staged: report.staged,
            fingerprint,
            rules: rule_stamps(&git_dir, tl.common_dir(), &dirs, global_rules.as_deref()),
            dirs: stamp_all(&dirs),
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

        let (dirs, rules) = rayon::join(
            || {
                self.dirs
                    .par_iter()
                    .with_min_len(PARALLEL_THRESHOLD)
                    .all(FileStamp::dir_matches)
            },
            || {
                self.rules
                    .par_iter()
                    .with_min_len(PARALLEL_THRESHOLD)
                    .all(FileStamp::matches)
            },
        );
        if !(dirs && rules) {
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

/// A worktree walk that records the directories it descends into.
///
/// It is started before the status of a repository is computed and read afterwards, because both
/// walk the worktree and the operating system can do that on two cores at once.
pub struct Watch(Option<std::thread::JoinHandle<Option<Vec<PathBuf>>>>);

impl Watch {
    /// Start recording the directories of `shared`'s worktree.
    pub fn start(shared: &ThreadSafeRepository) -> Watch {
        let shared = shared.clone();
        let walk = std::thread::Builder::new()
            .name("bash-git-status walk".into())
            .spawn(move || watch_dirs(&shared));

        Watch(walk.ok())
    }

    /// The directories the walk descended into.
    fn dirs(self) -> Option<Vec<PathBuf>> {
        self.0?.join().ok()?
    }
}

/// Every directory that could gain or lose a file, as it is now.
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
fn watch_dirs(shared: &ThreadSafeRepository) -> Option<Vec<PathBuf>> {
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
        .into_iter()
        .map(|path| workdir.join(OsStr::from_bytes(&path)))
        .collect();
    dirs.sort();

    Some(dirs)
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

/// The files that decide which files a status scan reports, and that can change without any
/// directory changing: the ignore rules of the worktree, of the repository, of the user and of the
/// system, and the configuration that selects them.
///
/// A rule file that appears or disappears changes the mtime of the directory holding it, which is
/// watched, but editing one that exists doesn't, so the metadata of the file itself is watched
/// too. The configuration is watched because it says which global rule file applies, because it
/// can turn untracked reporting off, and because of what it includes, see [`config_files()`].
fn rule_stamps(
    git_dir: &Path,
    common_dir: &Path,
    dirs: &[PathBuf],
    global_excludes: Option<&Path>,
) -> Vec<FileStamp> {
    // Two metadata calls per watched directory: listing one instead would cost a lookup per entry
    // it holds, which is more than the calls it saves. Only the ones that are there are kept - a
    // rule file that appears changes the mtime of the directory holding it, which is watched, so
    // watching the ones that exist is enough, and a stamp of a file that isn't there would be
    // looked at again on every check.
    let mut rules: Vec<FileStamp> = dirs
        .par_iter()
        .with_min_len(PARALLEL_THRESHOLD)
        .flat_map_iter(|dir| {
            [dir.join(".gitignore"), dir.join(".gitattributes")]
                .into_iter()
                .map(FileStamp::read)
                .filter(|stamp| stamp.state.is_some())
        })
        .collect();

    for path in [
        common_dir.join("info/exclude"),
        common_dir.join("info/attributes"),
    ] {
        rules.push(FileStamp::read(path));
    }

    // The global rule file `core.excludesFile` points at, wherever it is.
    if let Some(global) = global_excludes {
        rules.push(FileStamp::read(global));
    }

    rules.extend(global_rule_files().into_iter().map(FileStamp::read));

    // The configuration, and the files it includes: what an `include.path` points at is read as if
    // it were written in the file that includes it, so a change there changes the status without
    // any watched file changing.
    rules.extend(
        config_files(config_roots(git_dir, common_dir))
            .into_iter()
            .map(FileStamp::read),
    );

    rules
}

/// The rule files of the user, at the place git looks for them when `core.excludesFile` is not
/// set: `$XDG_CONFIG_HOME/git/ignore`, which is `$HOME/.config/git/ignore` by default.
fn global_rule_files() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|home| home.join(".config")));

    config_home
        .map(|config_home| vec![config_home.join("git/ignore")])
        .unwrap_or_default()
}

/// The configuration files git reads for a repository, in the places it looks for them.
fn config_roots(git_dir: &Path, common_dir: &Path) -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|home| home.join(".config")));

    let mut paths = vec![
        std::env::var_os("GIT_CONFIG_SYSTEM")
            .map_or_else(|| PathBuf::from("/etc/gitconfig"), PathBuf::from),
        common_dir.join("config"),
        git_dir.join("config.worktree"),
    ];
    if let Some(config_home) = &config_home {
        paths.push(config_home.join("git/config"));
    }
    if let Some(home) = &home {
        paths.push(home.join(".gitconfig"));
    }
    if let Some(global) = std::env::var_os("GIT_CONFIG_GLOBAL") {
        paths.push(PathBuf::from(global));
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
fn config_files(roots: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
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
            include_paths(&path)
                .into_iter()
                .map(|included| (included, depth + 1)),
        );
        files.push(path);
    }

    files
}

/// The files `path` includes, as the `path` of its `include` sections name them.
fn include_paths(path: &Path) -> Vec<PathBuf> {
    let Ok(config) =
        gix::config::File::from_path_no_includes(path.to_owned(), gix::config::Source::Local)
    else {
        return Vec::new();
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
        .filter_map(|value| included_config(value, path.parent()))
        .collect()
}

/// Resolve what an `include.path` says to the file it points at.
///
/// Relative paths are relative to the file that includes them, and a leading `~/` is the home
/// directory, as in the configuration itself.
fn included_config(value: impl AsRef<[u8]>, dir: Option<&Path>) -> Option<PathBuf> {
    let path = Path::new(OsStr::from_bytes(value.as_ref()));

    match path.strip_prefix("~").ok() {
        Some(rest) => Some(std::env::var_os("HOME").map(PathBuf::from)?.join(rest)),
        None => Some(dir?.join(path)),
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
mod tests {
    use super::*;

    /// A repository of its own, in a directory that is removed when the test ends.
    struct TempRepo {
        path: PathBuf,
    }

    impl TempRepo {
        fn new(name: &str) -> TempRepo {
            let path = std::env::temp_dir().join(format!(
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

        /// Capture a guard of the repository as it is now, as the daemon would.
        fn capture(&self) -> Guard {
            let repo = self.open();
            let watch = Watch::start(&repo.repo);
            let report = status::report(&repo);

            Guard::capture(&repo, &report, watch).expect("the repository can be watched")
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
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

        let dirs = watch_dirs(&repo.open().repo).expect("the worktree can be walked");

        assert!(dirs.contains(&repo.path.join("empty")));
        assert!(!dirs.iter().any(|dir| dir.ends_with("ignored")));
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
