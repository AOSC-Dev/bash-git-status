//! A small per-shell daemon that caches repository status.
//!
//! Each shell starts one daemon over two pipes it keeps open (see `contrib/bash-git-status.bash`),
//! and every `bash-git-status` call in that shell asks it for the prompt text and exit code of the
//! current directory. Every directory of a repository shares one entry, and the entry is reused for
//! as long as the repository is unchanged: staged changes, the branch and a modified, added or
//! removed file all invalidate it (see `crate::cache`). Repositories that can't be watched at all
//! are recomputed once their entry is older than `BASH_GIT_STATUS_TTL_MS`, and directories outside
//! any repository are kept for just as long (default 500ms).
//!
//! An entry is only answered from for `BASH_GIT_STATUS_TRUST_SECS` (see
//! [`crate::cache::trust_window()`]): once that passed, the prompt it would answer waits for the
//! status to be computed from scratch again, which is what re-establishes the trust in directory
//! mtimes that a status is given for that long.
//!
//! Requests and replies are single lines over the pipes, and a reply is matched to its request by
//! the process id of the client, so a client that gave up waiting can't be confused by an answer
//! that arrives later.
//!
//! A daemon computes the status of a repository that it has nothing cached for itself, which a
//! shell that was just started pays once per repository. The daemon exits when its shell closes the
//! pipes, or when the shell goes away without closing them.
//!
//! `BASH_GIT_STATUS_SERVER_LOG` redirects the daemon's standard error into a file for debugging,
//! and `BASH_GIT_STATUS_NO_SERVER=1` keeps the client from asking the daemon at all.

use crate::cache::{self, Guard};
use crate::status::{self, Status};
use log::{debug, info};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{FileType, fstat};
use rustix::process::{Signal, set_parent_process_death_signal};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{BorrowedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Protocol marker, so a garbage line can't be taken for a request or a reply.
const PREFIX: &str = "BGS1 ";

/// How long a client waits for the daemon before computing the status itself.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// How much of a reply to hold on to; the longest one holds a branch or tag name.
const REPLY_LIMIT: usize = 4096;

/// How many statuses to remember, so a daemon that saw many repositories doesn't grow forever.
const MAX_ENTRIES: usize = 32;

enum Entry {
    /// The status of a whole repository, shared by every directory inside it and reused as long as
    /// its [`Guard`] doesn't see a change. The code lives in the guard's state.
    Repo {
        /// Boxed because a guard is far larger than the other variant.
        guard: Box<Guard>,
        last_used: Instant,
    },

    /// The status of a single directory, kept for a fixed amount of time because it can't be
    /// watched for changes.
    Dir {
        code: i32,
        text: String,
        computed_at: Instant,
    },
}

impl Entry {
    fn last_used(&self) -> Instant {
        match self {
            Entry::Repo { last_used, .. } => *last_used,
            Entry::Dir { computed_at, .. } => *computed_at,
        }
    }
}

/// What the daemon remembers between requests: one entry per repository root, and one per directory
/// that isn't inside a repository.
type Cache = HashMap<PathBuf, Entry>;

/// Run the daemon, reading requests from the standard input and answering on the standard output.
pub fn run() -> ! {
    redirect_log();
    watch_parent();
    info!("serving requests on the pipes");

    let mut cache = Cache::new();
    let mut stdin = BufReader::new(std::io::stdin().lock());
    let mut stdout = std::io::stdout().lock();
    let mut request = Vec::new();

    loop {
        request.clear();
        match stdin.read_until(b'\n', &mut request) {
            // The shell is gone, and with it whoever would read an answer.
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                debug!("failed to read a request: {e}");
                break;
            }
        }

        let Some((id, ttl, cwd)) = parse_request(&request) else {
            continue;
        };

        // Every directory of a repository shares one entry, keyed by its root.
        let root = repo_root(&cwd);
        let (code, text) = answer(&cwd, ttl, root.as_deref(), &mut cache);

        if writeln!(stdout, "{PREFIX}{id} {code} {text}").is_err() || stdout.flush().is_err() {
            break;
        }
    }

    std::process::exit(0)
}

/// Read `BGS1 <id> <ttl-ms> <path>`; anything else is ignored.
fn parse_request(line: &[u8]) -> Option<(u32, Duration, PathBuf)> {
    let line = line.strip_prefix(PREFIX.as_bytes())?;
    let line = line.strip_suffix(b"\n").unwrap_or(line);

    let (id, rest) = split_field(line)?;
    let (ttl, path) = split_field(rest)?;
    if path.is_empty() {
        return None;
    }

    Some((
        std::str::from_utf8(id).ok()?.parse().ok()?,
        Duration::from_millis(std::str::from_utf8(ttl).ok()?.parse().ok()?),
        PathBuf::from(OsStr::from_bytes(path)),
    ))
}

/// Split the first space-separated field off `line`.
fn split_field(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let pos = line.iter().position(|b| *b == b' ')?;
    Some((&line[..pos], &line[pos + 1..]))
}

/// The answer for `cwd`, computed if nothing that is already remembered covers it.
fn answer(cwd: &Path, ttl: Duration, root: Option<&Path>, cache: &mut Cache) -> (i32, String) {
    if let Some(root) = root
        && let Some(answer) = reuse_repo(root, cache)
    {
        return answer;
    }

    if let Some(answer) = reuse_dir(cwd, cache, ttl) {
        return answer;
    }

    let (code, text, cached) = compute(cwd, root);
    remember(cache, cached.key, cached.entry);
    (code, text)
}

/// The root of the repository `cwd` is in, if it can be found without opening the repository.
///
/// Repositories are watched per root, so that moving between directories doesn't invalidate
/// anything.
fn repo_root(cwd: &Path) -> Option<PathBuf> {
    let mut dir = cwd.to_path_buf();
    loop {
        if dir.join(".git").symlink_metadata().is_ok() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Answer a request for a repository whose status was computed before and didn't change since.
fn reuse_repo(root: &Path, cache: &mut Cache) -> Option<(i32, String)> {
    let Some(Entry::Repo { guard, last_used }) = cache.get_mut(root) else {
        return None;
    };
    *last_used = Instant::now();

    // A status is only given for a limited time, see `cache::trust_window()`: what the guard
    // checks is that the repository still looks the way it did, and the assumption that makes that
    // sufficient is trusted again only by computing the status from scratch.
    if !guard.fresh() {
        return None;
    }

    // Checking runs the expensive part, and only once it is done is the answer known to be reusable.
    let code = match guard.check() {
        cache::Verdict::Unchanged => guard.code(),
        cache::Verdict::Changed => Status::Change.into(),
        cache::Verdict::Unknown => return None,
    };

    // The text is cheap to compute and changes without the status changing, for example when
    // another tag now points at `HEAD`.
    let text = status::progress_of(guard.shared()).ok()?;

    Some((code, text))
}

/// Answer a request from the time-based entry for `cwd`, if there is a fresh one.
fn reuse_dir(cwd: &Path, cache: &mut Cache, ttl: Duration) -> Option<(i32, String)> {
    let Some(Entry::Dir {
        code,
        text,
        computed_at,
    }) = cache.get(cwd)
    else {
        return None;
    };

    (computed_at.elapsed() < ttl).then(|| (*code, text.clone()))
}

/// A status and the cache entry that would let a later request skip computing it.
struct Cached {
    key: PathBuf,
    entry: Entry,
}

/// Compute the answer for `cwd`, like [`status::compute()`], and remember it if possible.
fn compute(cwd: &Path, root: Option<&Path>) -> (i32, String, Cached) {
    let Ok(repo) = status::get_repo(cwd) else {
        return without_repo(cwd);
    };
    let Ok(text) = status::repo_progress(&repo) else {
        return without_repo(cwd);
    };

    let report = status::report(&repo);
    let code: i32 = report.status.into();

    // Only a status that covers the repository as a whole can be watched: a sparse index is served
    // by `git status` for the current directory, and an error leaves nothing worth reusing.
    let guard = match root {
        Some(root)
            if matches!(
                report.status,
                Status::Unchange | Status::Change | Status::Untracked
            ) && !status::is_sparse(&repo) =>
        {
            cache::Guard::capture(&repo, &report).map(|guard| (root.to_path_buf(), guard))
        }
        _ => None,
    };

    let cached = match guard {
        Some((root, guard)) => Cached {
            key: root,
            entry: Entry::Repo {
                guard: Box::new(guard),
                last_used: Instant::now(),
            },
        },
        None => Cached {
            key: cwd.to_path_buf(),
            entry: Entry::Dir {
                code,
                text: text.clone(),
                computed_at: Instant::now(),
            },
        },
    };

    (code, text, cached)
}

/// The historical answer for a directory that isn't a repository, or can't be inspected.
fn without_repo(cwd: &Path) -> (i32, String, Cached) {
    let (code, text) = (1, String::new());
    let cached = Cached {
        key: cwd.to_path_buf(),
        entry: Entry::Dir {
            code,
            text: text.clone(),
            computed_at: Instant::now(),
        },
    };

    (code, text, cached)
}

/// Keep an entry in the cache, evicting the least recently used ones beyond [`MAX_ENTRIES`].
fn remember(cache: &mut Cache, key: PathBuf, entry: Entry) {
    cache.insert(key, entry);

    while cache.len() > MAX_ENTRIES {
        let oldest = cache
            .iter()
            .min_by_key(|(_, entry)| entry.last_used())
            .map(|(key, _)| key.clone());
        match oldest {
            Some(oldest) => {
                cache.remove(&oldest);
            }
            None => break,
        }
    }
}

/// Answer a prompt query, preferring the daemon of the shell and falling back to computing
/// in-process when this shell has none.
pub fn query_or_compute(cwd: &Path) -> (i32, String) {
    query(cwd).unwrap_or_else(|| status::compute(cwd))
}

fn query(cwd: &Path) -> Option<(i32, String)> {
    let request_fd = daemon_fd("BASH_GIT_STATUS_FD_IN")?;
    let response_fd = daemon_fd("BASH_GIT_STATUS_FD_OUT")?;

    let id = std::process::id();
    let mut request = Vec::with_capacity(PREFIX.len() + 32 + cwd.as_os_str().len());
    request.extend_from_slice(PREFIX.as_bytes());
    request.extend_from_slice(id.to_string().as_bytes());
    request.push(b' ');
    request.extend_from_slice(ttl().as_millis().to_string().as_bytes());
    request.push(b' ');
    request.extend_from_slice(cwd.as_os_str().as_bytes());
    request.push(b'\n');
    write_all(request_fd, &request).ok()?;

    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    let mut pending = Vec::new();
    let mut buffer = [0u8; 256];
    loop {
        // Anything longer than a reply means the descriptor isn't the daemon's.
        if pending.len() > REPLY_LIMIT {
            return None;
        }

        while let Some(end) = pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            if let Some(answer) = parse_reply(&line, id) {
                return Some(answer);
            }
        }

        if !readable(response_fd, deadline)? {
            return None;
        }

        match rustix::io::read(response_fd, &mut buffer[..]) {
            // The daemon is gone, so it won't answer.
            Ok(0) => return None,
            Ok(read) => pending.extend_from_slice(&buffer[..read]),
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return None,
        }
    }
}

/// Read `BGS1 <id> <code> <text>`, or `None` for a reply to another request.
fn parse_reply(line: &[u8], id: u32) -> Option<(i32, String)> {
    let line = line.strip_prefix(PREFIX.as_bytes())?;
    let line = line.strip_suffix(b"\n").unwrap_or(line);

    let (reply_id, rest) = split_field(line)?;
    if reply_id != id.to_string().as_bytes() {
        return None;
    }

    let (code, text) = split_field(rest)?;
    Some((
        std::str::from_utf8(code).ok()?.parse().ok()?,
        String::from_utf8_lossy(text).into_owned(),
    ))
}

/// The descriptor the shell wired to the daemon, if it did.
///
/// `contrib/bash-git-status.bash` exports the numbers of the pipes it started the daemon with; the
/// check that they are pipes keeps a stray descriptor from being written to or waited on.
fn daemon_fd(name: &str) -> Option<BorrowedFd<'static>> {
    let number = std::env::var(name).ok()?.parse::<RawFd>().ok()?;
    if number < 0 {
        return None;
    }

    // SAFETY: the descriptor belongs to the shell and outlives this process, which only borrows it.
    let fd = unsafe { BorrowedFd::borrow_raw(number) };
    (FileType::from_raw_mode(fstat(fd).ok()?.st_mode) == FileType::Fifo).then_some(fd)
}

fn write_all(fd: BorrowedFd<'_>, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        match rustix::io::write(fd, bytes) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
            Ok(written) => bytes = &bytes[written..],
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

/// Wait for the daemon to answer, `false` if it took it longer than [`RESPONSE_TIMEOUT`].
fn readable(fd: BorrowedFd<'_>, deadline: Instant) -> Option<bool> {
    let left = deadline.saturating_duration_since(Instant::now());
    let timeout = Timespec {
        tv_sec: left.as_secs().try_into().ok()?,
        tv_nsec: left.subsec_nanos().into(),
    };

    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    poll(&mut fds, Some(&timeout)).ok().map(|ready| ready > 0)
}

/// Move the log to the file the environment asks for, as it would otherwise be written to the
/// shell's terminal, where it would appear in the prompt.
fn redirect_log() {
    let Some(path) = std::env::var_os("BASH_GIT_STATUS_SERVER_LOG") else {
        return;
    };
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };

    let _ = rustix::stdio::dup2_stderr(&file);
}

/// Exit with the shell that started us, which the pipes alone don't notice while one of the shell's
/// background jobs keeps them open.
fn watch_parent() {
    if set_parent_process_death_signal(Some(Signal::TERM)).is_err() {
        debug!("failed to watch the parent process");
    }
}

/// The freshness window requested by the client for a cache hit.
fn ttl() -> Duration {
    Duration::from_millis(env_u64("BASH_GIT_STATUS_TTL_MS", 500))
}

pub(crate) fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
