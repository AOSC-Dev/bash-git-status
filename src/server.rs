//! A small per-user daemon that caches repository status.
//!
//! Clients ask it over a unix socket for the prompt text and exit code of
//! their current directory. Every directory of a repository shares one entry,
//! and the entry is reused for as long as the repository is unchanged: staged
//! changes, the branch and a modified, added or removed file all invalidate it
//! (see `crate::cache`). Only when a repository can't be watched, or when its
//! entry is older than `BASH_GIT_STATUS_TRUST_SECS`, the answer is recomputed
//! unconditionally, and directories outside a repository are kept for
//! `BASH_GIT_STATUS_TTL_MS` (default 500ms).
//!
//! The daemon starts on demand, exits after `BASH_GIT_STATUS_IDLE_SECS`
//! (default 600) without requests, and a lock file next to the socket keeps
//! concurrent clients from spawning duplicates. `BASH_GIT_STATUS_SERVER_LOG`
//! redirects the daemon's stderr into a file for debugging.

use crate::cache::{self, Guard};
use crate::status::{self, Status};
use anyhow::{Context, Result};
use interprocess::local_socket::{
    GenericFilePath, ListenerOptions, Stream, ToFsName as _,
    traits::{ListenerExt as _, Stream as _},
};
use interprocess::os::unix::local_socket::ListenerOptionsExt as _;
use log::{debug, info};
use rustix::fs::{FlockOperation, flock};
use rustix::process::{getuid, setsid};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Protocol marker, so a client can't be fooled by a reply from an outdated daemon after the
/// binary was rebuilt, and so that a request can't be taken for a reply.
const PREFIX: &[u8] = b"BGS2 ";

/// The longest directory a request may ask about; a path that doesn't exist is longer than it can
/// be, and the length is what a client states rather than what it sent.
const MAX_PATH: usize = 8 * 1024;

/// The environment overrides that decide which repository a directory belongs to and what its
/// status is: `git` and the library honour them, so a daemon that was started by another shell -
/// with another idea of both - can't answer for a shell that has one of them set.
const ENVIRONMENT_OVERRIDES: [&str; 18] = [
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_ATTR_NOSYSTEM",
    "GIT_ATTR_SYSTEM",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_SYSTEM",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
];

/// How long a freshly spawned daemon gets to bind its socket.
const SPAWN_TIMEOUT: Duration = Duration::from_millis(500);

/// How many statuses to remember, so a daemon that saw many repositories doesn't grow forever.
const MAX_ENTRIES: usize = 32;

type Cache = Arc<Mutex<HashMap<PathBuf, Entry>>>;

enum Entry {
    /// The status of a whole repository, shared by every directory inside it and reused as long as
    /// its [`Guard`] doesn't see a change.
    Repo {
        code: i32,
        guard: Arc<Guard>,
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

/// Run the daemon; it either exits via [`std::process::exit`] or serves forever.
pub fn run() -> ! {
    drop_environment_overrides();

    let socket = socket_path();
    let lock_path = socket.with_extension("lock");
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("failed to open lock file {}", lock_path.display()))
        .unwrap_or_else(|e| {
            eprintln!("{e:#}");
            std::process::exit(1);
        });

    // Any lock failure means another daemon is already running.
    if flock(&lock_file, FlockOperation::NonBlockingLockExclusive).is_err() {
        info!("another daemon is already running");
        std::process::exit(0);
    }

    // Remove a leftover socket from a previous, uncleanly exited daemon.
    let _ = std::fs::remove_file(&socket);
    let listener = socket
        .as_path()
        .to_fs_name::<GenericFilePath>()
        .and_then(|name| ListenerOptions::new().name(name).mode(0o600).create_sync())
        .with_context(|| format!("failed to bind {}", socket.display()))
        .unwrap_or_else(|e| {
            eprintln!("{e:#}");
            std::process::exit(1);
        });
    info!("listening on {}", socket.display());

    let cache: Cache = Default::default();
    let last_activity = Arc::new(Mutex::new(Instant::now()));
    spawn_idle_monitor(socket, Arc::clone(&last_activity));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cache = Arc::clone(&cache);
                let last_activity = Arc::clone(&last_activity);
                thread::spawn(move || {
                    touch(&last_activity);
                    if let Err(e) = handle(stream, &cache) {
                        debug!("connection error: {e:#}");
                    }
                    touch(&last_activity);
                });
            }
            Err(e) => debug!("accept error: {e}"),
        }
    }
    unreachable!("the accept loop handles every error")
}

/// The name of an environment override that is set, if there is one.
fn environment_override(set: impl Fn(&str) -> Option<std::ffi::OsString>) -> Option<&'static str> {
    ENVIRONMENT_OVERRIDES
        .iter()
        .copied()
        .find(|name| set(name).is_some())
}

/// Remove the overrides a daemon must not answer with, see [`ENVIRONMENT_OVERRIDES`].
///
/// The clients that need one of them compute the status themselves, so removing them can't take an
/// answer away from anyone: it only keeps a daemon that was started with `GIT_DIR` - by hand, or by
/// an older client - from answering with that repository for every other client.
fn drop_environment_overrides() {
    for name in ENVIRONMENT_OVERRIDES {
        // SAFETY: nothing else has run yet, so no thread can read the environment concurrently.
        unsafe { std::env::remove_var(name) };
    }
}

/// Read a request, which is `BGS2 <ttl-ms> <len>` followed by that many bytes of a directory.
///
/// The path is sent as its length instead of being terminated: a directory whose name contains a
/// newline is then still the directory that was asked about, and not a prefix of it that happens to
/// be another repository.
fn read_request(reader: &mut impl BufRead) -> Result<Option<(Duration, PathBuf)>> {
    let mut header = Vec::new();
    if reader.read_until(b'\n', &mut header)? == 0 {
        return Ok(None);
    }

    let Some(rest) = header.strip_prefix(PREFIX) else {
        return Ok(None);
    };
    let rest = rest.strip_suffix(b"\n").unwrap_or(rest);
    let Some(space) = rest.iter().position(|b| *b == b' ') else {
        return Ok(None);
    };
    let parse = |field: &[u8]| std::str::from_utf8(field).ok()?.parse::<u64>().ok();
    let (Some(ttl), Some(len)) = (parse(&rest[..space]), parse(&rest[space + 1..])) else {
        return Ok(None);
    };
    let Ok(len) = usize::try_from(len) else {
        return Ok(None);
    };
    if len == 0 || len > MAX_PATH {
        return Ok(None);
    }

    let mut path = vec![0u8; len];
    reader.read_exact(&mut path)?;

    Ok(Some((
        Duration::from_millis(ttl),
        PathBuf::from(OsStr::from_bytes(&path)),
    )))
}

fn handle(mut stream: Stream, cache: &Cache) -> Result<()> {
    let mut reader = BufReader::new(&stream);
    let Some((ttl, cwd)) = read_request(&mut reader)? else {
        return Ok(());
    };

    // Every directory of a repository shares one entry, keyed by its root.
    let root = repo_root(&cwd);
    let answer = root
        .as_deref()
        .and_then(|root| reuse_repo(root, cache))
        .or_else(|| reuse_dir(&cwd, cache, ttl));
    let (code, text) = match answer {
        Some(answer) => answer,
        None => {
            let (code, text, cached) = compute(&cwd, root.as_deref());
            remember(cache, cached.key, cached.entry);
            (code, text)
        }
    };

    let mut reply = Vec::with_capacity(PREFIX.len() + 16 + text.len());
    reply.extend_from_slice(PREFIX);
    reply.extend_from_slice(code.to_string().as_bytes());
    reply.push(b'\n');
    reply.extend_from_slice(text.as_bytes());
    stream.write_all(&reply)?;
    Ok(())
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
fn reuse_repo(root: &Path, cache: &Cache) -> Option<(i32, String)> {
    let (code, guard) = {
        let mut cache = cache.lock().unwrap();
        let Some(Entry::Repo {
            code,
            guard,
            last_used,
        }) = cache.get_mut(root)
        else {
            return None;
        };
        if !guard.fresh() {
            return None;
        }
        *last_used = Instant::now();
        (*code, Arc::clone(guard))
    };

    // Checking runs the expensive part without holding the lock, and only then is the answer
    // known to be reusable.
    let code = match guard.check() {
        cache::Verdict::Unchanged => code,
        cache::Verdict::Changed => Status::Change.into(),
        cache::Verdict::Unknown => return None,
    };

    // The text is cheap to compute and changes without the status changing, for example when
    // another tag now points at `HEAD`.
    status::progress_of(guard.shared())
        .ok()
        .map(|text| (code, text))
}

/// Answer a request from the time-based entry for `cwd`, if there is a fresh one.
fn reuse_dir(cwd: &Path, cache: &Cache, ttl: Duration) -> Option<(i32, String)> {
    let cache = cache.lock().unwrap();
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

    // The worktree walk the guard needs runs while the status is computed, so that a repository
    // that has to be scanned anyway doesn't wait for it afterwards.
    let watch = cache::Watch::start(&repo.repo);
    let t = Instant::now();
    let report = status::report(&repo);
    debug!("DBGT scan {:?}", t.elapsed());
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
            let t = Instant::now();
            let g = cache::Guard::capture(&repo, &report, watch)
                .map(|guard| (root.to_path_buf(), guard));
            debug!("DBGT capture {:?}", t.elapsed());
            g
        }
        _ => None,
    };

    let cached = match guard {
        Some((key, guard)) => Cached {
            key,
            entry: Entry::Repo {
                code,
                guard: Arc::new(guard),
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
fn remember(cache: &Cache, key: PathBuf, entry: Entry) {
    let mut cache = cache.lock().unwrap();
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

/// Answer a prompt query, preferring the daemon and falling back to computing
/// in-process when the daemon cannot be reached.
pub fn query_or_compute(cwd: &Path) -> (i32, String) {
    query(cwd).unwrap_or_else(|| status::compute(cwd))
}

fn query(cwd: &Path) -> Option<(i32, String)> {
    // A shell that says where its repository is can't be answered by a daemon that was started by
    // one that didn't, so it computes the status itself.
    if let Some(name) = environment_override(|name| std::env::var_os(name)) {
        debug!("{name} is set, computing in-process");
        return None;
    }

    let socket = socket_path();
    if let Some(result) = try_query(&socket, cwd) {
        return Some(result);
    }

    // No daemon (or it is still starting): spawn one and give it a moment.
    spawn_server();
    let deadline = Instant::now() + SPAWN_TIMEOUT;
    loop {
        if let Some(result) = try_query(&socket, cwd) {
            return Some(result);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn try_query(socket: &Path, cwd: &Path) -> Option<(i32, String)> {
    let name = socket.to_fs_name::<GenericFilePath>().ok()?;
    let mut stream = Stream::connect(name).ok()?;
    let _ = stream.set_recv_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_send_timeout(Some(Duration::from_secs(5)));

    let path = cwd.as_os_str().as_bytes();
    let mut request = Vec::with_capacity(PREFIX.len() + 24 + path.len());
    request.extend_from_slice(PREFIX);
    request.extend_from_slice(ttl().as_millis().to_string().as_bytes());
    request.push(b' ');
    request.extend_from_slice(path.len().to_string().as_bytes());
    request.push(b'\n');
    request.extend_from_slice(path);
    stream.write_all(&request).ok()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;

    // A daemon of an older build answers in its own protocol; computing in-process is better than
    // reading that answer as this one.
    let response = response.strip_prefix(PREFIX)?;
    let newline = response.iter().position(|b| *b == b'\n')?;
    let (code, text) = response.split_at(newline);
    Some((
        std::str::from_utf8(code).ok()?.parse().ok()?,
        String::from_utf8(text[1..].to_vec()).ok()?,
    ))
}

fn spawn_server() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };

    let mut command = Command::new(exe);
    command
        .arg("--server")
        // The daemon outlives the directory it was spawned from, and a working directory that was
        // deleted in the meantime makes opening any repository fail, so it gets one that can't.
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null());

    match std::env::var_os("BASH_GIT_STATUS_SERVER_LOG") {
        Some(log) => match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
        {
            Ok(file) => {
                command.stderr(Stdio::from(file));
            }
            Err(_) => {
                command.stderr(Stdio::null());
            }
        },
        None => {
            command.stderr(Stdio::null());
        }
    }

    // SAFETY: `setsid` is async-signal-safe and does not allocate.
    unsafe {
        command.pre_exec(|| setsid().map(|_| ()).map_err(std::io::Error::from));
    }

    let _ = command.spawn();
}

fn socket_path() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("bash-git-status.sock"),
        _ => {
            let uid = getuid().as_raw();
            PathBuf::from(format!("/tmp/bash-git-status-{uid}.sock"))
        }
    }
}

fn touch(last_activity: &Mutex<Instant>) {
    *last_activity.lock().unwrap() = Instant::now();
}

fn spawn_idle_monitor(socket: PathBuf, last_activity: Arc<Mutex<Instant>>) {
    let idle = idle_timeout();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(1));
            if last_activity.lock().unwrap().elapsed() >= idle {
                let _ = std::fs::remove_file(&socket);
                info!("idle for {idle:?}, exiting");
                std::process::exit(0);
            }
        }
    });
}

/// The freshness window requested by the client for a cache hit.
fn ttl() -> Duration {
    Duration::from_millis(env_u64("BASH_GIT_STATUS_TTL_MS", 500))
}

fn idle_timeout() -> Duration {
    Duration::from_secs(env_u64("BASH_GIT_STATUS_IDLE_SECS", 600))
}

pub(crate) fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
