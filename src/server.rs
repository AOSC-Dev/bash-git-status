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

/// Protocol marker, so a client can't be fooled by a reply from an outdated
/// daemon after the binary was rebuilt.
const REQUEST_PREFIX: &[u8] = b"BGS1 ";

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
    let socket = socket_path();
    let lock_path = socket.with_extension("lock");
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
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

fn handle(mut stream: Stream, cache: &Cache) -> Result<()> {
    let mut request = Vec::new();
    {
        let mut reader = BufReader::new(&stream);
        reader.read_until(b'\n', &mut request)?;
    }

    // The request is `BGS1 <ttl-ms> <path>`; anything else is ignored.
    let Some(rest) = request.strip_prefix(REQUEST_PREFIX) else {
        return Ok(());
    };
    let rest = rest.strip_suffix(b"\n").unwrap_or(rest);
    let Some(space) = rest.iter().position(|b| *b == b' ') else {
        return Ok(());
    };
    let Some(ttl_ms) = std::str::from_utf8(&rest[..space])
        .ok()
        .and_then(|ttl| ttl.parse::<u64>().ok())
    else {
        return Ok(());
    };
    let path = &rest[space + 1..];
    if path.is_empty() {
        return Ok(());
    }
    let cwd = PathBuf::from(OsStr::from_bytes(path));

    // Every directory of a repository shares one entry, keyed by its root.
    let root = repo_root(&cwd);
    let answer = root
        .as_deref()
        .and_then(|root| reuse_repo(root, cache))
        .or_else(|| reuse_dir(&cwd, cache, Duration::from_millis(ttl_ms)));
    let (code, text) = match answer {
        Some(answer) => answer,
        None => {
            let (code, text, cached) = compute(&cwd, root.as_deref());
            remember(cache, cached.key, cached.entry);
            (code, text)
        }
    };

    stream.write_all(format!("{code}\n{text}").as_bytes())?;
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

    let mut request = Vec::with_capacity(REQUEST_PREFIX.len() + 24 + cwd.as_os_str().len());
    request.extend_from_slice(REQUEST_PREFIX);
    request.extend_from_slice(ttl().as_millis().to_string().as_bytes());
    request.push(b' ');
    request.extend_from_slice(cwd.as_os_str().as_bytes());
    request.push(b'\n');
    stream.write_all(&request).ok()?;

    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let (code, text) = response.split_once('\n')?;
    Some((code.parse().ok()?, text.to_string()))
}

fn spawn_server() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };

    let mut command = Command::new(exe);
    command
        .arg("--server")
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
