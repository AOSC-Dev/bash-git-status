//! A small per-user daemon that caches repository status.
//!
//! Clients ask it over a unix socket for the prompt text and exit code of
//! their current directory: entries younger than the client-provided TTL
//! (`BASH_GIT_STATUS_TTL_MS`, default 500ms) are answered from cache,
//! anything else is recomputed before the reply is sent.
//!
//! The daemon starts on demand, exits after `BASH_GIT_STATUS_IDLE_SECS`
//! (default 600) without requests, and a lock file next to the socket keeps
//! concurrent clients from spawning duplicates. `BASH_GIT_STATUS_SERVER_LOG`
//! redirects the daemon's stderr into a file for debugging.

use crate::status;
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

type Cache = Arc<Mutex<HashMap<PathBuf, Entry>>>;

struct Entry {
    code: i32,
    text: String,
    computed_at: Instant,
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

    let ttl = Duration::from_millis(ttl_ms);
    let cached = {
        let cache = cache.lock().unwrap();
        cache
            .get(&cwd)
            .filter(|entry| entry.computed_at.elapsed() < ttl)
            .map(|entry| (entry.code, entry.text.clone()))
    };

    let (code, text) = match cached {
        Some(hit) => hit,
        None => {
            let computed = status::compute(&cwd);
            cache.lock().unwrap().insert(
                cwd,
                Entry {
                    code: computed.0,
                    text: computed.1.clone(),
                    computed_at: Instant::now(),
                },
            );
            computed
        }
    };

    stream.write_all(format!("{code}\n{text}").as_bytes())?;
    Ok(())
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

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
