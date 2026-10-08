//! A small per-user daemon that caches repository status.
//!
//! Clients ask it over a unix socket for the prompt text and exit code of
//! their current directory. Every directory of a repository shares one entry,
//! and the entry is answered from only while its guard proves that the
//! repository is still the one the status was computed for: staged changes,
//! the branch and a modified, added or removed file all invalidate it (see
//! `crate::cache`). An entry that can't be proven - a repository that can't be
//! watched, a directory outside any repository, or one older than
//! `BASH_GIT_STATUS_TRUST_SECS` - is computed again before the reply, so a
//! status that has passed is never served while a new one is pending.
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
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Protocol marker, so a client can't be fooled by a reply from an outdated daemon after the
/// binary was rebuilt, and so that a request can't be taken for a reply.
const PREFIX: &[u8] = b"BGS4 ";

/// The longest directory a request may ask about; a path that doesn't exist is longer than it can
/// be, and the length is what a client states rather than what it sent.
const MAX_PATH: usize = 8 * 1024;

/// The environment overrides that decide which repository a directory belongs to and what its
/// status is: `git` and the library honour them, and this program's own switches change the text it
/// prints, so a daemon that was started by another shell - with another idea of them - can't answer
/// for a shell that has one of them set.
const ENVIRONMENT_OVERRIDES: [&str; 19] = [
    "BASH_DISABLE_GIT_FILE_TRACKING",
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

/// The status of a whole repository, shared by every directory inside it.
///
/// Nothing else is kept: an entry is only answered from while its guard proves that the repository
/// is still the one the status was computed for, and a status that can't be guarded - one of a
/// repository that can't be watched, or of a directory that isn't in a repository at all - would be
/// answered from without anything having checked it.
struct Entry {
    /// The exit code of the status the guard was captured for.
    code: i32,

    /// Proves that the repository is unchanged, and says what its status is when it did change.
    guard: Arc<Guard>,

    /// When the entry was answered from last, for eviction.
    last_used: Instant,
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

    let identity = config_identity();
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
                    if let Err(e) = handle(stream, &cache, identity) {
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

/// A fingerprint of the environment that decides which configuration files are read.
///
/// The daemon keeps the environment of the shell that started it, so a client whose own differs in
/// a way that changes the status can't take its answer: both sides hash what they have and only
/// agree if it is the same. Hashed, because all the client needs to know is whether the answers
/// would be made with the same configuration.
///
/// `HOME` and `XDG_CONFIG_HOME` decide where the user's configuration is read from, and the `git`
/// of `PATH` is the one whose installation configuration is read along with it - and the one that
/// serves a repository with a sparse index.
fn config_identity() -> u64 {
    let home = std::env::var_os("HOME");
    let config_home = std::env::var_os("XDG_CONFIG_HOME");
    let git = git_executable();

    config_identity_of(home.as_deref(), config_home.as_deref(), git.as_deref())
}

/// [`config_identity()`] of the values it is made of.
fn config_identity_of(
    home: Option<&OsStr>,
    config_home: Option<&OsStr>,
    git: Option<&Path>,
) -> u64 {
    /// FNV-1a, which only has to tell environments apart, not resist an attack.
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let values = [home, config_home, git.map(Path::as_os_str)];

    let mut hash = OFFSET;
    for value in values {
        if let Some(value) = value {
            for byte in value.as_encoded_bytes() {
                hash = (hash ^ u64::from(*byte)).wrapping_mul(PRIME);
            }
        }

        // A separator, so that two values can't be mistaken for one.
        hash = hash.wrapping_mul(PRIME) ^ u64::from(u8::MAX);
    }

    hash
}

/// The `git` a shell with this `PATH` would run.
fn git_executable() -> Option<PathBuf> {
    executable_in_path(&std::env::var_os("PATH")?, "git")
}

/// The first `name` of `path` that can be run, as the file it is.
///
/// A link is resolved to the file it points at, so that two spellings of one program are told apart
/// from two programs. An entry that isn't absolute is resolved against the working directory, which
/// a daemon has another one of than a client, so rather than let two of them agree on a name that
/// means different programs to each, they disagree.
fn executable_in_path(path: &OsStr, name: &str) -> Option<PathBuf> {
    std::env::split_paths(path).find_map(|dir| {
        let candidate = dir.join(name);
        let metadata = std::fs::metadata(&candidate).ok()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return None;
        }

        Some(std::fs::canonicalize(&candidate).unwrap_or(candidate))
    })
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

/// Read a request, which is `BGS4 <identity> <len>` followed by that many bytes of a directory.
///
/// The path is sent as its length instead of being terminated: a directory whose name contains a
/// newline is then still the directory that was asked about, and not a prefix of it that happens to
/// be another repository.
fn read_request(reader: &mut impl BufRead) -> Result<Option<(u64, PathBuf)>> {
    let mut header = Vec::new();
    if reader.read_until(b'\n', &mut header)? == 0 {
        return Ok(None);
    }

    let Some(rest) = header.strip_prefix(PREFIX) else {
        return Ok(None);
    };
    let rest = rest.strip_suffix(b"\n").unwrap_or(rest);
    let mut fields = rest.split(|b| *b == b' ');
    let number = |field: Option<&[u8]>, radix: u32| {
        std::str::from_utf8(field?)
            .ok()
            .and_then(|field| u64::from_str_radix(field, radix).ok())
    };

    let (Some(identity), Some(len)) = (number(fields.next(), 16), number(fields.next(), 10)) else {
        return Ok(None);
    };
    let Ok(len) = usize::try_from(len) else {
        return Ok(None);
    };
    if len == 0 || len > MAX_PATH || fields.next().is_some() {
        return Ok(None);
    }

    let mut path = vec![0u8; len];
    reader.read_exact(&mut path)?;

    Ok(Some((identity, PathBuf::from(OsStr::from_bytes(&path)))))
}

fn handle(mut stream: Stream, cache: &Cache, identity: u64) -> Result<()> {
    let mut reader = BufReader::new(&stream);
    let Some((client, cwd)) = read_request(&mut reader)? else {
        return Ok(());
    };

    // The daemon reads the configuration of the shell that started it. A client whose own is
    // somewhere else gets no answer at all, so that it computes the status itself instead of taking
    // one that was made without its configuration - a global `.gitconfig`, or a file it includes,
    // can change what the status is - and so that nothing is computed for an answer that would be
    // thrown away.
    if client != identity {
        debug!("a client with another configuration asked, not answering");
        return Ok(());
    }

    // Every directory of a repository shares one entry, keyed by its root. Whatever that entry
    // can't answer is computed now: the status of a repository the daemon can't watch, and of a
    // directory that isn't in one, is never taken from an earlier answer.
    let root = repo_root(&cwd);
    let answer = root.as_deref().and_then(|root| reuse_repo(root, cache));
    let (code, text) = match answer {
        Some(answer) => answer,
        None => {
            let (code, text, cached) = compute(&cwd, root.as_deref());
            if let Some((key, entry)) = cached {
                remember(cache, key, entry);
            }
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
        let entry = cache.get_mut(root)?;
        if !entry.guard.fresh() {
            return None;
        }
        entry.last_used = Instant::now();
        (entry.code, Arc::clone(&entry.guard))
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

/// Compute the answer for `cwd`, like [`status::compute()`], along with the entry that would let a
/// later request skip computing it.
///
/// The entry is missing when the status can't be watched: for a directory that isn't in a
/// repository, for one whose repository can't be opened, and for a repository whose changes nothing
/// would notice. Its answer is then computed for every request - an entry that nothing proves would
/// otherwise be served while it may already be wrong.
fn compute(cwd: &Path, root: Option<&Path>) -> (i32, String, Option<(PathBuf, Entry)>) {
    let Ok(repo) = status::get_repo(cwd) else {
        return without_repo();
    };
    let Ok(text) = status::repo_progress(&repo) else {
        return without_repo();
    };

    // The worktree walk the guard needs runs while the status is computed, so that a repository
    // that has to be scanned anyway doesn't wait for it afterwards.
    let watch = cache::Watch::start(&repo.repo);
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
            cache::Guard::capture(&repo, &report, watch).map(|guard| (root.to_path_buf(), guard))
        }
        _ => None,
    };

    let cached = guard.map(|(key, guard)| {
        (
            key,
            Entry {
                code,
                guard: Arc::new(guard),
                last_used: Instant::now(),
            },
        )
    });

    (code, text, cached)
}

/// The historical answer for a directory that isn't a repository, or can't be inspected.
fn without_repo() -> (i32, String, Option<(PathBuf, Entry)>) {
    (1, String::new(), None)
}

/// Keep an entry in the cache, evicting the least recently used ones beyond [`MAX_ENTRIES`].
fn remember(cache: &Cache, key: PathBuf, entry: Entry) {
    let mut cache = cache.lock().unwrap();
    cache.insert(key, entry);

    while cache.len() > MAX_ENTRIES {
        let oldest = cache
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
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
    match try_query(&socket, cwd) {
        Answer::Status(code, text) => return Some((code, text)),
        // A daemon that didn't answer this client won't answer it either when it is asked again,
        // and it holds the lock that keeps another one from starting: computing here is the only
        // answer left, and waiting for that lock to be released would only delay it.
        Answer::Stranger => return None,
        Answer::NoDaemon => {}
    }

    // No daemon (or it is still starting): spawn one and give it a moment.
    spawn_server();
    let deadline = Instant::now() + SPAWN_TIMEOUT;
    loop {
        match try_query(&socket, cwd) {
            Answer::Status(code, text) => return Some((code, text)),
            Answer::Stranger => return None,
            Answer::NoDaemon => {}
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// How asking the daemon went.
enum Answer {
    /// The daemon answered with a status.
    Status(i32, String),

    /// Nothing answered: either nothing is listening, or the daemon that is still starting hasn't
    /// begun to. Waiting for one is worthwhile, as it may answer after it bound its socket.
    NoDaemon,

    /// Something is listening but didn't answer with a status of this protocol: a daemon of another
    /// build, or one whose configuration isn't the one this client would be answered with. Neither
    /// will ever answer this client, so waiting for a daemon that can't start while they live would
    /// only delay the computation.
    Stranger,
}

fn try_query(socket: &Path, cwd: &Path) -> Answer {
    let Some(name) = socket.to_fs_name::<GenericFilePath>().ok() else {
        return Answer::NoDaemon;
    };
    let Ok(mut stream) = Stream::connect(name) else {
        return Answer::NoDaemon;
    };
    let _ = stream.set_recv_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_send_timeout(Some(Duration::from_secs(5)));

    let path = cwd.as_os_str().as_bytes();
    let mut request = Vec::with_capacity(PREFIX.len() + 48 + path.len());
    request.extend_from_slice(PREFIX);
    request.extend_from_slice(format!("{:016x}", config_identity()).as_bytes());
    request.push(b' ');
    request.extend_from_slice(path.len().to_string().as_bytes());
    request.push(b'\n');
    request.extend_from_slice(path);
    if stream.write_all(&request).is_err() {
        return Answer::Stranger;
    }

    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() {
        return Answer::Stranger;
    }

    match read_reply(&response) {
        Some((code, text)) => Answer::Status(code, text),
        None => Answer::Stranger,
    }
}

/// The status in a reply, if it is a reply of this protocol.
///
/// A daemon of another build answers in its own protocol, which is why a reply that doesn't read as
/// one of this one is not an answer at all.
fn read_reply(response: &[u8]) -> Option<(i32, String)> {
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

fn idle_timeout() -> Duration {
    Duration::from_secs(env_u64("BASH_GIT_STATUS_IDLE_SECS", 600))
}

pub(crate) fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::tests::TempRepo;
    use std::fs::Permissions;

    /// A request as a client sends it, for `path`.
    fn request(path: &[u8]) -> Vec<u8> {
        let mut request = Vec::new();
        request.extend_from_slice(PREFIX);
        request.extend_from_slice(b"0011223344556677 ");
        request.extend_from_slice(path.len().to_string().as_bytes());
        request.push(b'\n');
        request.extend_from_slice(path);

        request
    }

    #[test]
    fn a_request_carries_the_path_verbatim() {
        let path = "/tmp/a\nnew";
        let request = request(path.as_bytes());
        let mut reader = BufReader::new(&request[..]);

        let (identity, read) = read_request(&mut reader)
            .expect("a request can be read")
            .expect("the request is well formed");

        assert_eq!(identity, 0x0011_2233_4455_6677);
        assert_eq!(read, PathBuf::from(path));
    }

    #[test]
    fn a_repository_that_can_be_watched_is_remembered() {
        let repo = TempRepo::new("remembered");

        let (code, _, cached) = compute(&repo.path, Some(&repo.path));

        assert_eq!(code, 5);
        assert!(cached.is_some(), "a watchable repository is remembered");
    }

    #[test]
    fn a_repository_that_can_not_be_watched_is_not_remembered() {
        let repo = TempRepo::new("unwatched");
        let config = repo.path.join(".git/config");
        let mut content = std::fs::read_to_string(&config).expect("the configuration can be read");
        content.push_str("[include]\n\tpath = ~no-such-user-bash-git-status/x.cfg\n");
        std::fs::write(&config, content).expect("the configuration can be written");

        let (code, _, cached) = compute(&repo.path, Some(&repo.path));

        assert_eq!(code, 5);
        assert!(
            cached.is_none(),
            "a repository whose changes nothing would notice must not be remembered"
        );
    }

    #[test]
    fn a_directory_outside_a_repository_is_not_remembered() {
        let dir =
            std::env::temp_dir().join(format!("bash-git-status-plain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the directory can be created");

        let (code, text, cached) = compute(&dir, None);

        assert_eq!((code, text.as_str()), (1, ""));
        assert!(
            cached.is_none(),
            "a directory that may become a repository must not be remembered"
        );
        std::fs::remove_dir_all(&dir).expect("the directory can be removed");
    }

    #[test]
    fn a_reply_that_is_not_of_this_protocol_is_no_answer() {
        assert_eq!(read_reply(b"BGS4 5\nmain"), Some((5, "main".to_owned())));
        assert_eq!(read_reply(b"BGS4 1\n"), Some((1, String::new())));
        assert_eq!(
            read_reply(b"BGS4 7\nmain\nmore"),
            Some((7, "main\nmore".to_owned()))
        );

        // An older daemon, one of a client that isn't this one, a truncated reply, and a code that
        // isn't a number.
        assert_eq!(read_reply(b"BGS3 500 5\nmain"), None);
        assert_eq!(read_reply(b""), None);
        assert_eq!(read_reply(b"BGS4 5"), None);
        assert_eq!(read_reply(b"BGS4 x\nmain"), None);
    }

    #[test]
    fn a_shell_whose_git_is_another_one_is_answered_by_neither() {
        let identity = |home: Option<&OsStr>, git: Option<&OsStr>| {
            config_identity_of(home, None, git.map(Path::new))
        };
        let (here, elsewhere) = (OsStr::new("/usr/bin/git"), OsStr::new("/opt/git/bin/git"));

        assert_eq!(identity(None, Some(here)), identity(None, Some(here)));
        assert_ne!(identity(None, Some(here)), identity(None, Some(elsewhere)));
        assert_ne!(identity(None, Some(here)), identity(None, None));
        assert_ne!(
            identity(Some(OsStr::new("/home/a")), None),
            identity(None, None)
        );
    }

    #[test]
    fn the_git_of_a_path_is_the_first_one_that_can_be_run() {
        let dir = std::env::temp_dir().join(format!("bash-git-status-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (runnable, not_runnable) = (dir.join("first"), dir.join("second"));
        for directory in [&runnable, &not_runnable] {
            std::fs::create_dir_all(directory).expect("the test directory can be created");
            std::fs::write(directory.join("git"), "").expect("the file can be written");
        }
        std::fs::set_permissions(runnable.join("git"), Permissions::from_mode(0o755))
            .expect("the file can be made runnable");
        std::fs::set_permissions(not_runnable.join("git"), Permissions::from_mode(0o644))
            .expect("the file can be left un-runnable");

        let path = std::env::join_paths([&runnable, &not_runnable]).expect("a path can be built");
        let found = executable_in_path(&path, "git");
        assert_eq!(
            found,
            Some(std::fs::canonicalize(runnable.join("git")).expect("the file resolves"))
        );

        // A name that no entry holds is nothing, and neither is a path of nothing but a name that
        // can't be run.
        assert_eq!(executable_in_path(&path, "hg"), None);
        assert_eq!(executable_in_path(not_runnable.as_os_str(), "git"), None);
        std::fs::remove_dir_all(&dir).expect("the directory can be removed");
    }

    #[test]
    fn a_malformed_request_is_ignored() {
        for request in [
            // Too few fields, an old protocol, a path that is too long or too short, an empty path,
            // and a field that doesn't belong.
            &b"BGS4 0011223344556677\n"[..],
            &b"BGS3 500 0011223344556677 3\nabc"[..],
            &b"BGS4 0011223344556677 99999\nabc"[..],
            &b"BGS4 0011223344556677 3\nab"[..],
            &b"BGS4 0011223344556677 0\n"[..],
            &b"BGS4 0011223344556677 3 x\nabc"[..],
            &b"BGS4 x 3\nabc"[..],
        ] {
            let mut reader = BufReader::new(request);

            assert!(
                !matches!(read_request(&mut reader), Ok(Some(_))),
                "read the request {:?}",
                String::from_utf8_lossy(request)
            );
        }
    }
}
