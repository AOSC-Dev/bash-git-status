//! A bash prompt helper printing the current branch (or in-progress operation)
//! and exiting with a code describing the worktree state.
//!
//! By default the status comes from a small per-user daemon over a unix
//! socket (see `src/server.rs`): entries of a repository are answered
//! instantly as long as it didn't change (see `src/cache.rs`), and are
//! otherwise recomputed before the reply. The daemon starts on demand and
//! exits after `BASH_GIT_STATUS_IDLE_SECS` (default 600) of inactivity.
//! `BASH_GIT_STATUS_NO_SERVER=1` always computes in-process instead.

mod cache;
mod server;
mod status;

use clap::Parser;
use std::env;
use std::path::PathBuf;
use std::process::exit;

/// Print the git branch or in-progress operation for a bash prompt.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Run the status-caching daemon; the client spawns it on demand.
    #[arg(long, hide = true)]
    server: bool,
}

fn main() {
    env_logger::init();

    if Cli::parse().server {
        server::run();
    }

    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // No file tracking means nothing to cache, and `..._NO_SERVER` asks for
    // the direct path explicitly.
    let (code, text) = if env::var_os("BASH_DISABLE_GIT_FILE_TRACKING").is_some()
        || env::var_os("BASH_GIT_STATUS_NO_SERVER").is_some()
    {
        status::compute(&cwd)
    } else {
        server::query_or_compute(&cwd)
    };

    if !text.is_empty() {
        println!("{text}");
    }

    exit(code);
}
