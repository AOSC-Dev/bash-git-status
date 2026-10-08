//! A bash prompt helper printing the current branch (or in-progress operation)
//! and exiting with a code describing the worktree state.
//!
//! Statuses are served by a small daemon per shell, over pipes the shell keeps open (see
//! `src/server.rs` and `contrib/bash-git-status.bash`): entries of a repository are answered
//! instantly as long as it didn't change (see `src/cache.rs`). Without the shell integration, or
//! with `BASH_GIT_STATUS_NO_SERVER=1`, every call computes the status in-process.

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
    /// Run the status-caching daemon, which the shell starts and talks to over pipes.
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
