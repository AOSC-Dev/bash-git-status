bash-git-status
===============

A simple program to display Git status, useful for integration in Bash's PS1 prompt.

Status server
-------------

By default the status is served by a small per-user daemon (unix socket in `$XDG_RUNTIME_DIR`). It caches one result per repository, shared by all of its directories, and reuses it until the repository changes: the index (`git add`, `git commit`, `git reset`), `HEAD` (checkouts, commits, in-progress operations), tracked files that were modified, added, removed or made executable, and untracked files that appeared or vanished. A directory inside a huge repository therefore answers in a few milliseconds instead of scanning the worktree again.

Detecting a change this way means no directory walk, no ignore matching and no tree traversal: only the mtime of every directory that held a tracked or untracked file, and the index entries themselves, are checked again. An entry is still only trusted for `BASH_GIT_STATUS_TRUST_SECS` (default 60) before it is recomputed regardless, which bounds the effect of filesystems that don't update directory mtimes. Repositories that can't be watched this way (a sparse index, a reference backend without reference files, or more directories than the daemon is willing to watch) and directories outside any repository fall back to a plain cache kept for `BASH_GIT_STATUS_TTL_MS` (default 500).

- The daemon starts on demand and exits after `BASH_GIT_STATUS_IDLE_SECS` (default 600) of inactivity; kill it early with `pkill -x bash-git-status`.
- Starting a daemon always starts from a fresh state, but a daemon of an older build answers with its old behaviour until it exits.
- When no daemon can be reached, the client falls back to computing in-process.
- `BASH_GIT_STATUS_NO_SERVER=1` disables the daemon entirely.
- `BASH_GIT_STATUS_TRUST_SECS` bounds how long a status may be reused without recomputing it.
- `BASH_GIT_STATUS_TTL_MS` is the freshness window for repositories and directories that can't be watched for changes.
- `BASH_GIT_STATUS_SERVER_LOG=<file>` appends the daemon's log output to a file for debugging.
