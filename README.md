bash-git-status
===============

A simple program to display Git status, useful for integration in Bash's PS1 prompt.

Status server
-------------

By default the status is served by a small per-user daemon (a unix socket in `$XDG_RUNTIME_DIR`,
`/tmp` when it isn't set). It starts on demand - the first `bash-git-status` call spawns it and
waits for it to bind - and every shell asks the same one, so a repository another shell already
looked at is answered from its cache. The daemon caches one result per repository, shared by all of
its directories, and reuses it until the repository changes: the index (`git add`, `git commit`,
`git reset`), `HEAD` (checkouts, commits, in-progress operations), tracked files that were modified,
added, removed or made executable, and untracked files that appeared or vanished. A directory inside
a huge repository therefore answers in a few milliseconds instead of scanning the worktree again.

Detecting a change this way means no directory walk, no ignore matching and no tree traversal: only
the mtime and inode of every directory that held a tracked or untracked file, and the stat
information the index recorded for every tracked file, are checked again. A file counts as unchanged
when its size, timestamps and inode are still the ones the index wrote down for it, compared down to
nanoseconds the way `git status` compares them, so a file written in the same second as the index
doesn't have to be read to be trusted; whatever that comparison can't decide is left to the full
index-to-worktree comparison of gitoxide.

An entry is still only served for `BASH_GIT_STATUS_TRUST_SECS` (default 60) before the status is
computed from scratch again, which bounds the effect of filesystems that don't update directory
mtimes. Once that window has passed, the prompt asking for the status waits for that recomputation,
so a repository is scanned again at most once every 60 seconds of use; raise the setting if the
filesystems holding the worktree and `.git` report directory mtimes reliably, or lower it if they
don't. Repositories that can't be watched this way (a sparse index, a reference backend without
reference files, or more directories than the daemon is willing to watch) and directories outside
any repository are kept for `BASH_GIT_STATUS_TTL_MS` (default 500).

- The daemon starts on demand and exits after `BASH_GIT_STATUS_IDLE_SECS` (default 600) of
  inactivity; kill it early with `pkill -x bash-git-status`.
- A lock file next to the socket keeps concurrent clients from spawning duplicates, and a stale
  socket left by an unclean exit is replaced. Starting a daemon always starts from a fresh state,
  but a daemon of an older build answers with its old behaviour until it exits.
- When no daemon can be reached, `bash-git-status` computes the status in-process, which is the
  historical behaviour and the fallback at every step.
- `BASH_GIT_STATUS_NO_SERVER=1` disables the daemon entirely.
- `BASH_GIT_STATUS_TRUST_SECS` bounds how long a status may be served before the status is computed
  again.
- `BASH_GIT_STATUS_TTL_MS` is the freshness window for repositories and directories that can't be
  watched for changes.
- `BASH_GIT_STATUS_SERVER_LOG=<file>` appends the daemon's log output to a file, which with
  `RUST_LOG=debug` shows its startup and the failures it doesn't report to the prompt.
