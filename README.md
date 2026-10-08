bash-git-status
===============

A simple program to display Git status, useful for integration in Bash's PS1 prompt.

Status server
-------------

By default the status is served by a small per-user daemon (a unix socket in `$XDG_RUNTIME_DIR`,
`/tmp` when it isn't set). It starts on demand - the first `bash-git-status` call spawns it and
waits for it to bind - and every shell asks the same one, so a repository another shell already
looked at is answered from its cache. The daemon caches one result per repository, shared by all of
its directories, and answers from it only while it can tell that the repository is still the one the
result was computed for: the index (`git add`, `git commit`, `git reset`), `HEAD` (checkouts,
commits, in-progress operations), tracked files that were modified, added, removed or made
executable, and untracked files that appeared or vanished. A directory inside
a huge repository therefore answers in a few milliseconds instead of scanning the worktree again.

Detecting a change this way means no scan when nothing changed: the mtime and inode of every
directory a scan would descend into are checked again, and so are the stat information the index
recorded for every tracked file. A file counts as unchanged when its size, timestamps and inode are
still the ones the index wrote down for it, compared down to nanoseconds the way `git status`
compares them, so a file written in the same second as the index doesn't have to be read to be
trusted; whatever that comparison can't decide is left to the full index-to-worktree comparison of
gitoxide.

The watched directories are the ones the scan enters, which - next to the directories that hold a
file - includes those that hold none: a file created in an empty directory, or in one whose contents
are all ignored, changes the mtime of a directory that is watched. Directories that are ignored
themselves are left out, as anything that can be created in them is ignored as well. Editing an
ignore or attributes rule doesn't change any directory, so the files that decide what a scan reports
are watched too: the `.gitignore` and `.gitattributes` that exist next to every watched directory,
`info/exclude` and `info/attributes` of the repository, the rule files `core.excludesFile` and
`core.attributesFile` point at together with the user's and the system's defaults, and the
configuration itself - the repository's, the user's and the system's, with the files their
`include.path` says to read, since what those contain is read as if it were written in the file that
includes them, and each of them with what a symbolic link of it points at. Watching a rule file or a
configuration file that doesn't exist isn't needed, because creating one changes the mtime of the
directory that holds it; a file that an `include.path` points at is watched whether or not it is
conditional or there. An `include.path` is resolved the way the configuration resolves it, `~user/`
being that user's home directory and `%(prefix)/` the directory of the running binary; a path that
can't be resolved that way leaves the repository unwatched, since what the include would read isn't
known.

An entry is still only served for `BASH_GIT_STATUS_TRUST_SECS` (default 60) before the status is
computed from scratch again, which bounds the effect of filesystems that don't update directory
mtimes. A recomputation that finds the directories recorded by the entry it replaces still in place
takes them over instead of walking the worktree again, so the periodic rescan doesn't repeat that
walk. Once that window has passed, the prompt asking for the status waits for that recomputation,
so a repository is scanned again at most once every 60 seconds of use; raise the setting if the
filesystems holding the worktree and `.git` report directory mtimes reliably, or lower it if they
don't. Nothing else is reused: a repository that can't be watched this way (a sparse index, a
reference backend without reference files, a configuration path that can't be resolved, or more
directories than the daemon is willing to watch) and a directory that isn't inside a repository are
computed again for every request, so a prompt never shows a status that has passed - a directory
that has just become a repository is answered as one.

- The daemon starts on demand and exits after `BASH_GIT_STATUS_IDLE_SECS` (default 600) of
  inactivity; kill it early with `pkill -x bash-git-status`.
- A lock file next to the socket keeps concurrent clients from spawning duplicates, and a stale
  socket left by an unclean exit is replaced. Starting a daemon always starts from a fresh state,
  and both directions of the protocol carry its version, so a client that finds a daemon of an older
  build computes the status itself instead of reading its older answer.
- A shell that sets an environment override which changes what a status means - `GIT_DIR`,
  `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_CONFIG_*`, `GIT_NAMESPACE` and the rest - computes the
  status in-process, because the daemon was started by another shell and has another environment.
  The daemon drops those overrides when it starts, so it never answers another shell's repository.
- The same goes for a shell whose configuration would be read from somewhere else: the daemon reads
  the `HOME` and `XDG_CONFIG_HOME` of the shell that started it, so its answer carries a fingerprint
  of them and a client that has another pair computes the status itself.
- When no daemon can be reached, `bash-git-status` computes the status in-process, which is the
  historical behaviour and the fallback at every step.
- `BASH_GIT_STATUS_NO_SERVER=1` disables the daemon entirely.
- `BASH_GIT_STATUS_TRUST_SECS` bounds how long a status may be served before the status is computed
  again.
- `BASH_GIT_STATUS_SERVER_LOG=<file>` appends the daemon's log output to a file, which with
  `RUST_LOG=debug` shows its startup and the failures it doesn't report to the prompt.
