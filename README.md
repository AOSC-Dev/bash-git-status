bash-git-status
===============

A simple program to display Git status, useful for integration in Bash's PS1 prompt.

Status server
-------------

By default the status is served by a small per-user daemon (unix socket in `$XDG_RUNTIME_DIR`) that caches the result per directory: a cached entry younger than `BASH_GIT_STATUS_TTL_MS` (default 500) is answered immediately, older entries are recomputed before the reply. A cache hit costs about 2ms, so even huge repositories respond instantly unless an entry expired.

- The daemon starts on demand and exits after `BASH_GIT_STATUS_IDLE_SECS` (default 600) of inactivity; kill it early with `pkill -x bash-git-status`.
- When no daemon can be reached, the client falls back to computing in-process.
- `BASH_GIT_STATUS_NO_SERVER=1` disables the daemon entirely.
- `BASH_GIT_STATUS_SERVER_LOG=<file>` appends the daemon's log output to a file for debugging.
