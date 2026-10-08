# Bash integration for bash-git-status.
#
# Source this file from your bashrc (on AOSC OS, drop it into /etc/bashrc.d/) to give every shell
# its own status daemon. The prompts of that shell are then answered over two pipes it keeps open,
# so a status that was computed once is reused until the repository changes. Without it, every
# `bash-git-status` call computes the status on its own.

# Start a daemon for this shell, replacing one that is already there.
_bgs_start() {
    _bgs_stop

    # Job control would otherwise announce the daemon, and its replacement, above the prompt.
    { coproc BGS { exec bash-git-status --server 2>/dev/null; }; } 2>/dev/null
    disown "$BGS_PID" 2>/dev/null

    # `coproc` marks its own pipes close-on-exec, so they would be closed just before the prompt's
    # subshell runs `bash-git-status`; these copies of them are inherited instead.
    if [[ -z $BGS_PID ]] || ! exec 3>/dev/fd/"${BGS[1]}" 4</dev/fd/"${BGS[0]}"; then
        _bgs_stop
        return 1
    fi

    export BASH_GIT_STATUS_FD_IN=3 BASH_GIT_STATUS_FD_OUT=4
}

_bgs_stop() {
    if [[ -n $BGS_PID ]] && kill -0 "$BGS_PID" 2>/dev/null; then
        kill "$BGS_PID" 2>/dev/null
    fi

    unset BGS_PID BASH_GIT_STATUS_FD_IN BASH_GIT_STATUS_FD_OUT
}

# A daemon that died would leave this shell without one, so it is started again before the prompt
# gets a chance to ask it anything; the check costs one `kill -0` per prompt.
_bgs_alive() { [[ -n $BGS_PID ]] && kill -0 "$BGS_PID" 2>/dev/null; }

if [[ $- == *i* && ${BASH_VERSINFO[0]} -ge 4 ]] && command -v bash-git-status >/dev/null 2>&1; then
    _bgs_start
    if [[ ${PROMPT_COMMAND@a} == *a* ]]; then
        PROMPT_COMMAND=('_bgs_alive || _bgs_start' "${PROMPT_COMMAND[@]}")
    else
        PROMPT_COMMAND="_bgs_alive || _bgs_start${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
    fi
fi
