//! Status computation: the prompt text and the exit code.

use anyhow::{Context, Result, anyhow};
use gix::bstr::BString;
use gix::commit::describe::SelectRef::{self};
use gix::progress;
use gix::state::InProgress;
use gix::status::Submodule;
use gix::{
    Repository, ThreadSafeRepository,
    sec::{self, trust::DefaultForLevel},
};
use log::debug;
use num_enum::IntoPrimitive;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Repo {
    pub repo: ThreadSafeRepository,

    /// The directory the status was asked for. `git` is asked about it when the index is sparse,
    /// as `git status` only reports what is below the directory it runs in.
    pub cwd: PathBuf,
}

const MODIFY_STATUS: &str = "MATDRCU";

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive)]
#[repr(i32)]
pub enum Status {
    Unchange = 5,
    Change = 6,
    Untracked = 7,
    HasError = 8,
    Disable = 9,
}

/// The outcome of a status computation, along with what is needed to cache it.
pub struct Report {
    pub status: Status,

    /// Whether [`Status::Change`] is due to a difference between the tree `HEAD` points at and the
    /// index, as opposed to a difference between the index and the worktree.
    pub staged: bool,

    /// The repository-relative paths of the untracked entries the directory walk has seen.
    pub untracked: Vec<BString>,
}

/// Compute the prompt text and exit code for the repository containing `cwd`.
///
/// `text` is empty when no repository could be found; such failures keep the
/// historical exit code of 1.
pub fn compute(cwd: &Path) -> (i32, String) {
    let repo = match get_repo(cwd) {
        Ok(repo) => repo,
        Err(e) => {
            debug!("{e}");
            return (1, String::new());
        }
    };

    let text = match repo_progress(&repo) {
        Ok(text) => text,
        Err(e) => {
            debug!("{e}");
            return (1, String::new());
        }
    };

    let code: i32 = report(&repo).status.into();

    (code, text)
}

/// Compute the status of `repo`, collecting the information needed by a [`Guard`](crate::cache::Guard)
/// to detect later changes.
pub fn report(repo: &Repo) -> Report {
    let mut report = Report {
        status: Status::Unchange,
        staged: false,
        untracked: Vec::new(),
    };

    if env::var("BASH_DISABLE_GIT_FILE_TRACKING").is_ok() {
        report.status = Status::Disable;
        return report;
    }

    let cwd = &repo.cwd;
    let repo = repo.repo.to_thread_local();

    if repo.index_or_empty().is_ok_and(|index| index.is_sparse()) {
        report.status = get_status_sparse(cwd);
        return report;
    }

    let Ok(status) = repo
        .status(progress::Discard)
        .inspect_err(|e| debug!("{e}"))
    else {
        report.status = Status::HasError;
        return report;
    };

    let status = status.index_worktree_submodules(Submodule::AsConfigured { check_dirty: true });
    let status = status.index_worktree_options_mut(|opts| {
        // TODO: figure out good defaults for other platforms, maybe make it configurable.
        opts.thread_limit = None;

        if let Some(opts) = opts.dirwalk_options.as_mut() {
            opts.set_emit_untracked(gix::dir::walk::EmissionMode::Matching)
                .set_emit_ignored(None)
                .set_emit_pruned(false)
                .set_emit_empty_directories(false);
        }
    });

    let status = status.tree_index_track_renames(gix::status::tree_index::TrackRenames::Given({
        let mut config = gix::diff::new_rewrites(&repo.config_snapshot(), true)
            .unwrap_or_default()
            .0
            .unwrap_or_default();

        config.limit = 100;
        config
    }));

    // This will start the status machinery, collecting status items in the background.
    // Thus, we can do some work in this thread without blocking, before starting to count status items.
    let Ok(status) = status.into_iter(None).inspect_err(|e| debug!("{e}")) else {
        report.status = Status::HasError;
        return report;
    };

    for change in status.filter_map(Result::ok) {
        use gix::status;
        match &change {
            status::Item::TreeIndex(_) => {
                report.staged = true;
                report.status = Status::Change;
                return report;
            }
            status::Item::IndexWorktree(change) => {
                use gix::status::index_worktree::Item;
                match change {
                    modification @ Item::Modification { .. } if worktree_change(modification) => {
                        report.status = Status::Change;
                        return report;
                    }
                    Item::DirectoryContents { entry, .. }
                        if entry.status == gix::dir::entry::Status::Untracked =>
                    {
                        report.untracked.push(entry.rela_path.clone());
                    }
                    Item::Rewrite { .. } => {
                        unreachable!(
                            "this kind of rename tracking isn't enabled by default and specific to gitoxide"
                        )
                    }
                    _ => {}
                }
            }
        }
    }

    if !report.untracked.is_empty() {
        report.status = Status::Untracked;
    }

    report
}

/// Whether an index-to-worktree item means the worktree changed in a way `git status` reports.
///
/// Not every item is a change: [`EntryStatus::NeedsUpdate`](gix::status::plumbing::index_as_worktree::EntryStatus::NeedsUpdate)
/// exists to let callers refresh the index so a later status is cheaper.
pub fn worktree_change(item: &gix::status::index_worktree::Item) -> bool {
    use gix::status::index_worktree::Item;
    use gix::status::plumbing::index_as_worktree::{Change, EntryStatus};

    let Item::Modification { status, .. } = item else {
        return false;
    };

    matches!(
        status,
        EntryStatus::Conflict { .. }
            | EntryStatus::IntentToAdd
            | EntryStatus::Change(Change::Removed)
            | EntryStatus::Change(Change::Modification { .. } | Change::SubmoduleModification(_))
            | EntryStatus::Change(Change::Type { .. })
    )
}

/// Whether `repo` uses a sparse index, in which case its status is obtained from `git` and does not
/// only depend on the repository as a whole.
pub fn is_sparse(repo: &Repo) -> bool {
    repo.repo
        .to_thread_local()
        .index_or_empty()
        .is_ok_and(|index| index.is_sparse())
}

/// Ask `git` for the status of `cwd`, used for repositories whose index is sparse.
///
/// The directory matters: `git status` only reports what is below it, so the daemon has to ask for
/// the directory the client is in rather than its own.
fn get_status_sparse(cwd: &Path) -> Status {
    let cmd = Command::new("git")
        .arg("status")
        .arg("--porcelain")
        .current_dir(cwd)
        .output();

    let mut status = Status::Unchange;

    if let Ok(cmd) = cmd {
        if cmd.status.success() {
            let out = String::from_utf8_lossy(&cmd.stdout);
            let mut out_iter = out
                .trim()
                .split('\n')
                .filter_map(|x| x.rsplit_once(' '))
                .map(|x| x.0);

            match out_iter.next() {
                None => {}
                Some(x)
                    if MODIFY_STATUS.contains(x)
                        || MODIFY_STATUS.contains(&x[..1])
                        || MODIFY_STATUS.contains(&x[1..2]) =>
                {
                    status = Status::Change;
                }
                Some("??") => {
                    status = Status::Untracked;
                }
                _ => {}
            }

            debug!("git status --porcelain output: {out}");
        } else {
            status = Status::HasError;
        }
    }

    status
}

pub fn repo_progress(repo: &Repo) -> Result<String> {
    progress_of(&repo.repo)
}

/// Like [`repo_progress()`], but for an already-opened repository.
pub fn progress_of(shared: &ThreadSafeRepository) -> Result<String> {
    let git_repo = shared.to_thread_local();

    let display_name = get_current_branch(&git_repo)
        .or_else(|| get_tag(&git_repo))
        .or_else(|| {
            Some(format!(
                "(detached {})",
                git_repo.head_id().ok()?.shorten_or_id()
            ))
        });

    let display_name = display_name.ok_or_else(|| anyhow!("Failed to get branch/hash"))?;

    let s = if let Some(state) = &git_repo.state() {
        match state {
            InProgress::ApplyMailbox => format!("Mailbox progress {display_name}"),
            InProgress::ApplyMailboxRebase => {
                format!("Mailbox rebase progress {display_name}")
            }
            InProgress::Bisect => format!("Bisect progress {display_name}"),
            InProgress::CherryPick => format!("Cherry pick progress {display_name}"),
            InProgress::CherryPickSequence => {
                format!("Cherry pick sequence progress {display_name}")
            }
            InProgress::Merge => format!("Merge progress {display_name}"),
            InProgress::Rebase => format!("Rebase progress {display_name}"),
            InProgress::RebaseInteractive => {
                format!("Rebasing {display_name}")
            }
            InProgress::Revert => format!("Revert progress {display_name}"),
            InProgress::RevertSequence => format!("Revert Sequence progress {display_name}"),
        }
    } else {
        display_name.to_string()
    };

    Ok(s)
}

pub fn get_repo(path: &Path) -> Result<Repo> {
    let mut git_open_opts_map = sec::trust::Mapping::<gix::open::Options>::default();

    let config = gix::open::permissions::Config {
        git_binary: true,
        system: true,
        git: true,
        user: true,
        env: true,
        includes: true,
    };

    git_open_opts_map.reduced = git_open_opts_map
        .reduced
        .permissions(gix::open::Permissions {
            config,
            ..gix::open::Permissions::default_for_level(sec::Trust::Reduced)
        });

    git_open_opts_map.full = git_open_opts_map.full.permissions(gix::open::Permissions {
        config,
        ..gix::open::Permissions::default_for_level(sec::Trust::Full)
    });

    let shared_repo = ThreadSafeRepository::discover_with_environment_overrides_opts(
        path,
        Default::default(),
        git_open_opts_map,
    )
    .context("Failed to find git repo")?;

    Ok(Repo {
        repo: shared_repo,
        cwd: path.to_path_buf(),
    })
}

fn get_current_branch(repository: &Repository) -> Option<String> {
    let name = repository.head_name().ok()??;
    let shorthand = name.shorten();

    Some(shorthand.to_string())
}

fn get_tag(repository: &Repository) -> Option<String> {
    let head_commit = repository.head_commit().ok()?;
    let describe_platform = head_commit
        .describe()
        .names(SelectRef::AllTags)
        .id_as_fallback(false);

    let formatter = describe_platform.try_format().ok()??;

    debug!("Describe: {:?}", formatter);

    if formatter.depth > 0 {
        None
    } else {
        Some(formatter.name?.to_string())
    }
}
