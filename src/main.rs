use anyhow::{Context, Result, anyhow};
use gix::commit::describe::SelectRef::{self};
use gix::progress;
use gix::state::InProgress;
use gix::status::Submodule;
use gix::{
    Repository, ThreadSafeRepository,
    sec::{self, trust::DefaultForLevel},
};
use log::debug;
use std::borrow::Cow;
use std::env;
use std::path::Path;
use std::process::Command;
use std::{path::PathBuf, process::exit};

pub struct Repo {
    pub repo: ThreadSafeRepository,

    /// If `current_dir` is a git repository or is contained within one,
    /// this is the current branch name of that repo.
    pub branch: Option<String>,

    /// If `current_dir` is a git repository or is contained within one,
    /// this is the path to the root of that repo.
    pub workdir: Option<PathBuf>,

    /// The path of the repository's `.git` directory.
    pub path: PathBuf,

    /// State
    pub state: Option<InProgress>,
    // /// Remote repository
    // pub remote: Option<Remote>,
}

const MODIFY_STATUS: &str = "MATDRCU";

fn main() {
    env_logger::init();

    let path = PathBuf::from(".");

    let Ok(repo) = get_repo(&path) else {
        exit(1);
    };

    let progress_status = match repo_progress(&repo) {
        Ok(output) => output,
        Err(e) => {
            debug!("{e}");
            exit(1);
        }
    };

    println!("{progress_status}");

    let status = get_status(&repo);

    exit(status)
}

fn get_status(repo: &Repo) -> i32 {
    if env::var("BASH_DISABLE_GIT_FILE_TRACKING").is_ok() {
        return 9;
    }

    let repo = repo.repo.to_thread_local();

    if repo.index_or_empty().is_ok_and(|repo| repo.is_sparse()) {
        return get_status_sparse();
    }

    let Ok(status) = repo
        .status(progress::Discard)
        .inspect_err(|e| debug!("{e}"))
    else {
        return 8;
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
        return 8;
    };

    for change in status.filter_map(Result::ok) {
        use gix::status;
        match &change {
            status::Item::TreeIndex(_) => {
                return 6;
            }
            status::Item::IndexWorktree(change) => {
                use gix::status::index_worktree::Item;
                use gix::status::plumbing::index_as_worktree::{Change, EntryStatus};
                match change {
                    Item::Modification {
                        status: EntryStatus::Conflict(_),
                        ..
                    } => {
                        return 6;
                    }
                    Item::Modification {
                        status: EntryStatus::Change(Change::Removed),
                        ..
                    } => {
                        return 6;
                    }
                    Item::Modification {
                        status:
                            EntryStatus::IntentToAdd
                            | EntryStatus::Change(
                                Change::Modification { .. } | Change::SubmoduleModification(_),
                            ),
                        ..
                    } => {
                        return 6;
                    }
                    Item::Modification {
                        status: EntryStatus::Change(Change::Type { .. }),
                        ..
                    } => {
                        return 6;
                    }
                    Item::DirectoryContents {
                        entry:
                            gix::dir::Entry {
                                status: gix::dir::entry::Status::Untracked,
                                ..
                            },
                        ..
                    } => {
                        return 7;
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

    5
}

fn get_status_sparse() -> i32 {
    let cmd = Command::new("git")
        .arg("status")
        .arg("--porcelain")
        .output();

    let mut status = 0;

    if let Ok(cmd) = cmd {
        if cmd.status.success() {
            let out = String::from_utf8_lossy(&cmd.stdout);
            let mut out_iter = out
                .trim()
                .split('\n')
                .filter_map(|x| x.rsplit_once(' '))
                .map(|x| x.0);

            match out_iter.next() {
                None => {
                    status = 5;
                }
                Some(x)
                    if MODIFY_STATUS.contains(x)
                        || MODIFY_STATUS.contains(&x[..1])
                        || MODIFY_STATUS.contains(&x[1..2]) =>
                {
                    status = 6;
                }
                Some("??") => {
                    status = 7;
                }
                _ => {}
            }

            debug!("git status --porcelain output: {out}");
        } else {
            status = 8;
        }
    }

    status
}

fn repo_progress(repo: &Repo) -> Result<String> {
    let git_repo = repo.repo.to_thread_local();

    let display_name = repo
        .branch
        .as_ref()
        .map(Cow::Borrowed)
        .or_else(|| get_tag(&git_repo).map(Cow::Owned))
        .or_else(|| {
            Some(Cow::Owned(format!(
                "(detached {})",
                git_repo.head_id().ok()?.shorten_or_id()
            )))
        });

    let display_name = display_name.ok_or_else(|| anyhow!("Failed to get branch/hash"))?;

    let s = if let Some(state) = &repo.state {
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

fn get_repo(path: &Path) -> Result<Repo> {
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

    let repository = shared_repo.to_thread_local();
    let branch = get_current_branch(&repository);
    let path = repository.path().to_path_buf();

    let repo = Repo {
        repo: shared_repo,
        branch,
        workdir: repository.workdir().map(PathBuf::from),
        path,
        state: repository.state(),
    };

    Ok(repo)
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
