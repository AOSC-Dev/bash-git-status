use anyhow::{Context, Result, anyhow};
use gix::commit::describe::SelectRef::{self};
use gix::state::InProgress;
use gix::{
    Repository, ThreadSafeRepository,
    sec::{self, trust::DefaultForLevel},
};
use log::debug;
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

    let progress_status = match repo_progress(path) {
        Ok(output) => output,
        Err(e) => {
            debug!("{e}");
            exit(1);
        }
    };

    let status = print_and_get_status(&progress_status);

    exit(status)
}

fn print_and_get_status(progress_status: &str) -> i32 {
    println!("{progress_status}");

    if env::var("BASH_DISABLE_GIT_FILE_TRACKING").is_ok() {
        return 9;
    }

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
                .filter_map(|x| x.split_once(' '))
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

fn repo_progress(path: PathBuf) -> Result<String> {
    // custom open options
    let repo = get_repo(&path)?;

    let git_repo = repo.repo.to_thread_local();

    let display_name = repo.branch.or_else(|| get_tag(&git_repo)).or_else(|| {
        Some(format!(
            "(detached {})",
            git_repo.head_id().ok()?.shorten_or_id()
        ))
    });

    let display_name = display_name.ok_or_else(|| anyhow!("Failed to get branch/hash"))?;

    let s = if let Some(state) = repo.state {
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
        display_name
    };

    Ok(s)
}

fn get_repo(path: &Path) -> Result<Repo> {
    let mut git_open_opts_map = sec::trust::Mapping::<gix::open::Options>::default();

    let config = gix::open::permissions::Config {
        git_binary: false,
        system: false,
        git: false,
        user: false,
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
