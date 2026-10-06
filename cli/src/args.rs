use super::*;
use clap::Args;

#[derive(Parser)]
#[command(
    name = "ve",
    about = "Passwordless encrypted environment workspaces",
    version,
    after_help = "Examples:\n  ve init\n  ve status\n  ve pull --dry-run\n  ve pull --conflicts use-remote\n  ve push --file .env.local\n  ve completions zsh"
)]
pub(super) struct Cli {
    #[command(flatten)]
    pub options: Options,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args, Default)]
pub(super) struct Options {
    #[arg(
        long,
        global = true,
        default_value = ".env",
        value_name = "PATH",
        help = "Environment file, relative to the project containing .voe.json"
    )]
    pub file: PathBuf,
    #[arg(
        long,
        global = true,
        help = "Output structured JSON; disables interactive prompts"
    )]
    pub json: bool,
    #[arg(
        short,
        long,
        global = true,
        help = "Suppress normal output; errors and auth instructions remain"
    )]
    pub quiet: bool,
    #[arg(
        long,
        global = true,
        help = "Never prompt; fail with the flags needed to continue"
    )]
    pub no_input: bool,
    #[arg(
        long,
        global = true,
        help = "Print the approval URL without opening a browser"
    )]
    pub no_browser: bool,
}

impl Options {
    pub fn interactive(&self) -> bool {
        !self.no_input
            && !self.json
            && !self.quiet
            && io::stdin().is_terminal()
            && io::stderr().is_terminal()
    }

    pub fn env_path(&self, project: &Project) -> PathBuf {
        project.root.join(&self.file)
    }

    pub fn emit(&self, value: &Value, human: &str) -> Result<()> {
        if self.json {
            writeln!(io::stdout().lock(), "{}", serde_json::to_string(value)?)?;
        } else if !self.quiet && !human.is_empty() {
            writeln!(io::stdout().lock(), "{}", human.trim_end())?;
        }
        Ok(())
    }

    pub fn progress(&self, message: &str) {
        if !self.quiet && !self.json {
            eprintln!("{message}");
        }
    }
}

#[derive(Subcommand)]
pub(super) enum Commands {
    #[command(
        about = "Enroll this CLI using your browser and passkey",
        after_help = "Examples:\n  ve auth\n  ve auth --no-browser"
    )]
    Auth,
    #[command(about = "Remove this CLI's locally stored credentials")]
    Logout,
    #[command(about = "Update ve to the latest release")]
    Update,
    #[command(about = "List workspaces you belong to")]
    Workspaces,
    #[command(
        about = "Connect this project to a workspace and folder",
        after_help = "Examples:\n  ve init\n  ve init --org wemuda --path app:development\n  ve init --org wemuda --path / --no-input"
    )]
    Init {
        #[arg(long, help = "Workspace name or ID; omit to choose a workspace")]
        org: Option<String>,
        #[arg(
            short,
            long,
            help = "Existing folder path; use / for root; omit to choose interactively"
        )]
        path: Option<String>,
    },
    #[command(about = "Show project context, authentication, and sync status")]
    Status,
    #[command(
        about = "Encrypt and push the local environment file",
        after_help = "Examples:\n  ve push --dry-run\n  ve push\n  ve push --force --dry-run"
    )]
    Push {
        #[arg(long, help = "Also delete remote keys absent from the local file")]
        force: bool,
        #[arg(long, help = "Preview changes without uploading anything")]
        dry_run: bool,
    },
    #[command(
        about = "Pull remote secrets into the local environment file",
        after_help = "Examples:\n  ve pull --dry-run\n  ve pull --conflicts keep-local\n  ve pull --conflicts use-remote\n  ve pull --force"
    )]
    Pull {
        #[arg(
            long,
            conflicts_with = "conflicts",
            help = "Replace the entire local file, removing local-only keys"
        )]
        force: bool,
        #[arg(long, help = "Preview changes and conflicts without writing a file")]
        dry_run: bool,
        #[arg(
            long,
            value_enum,
            help = "Resolve differing values while retaining local-only keys"
        )]
        conflicts: Option<ConflictPolicy>,
    },
    #[command(about = "Show folders and secret names in a tree")]
    List,
    #[command(about = "Compare local and remote values without printing them")]
    Diff {
        #[arg(long, help = "Include unchanged keys")]
        all: bool,
    },
    #[command(about = "Search secret names in the selected workspace")]
    Search { pattern: String },
    #[command(about = "Validate the local environment file")]
    Validate,
    #[command(about = "Show the current authenticated account")]
    Whoami,
    #[command(about = "Test authenticated access")]
    Test,
    #[command(
        about = "Generate shell completion scripts",
        after_help = "Examples:\n  ve completions zsh > ~/.zfunc/_ve\n  ve completions bash > ~/.ve-completion.bash\n  ve completions fish > ~/.config/fish/completions/ve.fish"
    )]
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}
