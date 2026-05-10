use std::{
    io::{self, IsTerminal},
    num::NonZero,
};

use anyhow::{Context, anyhow};
use clap::{ArgAction, Parser, ValueEnum};
use fancy_regex::Regex;
use fingerprunk::Fingerprunk;
use sequoia_openpgp::packet::UserID;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Filter key fingerprints by using a regular expression.
    ///
    /// This regex is matched against the hexadecimal representation of the fingerprint, without
    /// spaces or other additional symbols.
    ///
    /// This is implemented using the fancy-regex library: <https://crates.io/crates/fancy-regex>.
    /// You can test and debug your regex here: <https://fancy-regex.github.io/fancy-regex/>.
    #[arg(short, long)]
    regex: Regex,

    /// Show status information.
    ///
    /// By default, status information is only shown if stderr is bound to a terminal and stdout is
    /// *not* bound to a terminal. The latter in particular prevents found keys (which are printed
    /// to stdin) from being "overwritten" by status information printed to stderr.
    #[arg(long, value_enum, default_value_t)]
    status: StatusEnabled,

    /// Stop once the specified number of matching keys has been found.
    #[arg(long, value_name = "NUM")]
    stop_after: Option<NonZero<u64>>,

    /// Prompt for a password and use it to encrypt matching keys.
    ///
    /// By default, found keys are printed to stdout unencrypted. Use this if you actually plan to
    /// use generated keys.
    #[arg(short, long, action = ArgAction::SetTrue)]
    password: bool,

    /// Add the given user ID to matching keys.
    #[arg(short, long = "userid")]
    userid: Vec<UserID>,

    /// Explicitly do not add user IDs to matching keys.
    ///
    /// Disables the warning about importing keys without user IDs into GnuPG.
    #[arg(long, conflicts_with = "userid", action = ArgAction::SetTrue)]
    no_userid: bool,

    /// Use the specified amount of worker threads.
    ///
    /// If not specified, the amount of worker threads will be set to the amount of the machine's
    /// available parallelism.
    #[arg(long, value_name = "NUM")]
    workers: Option<NonZero<usize>>,
}

#[derive(ValueEnum, Clone, Copy, Debug, Default)]
enum StatusEnabled {
    #[default]
    Auto,
    Always,
    Never,
}

impl StatusEnabled {
    fn evaluate(self) -> bool {
        match self {
            Self::Auto => io::stderr().is_terminal() && !io::stdout().is_terminal(),
            Self::Always => true,
            Self::Never => false,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if !args.no_userid && args.userid.is_empty() {
        eprintln!(
            "WARNING: No user ID was provided.\n\
            You may experience problems importing generated keys into GnuPG.\n\
            Use `--userid <USERID>` to add a user ID.\n"
        )
    }

    let password = if args.password {
        let password = rpassword::prompt_password(
            "Enter password for encrypting found keys (leave empty for no encryption): ",
        )
        .with_context(|| "Failed to prompt password")?;
        if password.is_empty() {
            None
        } else {
            let password_retype = rpassword::prompt_password("Retype password: ")
                .with_context(|| "Failed to prompt password retype")?;
            if password_retype == password {
                Some(password.into())
            } else {
                return Err(anyhow!("Passwords do not match"));
            }
        }
    } else {
        None
    };

    let workers = match args.workers {
        Some(workers) => workers,
        None => std::thread::available_parallelism().context(
            "unable to determine available parallelism, \
            use `--workers <NUM>` to specify amount of worker threads",
        )?,
    };

    let config = fingerprunk::Config {
        regex: args.regex,
        status_enabled: args.status.evaluate(),
        stop_after: args.stop_after,
        password,
        userids: args.userid,
        workers,
    };

    Fingerprunk::new_from_config(config).run()?;

    Ok(())
}
