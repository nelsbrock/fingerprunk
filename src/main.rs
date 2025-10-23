use std::io::{self, IsTerminal};

use anyhow::{Context as AnyhowContext, anyhow};
use clap::{ArgAction, Parser, ValueEnum};
use fancy_regex::Regex;
use fingerprunk::Fingerprunk;

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

    /// Prompt for a password and use it to encrypt found keys.
    ///
    /// By default, found keys are printed to stdout unencrypted. Use this if you actually plan to
    /// use generated keys.
    #[arg(short, long, action = ArgAction::SetTrue)]
    password: bool,
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

    let config = fingerprunk::Config {
        regex: args.regex,
        status_enabled: args.status.evaluate(),
        password,
    };

    Fingerprunk::new_from_config(config).run();

    Ok(())
}
