use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser, Subcommand};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
    Mount,
    Unmount,
    SyncDaemon,
    Mounts,
}

/// Encrypt, decrypt, and transparently mount Valv (.valv) files.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "valv",
    about = "Encrypt, decrypt, and transparently mount Valv (.valv) files.",
    after_help = "If no command is specified, Valv files are decrypted, directories with Valv files are mounted, and others are encrypted.",
    version
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Files or directory to process (when no command is specified)
    #[arg(value_name = "FILES_OR_DIR")]
    pub files: Vec<PathBuf>,

    /// Password to use
    #[arg(short, long, global = true)]
    pub password: Option<String>,

    /// Read password from standard input
    #[arg(long, global = true)]
    pub stdin_password: bool,

    /// Output file or destination directory
    #[arg(short, long, global = true)]
    pub output: Option<PathBuf>,

    /// Process ID to watch (session terminates when PID exits)
    #[arg(long, global = true)]
    pub watch_pid: Option<u32>,

    /// Run mount watcher in foreground
    #[arg(long, global = true)]
    pub foreground: bool,

    /// Overwrite existing destination files
    #[arg(short, long, global = true)]
    pub force: bool,

    /// PBKDF2 iterations for encryption (default: 50000)
    #[arg(short, long, global = true)]
    pub iterations: Option<u32>,

    /// Stream decrypted content to standard output
    #[arg(long = "stdout", global = true)]
    pub to_stdout: bool,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Transparently mount vault into in-memory directory
    #[command(alias = "open")]
    Mount {
        /// Vault directory to mount (defaults to current directory)
        vault_dir: Option<PathBuf>,
    },
    /// Lock and unmount active vault session
    #[command(alias = "close")]
    Unmount {
        /// Active mount path or vault directory (defaults to current directory)
        target: Option<PathBuf>,
    },
    /// List active vault mounts
    #[command(alias = "list", alias = "ls")]
    Mounts,
    /// Encrypt file(s) into Valv v2 format
    Encrypt {
        /// Files to encrypt
        files: Vec<PathBuf>,
    },
    /// Decrypt Valv file(s) (v2 and v1)
    Decrypt {
        /// Valv files to decrypt
        files: Vec<PathBuf>,
    },
    /// Background daemon to synchronize changes between mount and vault
    #[command(name = "sync-daemon", hide = true)]
    SyncDaemon {
        /// Vault directory
        vault_dir: PathBuf,
        /// Mount directory
        mount_dir: PathBuf,
    },
}

impl CliArgs {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }

    #[cfg(test)]
    pub fn try_parse_from<I, T>(itr: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        <Self as Parser>::try_parse_from(itr)
    }

    pub fn resolve_mode_and_files(
        &self,
        is_valv_fn: impl Fn(&Path) -> bool,
    ) -> (Mode, Vec<PathBuf>) {
        if let Some(cmd) = &self.command {
            match cmd {
                Command::Mount { vault_dir } => {
                    let files = vault_dir
                        .as_ref()
                        .map(|p| vec![p.clone()])
                        .unwrap_or_else(|| {
                            if self.files.is_empty() {
                                vec![PathBuf::from(".")]
                            } else {
                                self.files.clone()
                            }
                        });
                    (Mode::Mount, files)
                }
                Command::Unmount { target } => {
                    let files = target.as_ref().map(|p| vec![p.clone()]).unwrap_or_else(|| {
                        if self.files.is_empty() {
                            vec![PathBuf::from(".")]
                        } else {
                            self.files.clone()
                        }
                    });
                    (Mode::Unmount, files)
                }
                Command::Mounts => (Mode::Mounts, Vec::new()),
                Command::Encrypt { files } => {
                    let files = if files.is_empty() {
                        self.files.clone()
                    } else {
                        files.clone()
                    };
                    (Mode::Encrypt, files)
                }
                Command::Decrypt { files } => {
                    let files = if files.is_empty() {
                        self.files.clone()
                    } else {
                        files.clone()
                    };
                    (Mode::Decrypt, files)
                }
                Command::SyncDaemon {
                    vault_dir,
                    mount_dir,
                } => (Mode::SyncDaemon, vec![vault_dir.clone(), mount_dir.clone()]),
            }
        } else {
            let files = if self.files.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                self.files.clone()
            };

            let mode = if files.len() == 1 && files[0].is_dir() {
                Mode::Mount
            } else if files.iter().any(|f| is_valv_fn(f)) {
                Mode::Decrypt
            } else {
                Mode::Encrypt
            };

            (mode, files)
        }
    }
}

pub fn print_help() {
    let _ = CliArgs::command().print_help();
    println!();
}

pub fn read_password(cli: &CliArgs) -> io::Result<String> {
    if let Some(ref pwd) = cli.password {
        return Ok(pwd.clone());
    }

    if cli.stdin_password || !io::stdin().is_terminal() {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_string();
        return Ok(trimmed);
    }

    rpassword::prompt_password("Password: ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args_encrypt() {
        let args = vec!["valv", "encrypt", "-p", "secret", "file.txt"];
        let cli = CliArgs::try_parse_from(args).unwrap();
        let (mode, files) = cli.resolve_mode_and_files(|_| false);
        assert_eq!(mode, Mode::Encrypt);
        assert_eq!(cli.password.as_deref(), Some("secret"));
        assert_eq!(files, vec![PathBuf::from("file.txt")]);
    }

    #[test]
    fn test_parse_args_options() {
        let args = vec!["valv", "-f", "--stdout", "-i", "10000", "sample.valv"];
        let cli = CliArgs::try_parse_from(args).unwrap();
        let (mode, files) = cli.resolve_mode_and_files(|p| p.to_string_lossy().ends_with(".valv"));
        assert_eq!(mode, Mode::Decrypt);
        assert!(cli.force);
        assert!(cli.to_stdout);
        assert_eq!(cli.iterations, Some(10000));
        assert_eq!(files, vec![PathBuf::from("sample.valv")]);
    }

    #[test]
    fn test_mount_alias_open() {
        let args = vec!["valv", "open", "my_vault"];
        let cli = CliArgs::try_parse_from(args).unwrap();
        let (mode, files) = cli.resolve_mode_and_files(|_| false);
        assert_eq!(mode, Mode::Mount);
        assert_eq!(files, vec![PathBuf::from("my_vault")]);
    }

    #[test]
    fn test_mounts_command() {
        let args = vec!["valv", "mounts"];
        let cli = CliArgs::try_parse_from(args).unwrap();
        let (mode, _) = cli.resolve_mode_and_files(|_| false);
        assert_eq!(mode, Mode::Mounts);

        let args_ls = vec!["valv", "ls"];
        let cli_ls = CliArgs::try_parse_from(args_ls).unwrap();
        let (mode_ls, _) = cli_ls.resolve_mode_and_files(|_| false);
        assert_eq!(mode_ls, Mode::Mounts);
    }

    #[test]
    fn test_parse_args_no_args_mounts_current_dir() {
        let args = vec!["valv"];
        let cli = CliArgs::try_parse_from(args).unwrap();
        let (mode, files) = cli.resolve_mode_and_files(|_| false);
        assert_eq!(mode, Mode::Mount);
        assert_eq!(files, vec![PathBuf::from(".")]);
    }
}
