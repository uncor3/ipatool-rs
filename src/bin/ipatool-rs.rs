use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use ipatool::{CredentialBackend, DownloadArgs, IpaTool, Platform};
use std::io;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "ipatool-rs",
    about = "Download IPAs directly from Apple",
    after_long_help = "
    Download IPAs directly from Apple, a port of ipatool by @majd to pure Rust.
    Written primarily for ®iDescriptor.\n
    If you like this tool you probably would also like iDescriptor: https://github.com/iDescriptor/iDescriptor
    Github repo https://github.com/uncor3/ipatool-rs\n\n
    Not affiliated with Apple",
    version
)]
struct Cli {
    #[arg(long, global = true)]
    keychain_passphrase: Option<String>,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    Auth {
        #[command(subcommand)]
        cmd: AuthCommand,
    },
    Search {
        term: String,
        #[arg(long, default_value = "iphone")]
        platform: Platform,
        #[arg(long, default_value_t = 5)]
        limit: u32,
    },
    Purchase {
        #[arg(long)]
        bundle_identifier: String,
    },
    Download {
        #[arg(long, required_unless_present = "app_id")]
        bundle_identifier: Option<String>,
        #[arg(
            long,
            help = "Numeric App Store ID; also supports owned, delisted apps"
        )]
        app_id: Option<i64>,
        #[arg(long, default_value = "iphone")]
        platform: Platform,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        external_version_id: Option<String>,
        #[arg(long, default_value_t = false)]
        purchase: bool,
    },
    ListVersions {
        #[arg(long)]
        app_id: Option<u64>,
        #[arg(long)]
        bundle_identifier: Option<String>,
    },
    GetVersionMetadata {
        #[arg(long)]
        app_id: Option<u64>,
        #[arg(long)]
        bundle_identifier: Option<String>,
        #[arg(long)]
        external_version_id: String,
    },
}

#[derive(Subcommand)]
enum AuthCommand {
    Login {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        auth_code: Option<String>,
    },
    Info,
    Revoke,
}

fn auth_cb() -> ipatool::Result<String> {
    let mut input = "".to_string();

    println!("Enter 2FA Code:");

    io::stdin().read_line(&mut input)?;

    //trim should be fine
    Ok(input.trim().to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let login_will_write_account = matches!(
        &cli.cmd,
        Command::Auth {
            cmd: AuthCommand::Login { .. }
        }
    );
    let tool = IpaTool::new_default_with_passphrase(cli.keychain_passphrase.clone())?;
    if tool.credential_backend() == CredentialBackend::EncryptedFile
        && cli.keychain_passphrase.is_none()
        && tool.requires_keyring_passphrase()
    {
        let passphrase = rpassword::prompt_password(
            "Enter passphrase to unlock ~/.ipatool (separate from your Apple Account password): ",
        )?;
        tool.set_keyring_passphrase(passphrase)?;
    } else if tool.credential_backend() == CredentialBackend::EncryptedFile
        && cli.keychain_passphrase.is_none()
        && login_will_write_account
    {
        let passphrase = loop {
            let first = rpassword::prompt_password(
                "Create a passphrase for ~/.ipatool (separate from your Apple Account password): ",
            )?;
            let mut confirmation = rpassword::prompt_password("Confirm keyring passphrase: ")?;
            let matches = first == confirmation;
            confirmation.zeroize();
            if matches {
                break first;
            }
            eprintln!("Passphrases do not match. Try again.");
        };
        tool.set_keyring_passphrase(passphrase)?;
    }
    match cli.cmd {
        Command::Auth { cmd } => match cmd {
            AuthCommand::Login {
                email,
                password,
                auth_code,
            } => {
                tool.login(&email, &password, Some(Box::new(auth_cb)), auth_code)
                    .await?;

                eprintln!("Logged in successfully");
            }
            AuthCommand::Info => match tool.account_info()? {
                Some(acc) => {
                    let msg = format!(
                        "Current account details: email: {}, name: {}",
                        acc.email, acc.name
                    );
                    eprintln!("{msg}");
                }
                None => eprintln!("No account"),
            },
            AuthCommand::Revoke => {
                tool.revoke()?;
                println!(r#"{{"success":true}}"#);
            }
        },
        Command::Search {
            term,
            limit,
            platform,
        } => {
            let out = tool.search_for_platform(&term, limit, platform).await?;
            println!("{}", serde_json::to_string(&out)?);
        }
        Command::Purchase { bundle_identifier } => {
            tool.purchase(&bundle_identifier).await?;
            let msg = format!(
                "Purchased app with bundle identifier: {}",
                bundle_identifier
            );
            eprintln!("{msg}");
        }
        Command::Download {
            bundle_identifier,
            app_id,
            platform,
            output,
            external_version_id,
            purchase,
        } => {
            let pb = ProgressBar::new_spinner();
            pb.enable_steady_tick(std::time::Duration::from_millis(120));
            pb.set_message("downloading...");

            let pb_cb = pb.clone();
            let progress = move |downloaded, total| {
                if let Some(t) = total {
                    if pb_cb.length() != Some(t) {
                        pb_cb.set_length(t);
                        pb_cb.set_style(
                                    ProgressStyle::with_template(
                                        "{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
                                    )
                                    .unwrap(),
                                );
                    }
                    pb_cb.set_position(downloaded);
                } else {
                    pb_cb.set_style(
                        ProgressStyle::with_template("{spinner:.green} {bytes} downloaded")
                            .unwrap(),
                    );
                    pb_cb.set_position(downloaded);
                }
            };
            let args = DownloadArgs {
                bundle_id: bundle_identifier.unwrap_or_default(),
                output_path: output,
                external_version_id,
                acquire_license: purchase,
            };
            let out = match app_id {
                Some(app_id) => {
                    tool.download_by_id_for_platform_with_progress(app_id, args, platform, progress)
                        .await?
                }
                None => {
                    tool.download_for_platform_with_progress(args, platform, progress)
                        .await?
                }
            };

            pb.finish_and_clear();
            println!("{}", serde_json::to_string(&out)?);
        }
        Command::ListVersions {
            app_id,
            bundle_identifier,
        } => {
            let out = tool
                .list_versions(app_id, bundle_identifier.as_deref())
                .await?;
            println!("{}", serde_json::to_string(&out)?);
        }
        Command::GetVersionMetadata {
            app_id,
            bundle_identifier,
            external_version_id,
        } => {
            let out = tool
                .get_version_metadata(app_id, bundle_identifier.as_deref(), &external_version_id)
                .await?;
            println!("{}", serde_json::to_string(&out)?);
        }
    }

    Ok(())
}

mod anyhow {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
}
