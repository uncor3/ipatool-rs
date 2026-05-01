use clap::{Parser, Subcommand};
use env_logger::Env;
use indicatif::{ProgressBar, ProgressStyle};
use ipatool::util::{with_error_style, with_success_style};
use ipatool::{DownloadArgs, IpaTool};
use log::{error, info, trace, warn};
use std::io;

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
        #[arg(long, default_value_t = 5)]
        limit: u32,
    },
    Purchase {
        #[arg(long)]
        bundle_identifier: String,
    },
    Download {
        #[arg(long)]
        bundle_identifier: String,
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

    io::stdin().read_line(&mut input).map_err(|e| {
        ipatool::error::IpaToolError::Unexpected(format!("Failed to read input: {}", e))
    })?;

    //trim should be fine
    Ok(input.trim().to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let tool = IpaTool::new_default().await?;
    match cli.cmd {
        Command::Auth { cmd } => match cmd {
            AuthCommand::Login {
                email,
                password,
                auth_code,
            } => {
                tool.login(&email, &password, Some(Box::new(auth_cb)), auth_code)
                    .await?;
            }
            AuthCommand::Info => match tool.account_info().await? {
                Some(acc) => {
                    let msg = format!(
                        "Current account details: email: {}, name: {}",
                        acc.email, acc.name
                    );
                    info!("{}", with_success_style(msg));
                }
                None => error!("{}", with_error_style("No account".to_string())),
            },
            AuthCommand::Revoke => {
                tool.revoke().await?;
                println!(r#"{{"success":true}}"#);
            }
        },
        Command::Search { term, limit } => {
            let out = tool.search(&term, limit).await?;
            println!("{}", serde_json::to_string(&out)?);
        }
        Command::Purchase { bundle_identifier } => {
            tool.purchase(&bundle_identifier).await?;
            let msg = format!(
                "Purchased app with bundle identifier: {}",
                bundle_identifier
            );
            info!("{}", with_success_style(msg));
        }
        Command::Download {
            bundle_identifier,
            output,
            external_version_id,
            purchase,
        } => {
            let pb = ProgressBar::new_spinner();
            pb.enable_steady_tick(std::time::Duration::from_millis(120));
            pb.set_message("downloading...");

            let pb_cb = pb.clone();
            let out = tool
                .download_with_progress(
                    DownloadArgs {
                        bundle_id: bundle_identifier,
                        output_path: output,
                        external_version_id,
                        acquire_license: purchase,
                    },
                    move |downloaded, total| {
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
                                ProgressStyle::with_template(
                                    "{spinner:.green} {bytes} downloaded",
                                )
                                .unwrap(),
                            );
                            pb_cb.set_position(downloaded);
                        }
                    },
                )
                .await?;

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
