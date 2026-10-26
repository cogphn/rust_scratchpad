//! WinRM honeypot: a fake Windows WinRM endpoint that logs everything.
//!
//! Deploy only on hosts and networks you own or have written permission to test.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

use winrm_honeypot::config::Config;
use winrm_honeypot::logging::EventLog;
use winrm_honeypot::server::serve;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
    /// Override server.listen, e.g. 127.0.0.1:5985
    #[arg(long)]
    listen: Option<String>,
    /// Override log.path ("-" = stdout)
    #[arg(long)]
    log_file: Option<String>,
    /// Validate the configuration and exit: no sockets, no log file.
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut cfg = Config::load(&args.config)?;
    if let Some(listen) = args.listen {
        cfg.server.listen = listen;
    }
    if let Some(path) = args.log_file {
        cfg.log.path = path;
    }

    if args.check_config {
        println!(
            "config OK: {} credentials, listen {}",
            cfg.credentials.len(),
            cfg.server.listen
        );
        return Ok(());
    }

    let log = Arc::new(EventLog::open(&cfg.log.path)?);

    println!(
        "winrm-honeypot: impersonating {} ({}), listen {}, log {}",
        cfg.identity.computer_name, cfg.identity.domain, cfg.server.listen, cfg.log.path
    );
    println!("winrm-honeypot: deploy only on networks you are authorised to monitor.");

    serve(cfg, log).await?;
    Ok(())
}
