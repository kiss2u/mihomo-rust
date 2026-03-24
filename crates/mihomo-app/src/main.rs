use anyhow::Result;
use clap::{Parser, Subcommand};
use mihomo_api::ApiServer;
use mihomo_config::load_config;
use mihomo_config::raw::RawConfig;
use mihomo_dns::DnsServer;
use mihomo_listener::MixedListener;
use mihomo_tunnel::Tunnel;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

const SERVICE_NAME: &str = "mihomo";

#[derive(Parser)]
#[command(name = "mihomo", version, about = "A rule-based tunnel in Rust")]
struct Args {
    /// Path to configuration file
    #[arg(short = 'f', long = "config", default_value = "config.yaml")]
    config: String,

    /// Home directory
    #[arg(short = 'd', long = "directory")]
    directory: Option<String>,

    /// Test configuration and exit
    #[arg(short = 't', long = "test")]
    test: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Install as a systemd service
    Install {
        /// Config file path (absolute) for the service
        #[arg(short = 'f', long = "config")]
        config: Option<String>,
    },
    /// Uninstall the systemd service
    Uninstall,
    /// Show service status
    Status,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Handle subcommands before initializing logging/runtime
    if let Some(cmd) = &args.command {
        return handle_service_command(cmd, &args);
    }

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("mihomo-rust starting...");

    // Initialize rustls crypto provider (required for TLS-based proxy protocols)
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load config
    let config_path = if let Some(dir) = &args.directory {
        format!("{}/{}", dir, args.config)
    } else {
        args.config.clone()
    };

    let config = load_config(&config_path)?;
    info!("Config loaded from {}", config_path);

    if args.test {
        info!("Configuration test passed");
        return Ok(());
    }

    // Run the async runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move { run(config, config_path).await })
}

fn handle_service_command(cmd: &Command, args: &Args) -> Result<()> {
    match cmd {
        Command::Install { config } => install_service(config.as_deref(), args),
        Command::Uninstall => uninstall_service(),
        Command::Status => service_status(),
    }
}

fn install_service(config_override: Option<&str>, args: &Args) -> Result<()> {
    // Determine the binary path
    let exe_path = std::env::current_exe()?;
    let exe_path = exe_path
        .canonicalize()
        .unwrap_or(exe_path)
        .to_string_lossy()
        .to_string();

    // Determine config path (absolute)
    let config_rel = config_override.unwrap_or(&args.config);
    let config_path = if std::path::Path::new(config_rel).is_absolute() {
        config_rel.to_string()
    } else {
        let cwd = std::env::current_dir()?;
        cwd.join(config_rel).to_string_lossy().to_string()
    };

    // Determine working directory (config file's parent)
    let work_dir = std::path::Path::new(&config_path)
        .parent()
        .unwrap_or(std::path::Path::new("/"))
        .to_string_lossy()
        .to_string();

    let unit = format!(
        r#"[Unit]
Description=mihomo-rust proxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} -f {config}
WorkingDirectory={work_dir}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={work_dir}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"#,
        exe = exe_path,
        config = config_path,
        work_dir = work_dir,
    );

    let service_path = format!("/etc/systemd/system/{}.service", SERVICE_NAME);

    // Check if running as root
    if !is_root() {
        eprintln!("Root privileges required. Run with sudo:");
        eprintln!("  sudo {} install -f {}", exe_path, config_path);
        std::process::exit(1);
    }

    // Write service file
    std::fs::write(&service_path, &unit)?;
    println!("Service file written to {}", service_path);

    // Reload systemd and enable
    run_cmd("systemctl", &["daemon-reload"])?;
    run_cmd("systemctl", &["enable", SERVICE_NAME])?;
    run_cmd("systemctl", &["start", SERVICE_NAME])?;

    println!();
    println!("mihomo service installed and started.");
    println!();
    println!("  Config:  {}", config_path);
    println!("  Binary:  {}", exe_path);
    println!();
    println!("Commands:");
    println!("  sudo systemctl status {}", SERVICE_NAME);
    println!("  sudo systemctl restart {}", SERVICE_NAME);
    println!("  sudo systemctl stop {}", SERVICE_NAME);
    println!("  sudo journalctl -u {} -f", SERVICE_NAME);

    Ok(())
}

fn uninstall_service() -> Result<()> {
    if !is_root() {
        let exe = std::env::current_exe().unwrap_or_default();
        eprintln!("Root privileges required. Run with sudo:");
        eprintln!("  sudo {} uninstall", exe.display());
        std::process::exit(1);
    }

    let service_path = format!("/etc/systemd/system/{}.service", SERVICE_NAME);

    // Stop and disable
    let _ = run_cmd("systemctl", &["stop", SERVICE_NAME]);
    let _ = run_cmd("systemctl", &["disable", SERVICE_NAME]);

    // Remove service file
    if std::path::Path::new(&service_path).exists() {
        std::fs::remove_file(&service_path)?;
        println!("Removed {}", service_path);
    }

    run_cmd("systemctl", &["daemon-reload"])?;
    println!("mihomo service uninstalled.");

    Ok(())
}

fn service_status() -> Result<()> {
    let output = std::process::Command::new("systemctl")
        .args(["status", SERVICE_NAME])
        .output()?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    true
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{} {} failed with {}", cmd, args.join(" "), status);
    }
    Ok(())
}

async fn run(config: mihomo_config::Config, config_path: String) -> Result<()> {
    // Keep raw config in shared state for runtime mutations
    let raw_config = Arc::new(RwLock::new(config.raw.clone()));

    // Create the tunnel (core routing engine)
    let tunnel = Tunnel::new(config.dns.resolver.clone());
    tunnel.set_mode(config.general.mode);
    tunnel.update_rules(config.rules);
    tunnel.update_proxies(config.proxies);

    // Start DNS server if configured
    if let Some(listen_addr) = config.dns.listen_addr {
        let dns_server = DnsServer::new(config.dns.resolver.clone(), listen_addr);
        tokio::spawn(async move {
            if let Err(e) = dns_server.run().await {
                error!("DNS server error: {}", e);
            }
        });
    }

    // Start REST API if configured
    if let Some(api_addr) = config.api.external_controller {
        let api_server = ApiServer::new(
            tunnel.clone(),
            api_addr,
            config.api.secret.clone(),
            config_path.clone(),
            raw_config.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = api_server.run().await {
                error!("API server error: {}", e);
            }
        });
    }

    // Start subscription background refresh task
    {
        let raw_config = raw_config.clone();
        let tunnel = tunnel.clone();
        let config_path = config_path.clone();
        tokio::spawn(async move {
            subscription_refresh_loop(raw_config, tunnel, config_path).await;
        });
    }

    // Start listeners
    let bind_addr = &config.listeners.bind_address;

    if let Some(port) = config.listeners.mixed_port {
        let addr: SocketAddr = format!("{}:{}", bind_addr, port).parse()?;
        let listener = MixedListener::new(tunnel.clone(), addr);
        tokio::spawn(async move {
            if let Err(e) = listener.run().await {
                error!("Mixed listener error: {}", e);
            }
        });
    }

    if let Some(port) = config.listeners.socks_port {
        let addr: SocketAddr = format!("{}:{}", bind_addr, port).parse()?;
        let listener = MixedListener::new(tunnel.clone(), addr);
        tokio::spawn(async move {
            if let Err(e) = listener.run().await {
                error!("SOCKS listener error: {}", e);
            }
        });
    }

    if let Some(port) = config.listeners.http_port {
        let addr: SocketAddr = format!("{}:{}", bind_addr, port).parse()?;
        let listener = MixedListener::new(tunnel.clone(), addr);
        tokio::spawn(async move {
            if let Err(e) = listener.run().await {
                error!("HTTP listener error: {}", e);
            }
        });
    }

    info!("mihomo-rust is running");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}

async fn subscription_refresh_loop(
    raw_config: Arc<RwLock<RawConfig>>,
    tunnel: Tunnel,
    _config_path: String,
) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        let subs_to_refresh: Vec<(String, String)> = {
            let raw = raw_config.read();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            raw.subscriptions
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter(|s| {
                    if let (Some(interval), Some(last)) = (s.interval, s.last_updated) {
                        now - last >= interval as i64
                    } else {
                        false
                    }
                })
                .map(|s| (s.name.clone(), s.url.clone()))
                .collect()
        };

        for (name, url) in subs_to_refresh {
            info!("Auto-refreshing subscription '{}'", name);
            match mihomo_config::subscription::fetch_subscription(&url).await {
                Ok(fetched) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    let mut raw = raw_config.write();

                    if let Some(ref mut subs) = raw.subscriptions {
                        if let Some(sub) = subs.iter_mut().find(|s| s.name == name) {
                            sub.last_updated = Some(now);
                        }
                    }

                    // Replace with remote data as-is
                    raw.proxies = Some(fetched.proxies);
                    raw.proxy_groups = Some(fetched.proxy_groups);
                    raw.rules = Some(fetched.rules);

                    match mihomo_config::rebuild_from_raw(&raw) {
                        Ok((new_proxies, new_rules)) => {
                            tunnel.update_proxies(new_proxies);
                            tunnel.update_rules(new_rules);
                            info!("Subscription '{}' refreshed successfully", name);
                        }
                        Err(e) => error!("Failed to rebuild after refreshing '{}': {}", name, e),
                    }
                }
                Err(e) => error!("Failed to refresh subscription '{}': {}", name, e),
            }
        }
    }
}
