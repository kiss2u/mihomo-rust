use anyhow::Result;
use clap::Parser;
use mihomo_api::ApiServer;
use mihomo_config::load_config;
use mihomo_config::raw::RawConfig;
use mihomo_dns::DnsServer;
use mihomo_listener::{MixedListener, TunListener, TunListenerConfig};
use mihomo_tunnel::Tunnel;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "mihomo", version, about = "A rule-based tunnel in Rust")]
struct Args {
    /// Path to configuration file
    #[arg(short = 'f', long = "config", default_value = "config.example.yaml")]
    config: String,

    /// Home directory
    #[arg(short = 'd', long = "directory")]
    directory: Option<String>,

    /// Test configuration and exit
    #[arg(short = 't', long = "test")]
    test: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

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

    // Start TUN listener if configured and enabled
    if let Some(ref tun_config) = config.tun {
        if tun_config.enable {
            let tun_listener_config = TunListenerConfig {
                device: tun_config.device.clone(),
                mtu: tun_config.mtu,
                inet4_address: tun_config.inet4_address.clone(),
                dns_hijack: tun_config.dns_hijack.clone(),
            };
            let tun = TunListener::new(
                tunnel.clone(),
                tun_listener_config,
                config.dns.resolver.clone(),
            );
            tokio::spawn(async move {
                if let Err(e) = tun.run().await {
                    error!("TUN listener error: {}", e);
                }
            });
        }
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
