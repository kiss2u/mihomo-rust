mod firewall;
mod orig_dest;
mod sni;

use firewall::FirewallGuard;
use mihomo_common::{ConnType, Metadata, Network};
use mihomo_tunnel::Tunnel;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

pub struct TProxyListener {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    enable_sni: bool,
    routing_mark: Option<u32>,
    name: String,
}

impl TProxyListener {
    pub fn new(
        tunnel: Tunnel,
        listen_addr: SocketAddr,
        enable_sni: bool,
        routing_mark: Option<u32>,
        name: String,
    ) -> Self {
        Self {
            tunnel,
            listen_addr,
            enable_sni,
            routing_mark,
            name,
        }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Collect upstream proxy server IPs for firewall bypass
        let bypass_ips = collect_proxy_server_ips(&self.tunnel);

        // Set up firewall redirect rules (tears down on drop)
        let _firewall =
            FirewallGuard::setup(self.listen_addr.port(), self.routing_mark, &bypass_ips)?;

        let listener = TcpListener::bind(self.listen_addr).await?;
        info!(
            "TProxy listener '{}' started on {}",
            self.name, self.listen_addr
        );

        loop {
            let (stream, src_addr) = listener.accept().await?;
            let tunnel = self.tunnel.clone();
            let listen_addr = self.listen_addr;
            let enable_sni = self.enable_sni;
            let name = self.name.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    handle_tproxy_conn(tunnel, stream, src_addr, listen_addr, enable_sni, name)
                        .await
                {
                    debug!("TProxy connection error from {}: {}", src_addr, e);
                }
            });
        }
    }
}

/// Collect all upstream proxy server IPs from the tunnel's proxy map.
/// These IPs must be excluded from firewall redirection to prevent loops.
fn collect_proxy_server_ips(tunnel: &Tunnel) -> Vec<IpAddr> {
    let proxies = tunnel.proxies();
    let mut ips = HashSet::new();

    for proxy in proxies.values() {
        let addr_str = proxy.addr();
        if addr_str.is_empty() {
            continue;
        }

        // Try parsing as ip:port directly
        if let Ok(sock) = addr_str.parse::<SocketAddr>() {
            ips.insert(sock.ip());
            continue;
        }

        // Try parsing as just an IP
        if let Ok(ip) = addr_str.parse::<IpAddr>() {
            ips.insert(ip);
            continue;
        }

        // Try DNS resolution for host:port
        if let Ok(resolved) = addr_str.to_socket_addrs() {
            for sock in resolved {
                ips.insert(sock.ip());
            }
        }
    }

    let result: Vec<IpAddr> = ips.into_iter().collect();
    info!(
        "Collected {} upstream proxy IPs for firewall bypass: {:?}",
        result.len(),
        result
    );
    result
}

async fn handle_tproxy_conn(
    tunnel: Tunnel,
    mut stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    listen_addr: SocketAddr,
    enable_sni: bool,
    name: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Recover the original destination address
    let orig_dst = orig_dest::get_original_dst(&stream, listen_addr)?;

    // Skip connections where original dest equals listen addr (self-connection)
    if orig_dst == listen_addr {
        return Err("original destination is the listen address (loop detected)".into());
    }

    // Recover hostname:
    // 1. Try SNI extraction for HTTPS (port 443)
    // 2. Fall back to DNS snooping reverse lookup (IP → domain from recent DNS queries)
    let mut hostname = if enable_sni && orig_dst.port() == 443 {
        sni::extract_sni(&stream).await.unwrap_or_default()
    } else {
        String::new()
    };

    if hostname.is_empty() {
        if let Some(domain) = tunnel.resolver().reverse_lookup(orig_dst.ip()) {
            hostname = domain;
        }
    }

    debug!(
        "TProxy {} -> {} (host: {})",
        src_addr,
        orig_dst,
        if hostname.is_empty() {
            "<none>"
        } else {
            &hostname
        }
    );

    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::TProxy,
        src_ip: Some(src_addr.ip()),
        src_port: src_addr.port(),
        dst_ip: Some(orig_dst.ip()),
        dst_port: orig_dst.port(),
        host: hostname,
        in_name: name,
        in_port: listen_addr.port(),
        ..Default::default()
    };

    let inner = tunnel.inner();
    let (proxy, rule_name, rule_payload) = match inner.resolve_proxy(&metadata) {
        Some(v) => v,
        None => return Err("no matching rule".into()),
    };

    info!(
        "{} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    let conn_id = inner.stats.track_connection(
        metadata.pure(),
        &rule_name,
        &rule_payload,
        vec![proxy.name().to_string()],
    );

    match proxy.dial_tcp(&metadata).await {
        Ok(mut remote) => match tokio::io::copy_bidirectional(&mut stream, &mut remote).await {
            Ok((up, down)) => {
                inner.stats.add_upload(up as i64);
                inner.stats.add_download(down as i64);
            }
            Err(e) => debug!("TProxy relay error: {}", e),
        },
        Err(e) => warn!("TProxy dial error: {}", e),
    }

    inner.stats.close_connection(&conn_id);
    Ok(())
}
