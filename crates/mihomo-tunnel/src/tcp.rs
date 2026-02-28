use crate::tunnel::TunnelInner;
use mihomo_common::{DnsMode, Metadata, ProxyConn};
use mihomo_dns::Resolver;
use tokio::io;
use tracing::{debug, info, warn};

pub async fn handle_tcp(
    tunnel: &TunnelInner,
    mut conn: Box<dyn ProxyConn>,
    mut metadata: Metadata,
) {
    // Fix metadata: resolve FakeIP back to real host
    pre_handle_metadata(&mut metadata, &tunnel.resolver);

    // Match rules to find the right proxy
    let (proxy, rule_name, rule_payload) = match tunnel.resolve_proxy(&metadata) {
        Some(v) => v,
        None => {
            warn!("no matching rule for {}", metadata.remote_address());
            return;
        }
    };

    info!(
        "{} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    // Track the connection
    let conn_id = tunnel.stats.track_connection(
        metadata.pure(),
        &rule_name,
        &rule_payload,
        vec![proxy.name().to_string()],
    );

    // Dial the remote via proxy
    match proxy.dial_tcp(&metadata).await {
        Ok(mut remote) => {
            // Bidirectional copy
            match io::copy_bidirectional(&mut conn, &mut remote).await {
                Ok((up, down)) => {
                    tunnel.stats.add_upload(up as i64);
                    tunnel.stats.add_download(down as i64);
                    debug!(
                        "{} closed: up={} down={}",
                        metadata.remote_address(),
                        up,
                        down
                    );
                }
                Err(e) => {
                    debug!("{} relay error: {}", metadata.remote_address(), e);
                }
            }
        }
        Err(e) => {
            warn!("{} dial error: {}", metadata.remote_address(), e);
        }
    }

    tunnel.stats.close_connection(&conn_id);
}

fn pre_handle_metadata(metadata: &mut Metadata, resolver: &Resolver) {
    // If the destination IP is a FakeIP, look up the real host
    if let Some(dst_ip) = metadata.dst_ip {
        if resolver.is_fake_ip(dst_ip) {
            if let Some(host) = resolver.fake_ip_reverse(dst_ip) {
                metadata.host = host;
                metadata.dns_mode = DnsMode::FakeIp;
            }
        }
    }

    // If we have a host but no resolved IP, the actual resolution
    // happens lazily during rule matching.
}
