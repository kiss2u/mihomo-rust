use crate::tunnel::TunnelInner;
use dashmap::DashMap;
use mihomo_common::{Metadata, ProxyPacketConn};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// NAT table entry for UDP sessions
pub struct UdpSession {
    pub conn: Box<dyn ProxyPacketConn>,
    pub proxy_name: String,
}

// Direction A (ADR-0008 §6): key is a (src, dst) SocketAddr tuple — zero heap
// allocation on the per-packet fast path, replacing the previous String built
// by `format!("{}:{}", src, metadata.remote_address())`.
pub type NatTable = Arc<DashMap<(SocketAddr, SocketAddr), Arc<UdpSession>>>;

pub fn new_nat_table() -> NatTable {
    Arc::new(DashMap::new())
}

/// Handle a UDP packet: look up or create a NAT session.
pub async fn handle_udp(
    tunnel: &TunnelInner,
    data: &[u8],
    src: SocketAddr,
    mut metadata: Metadata,
) {
    // Pre-resolve metadata (host -> real IP if rules need it).
    tunnel.pre_resolve(&mut metadata).await;

    // Build destination SocketAddr for the NAT key.
    // pre_resolve() populates dst_ip for any hostname; if it is still None
    // after that (resolution failure or unresolvable host), we cannot track
    // the session and must discard the packet.
    let Some(dst_ip) = metadata.dst_ip else {
        warn!(
            "UDP {}: dst_ip not resolved after pre_resolve — dropping",
            metadata.remote_address()
        );
        return;
    };
    let dst_addr = SocketAddr::new(dst_ip, metadata.dst_port);
    let key = (src, dst_addr);

    // Fast path: existing session — forward and return.
    if let Some(session) = tunnel.nat_table.get(&key) {
        if let Err(e) = session.conn.write_packet(data, &dst_addr).await {
            debug!("UDP write error for {} -> {}: {}", src, dst_addr, e);
            tunnel.nat_table.remove(&key);
        }
        return;
    }

    // Slow path: new session — match rules and dial.
    let (proxy, rule_name, rule_payload) = match tunnel.resolve_proxy(&metadata) {
        Some(v) => v,
        None => {
            warn!("no matching rule for UDP {}", metadata.remote_address());
            return;
        }
    };

    info!(
        "UDP {} --> {} match {}({}) using {}",
        src,
        dst_addr,
        rule_name,
        rule_payload,
        proxy.name()
    );

    match proxy.dial_udp(&metadata).await {
        Ok(conn) => {
            if let Err(e) = conn.write_packet(data, &dst_addr).await {
                warn!("UDP initial write error for {} -> {}: {}", src, dst_addr, e);
                return;
            }
            let session = Arc::new(UdpSession {
                conn,
                proxy_name: proxy.name().to_string(),
            });
            tunnel.nat_table.insert(key, session);
        }
        Err(e) => {
            warn!("UDP dial error for {} -> {}: {}", src, dst_addr, e);
        }
    }
}
