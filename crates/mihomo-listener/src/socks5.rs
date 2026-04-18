use mihomo_common::{ConnType, Metadata, Network};
use mihomo_tunnel::Tunnel;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
#[allow(dead_code)]
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;

pub async fn handle_socks5(
    tunnel: &Tunnel,
    mut stream: TcpStream,
    src_addr: SocketAddr,
    in_name: &str,
    in_port: u16,
) {
    if let Err(e) = handle_socks5_inner(tunnel, &mut stream, src_addr, in_name, in_port).await {
        debug!("SOCKS5 error from {}: {}", src_addr, e);
    }
}

async fn handle_socks5_inner(
    tunnel: &Tunnel,
    stream: &mut TcpStream,
    src_addr: SocketAddr,
    in_name: &str,
    in_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Version/method negotiation
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS5_VERSION {
        return Err("invalid SOCKS version".into());
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // Reply: no auth required
    stream.write_all(&[SOCKS5_VERSION, NO_AUTH]).await?;

    // 2. Request
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != SOCKS5_VERSION {
        return Err("invalid SOCKS version in request".into());
    }

    let cmd = req[1];
    let atyp = req[3];

    // Parse address
    let (host, dst_ip, dst_port) = parse_socks5_address(stream, atyp).await?;

    if cmd != CMD_CONNECT {
        // Send command not supported
        let reply = [SOCKS5_VERSION, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        stream.write_all(&reply).await?;
        return Err(format!("unsupported SOCKS5 command: {}", cmd).into());
    }

    // 3. Send success reply
    let reply = [
        SOCKS5_VERSION,
        REP_SUCCESS,
        0x00,
        ATYP_IPV4,
        0,
        0,
        0,
        0, // Bind addr
        0,
        0, // Bind port
    ];
    stream.write_all(&reply).await?;

    // 4. Build metadata and hand off to tunnel
    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Socks5,
        src_ip: Some(src_addr.ip()),
        src_port: src_addr.port(),
        dst_ip,
        dst_port,
        host,
        in_name: in_name.to_string(),
        in_port,
        ..Default::default()
    };

    debug!("SOCKS5 CONNECT to {}", metadata.remote_address());

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
        Ok(mut remote) => match tokio::io::copy_bidirectional(stream, &mut remote).await {
            Ok((up, down)) => {
                inner.stats.add_upload(up as i64);
                inner.stats.add_download(down as i64);
            }
            Err(e) => debug!("SOCKS5 relay error: {}", e),
        },
        Err(e) => warn!("SOCKS5 dial error: {}", e),
    }

    inner.stats.close_connection(&conn_id);
    Ok(())
}

async fn parse_socks5_address(
    stream: &mut TcpStream,
    atyp: u8,
) -> Result<(String, Option<IpAddr>, u16), Box<dyn std::error::Error + Send + Sync>> {
    match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let ip = IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
            let port = u16::from_be_bytes(port_buf);
            Ok((String::new(), Some(ip), port))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let host = String::from_utf8_lossy(&domain).to_string();
            let port = u16::from_be_bytes(port_buf);
            Ok((host, None, port))
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(addr));
            let port = u16::from_be_bytes(port_buf);
            Ok((String::new(), Some(ip), port))
        }
        _ => Err(format!("unsupported address type: {}", atyp).into()),
    }
}
