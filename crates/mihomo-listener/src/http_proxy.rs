use mihomo_common::{ConnType, Metadata, Network};
use mihomo_tunnel::Tunnel;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub async fn handle_http(tunnel: &Tunnel, mut stream: TcpStream, src_addr: SocketAddr) {
    if let Err(e) = handle_http_inner(tunnel, &mut stream, src_addr).await {
        debug!("HTTP proxy error from {}: {}", src_addr, e);
    }
}

async fn handle_http_inner(
    tunnel: &Tunnel,
    stream: &mut TcpStream,
    src_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read the HTTP request line and headers byte by byte until we find \r\n\r\n.
    // We avoid BufReader to prevent borrow issues with the stream.
    let mut request_buf = Vec::with_capacity(4096);
    let mut headers_done = false;

    while !headers_done {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err("connection closed before headers complete".into());
        }
        request_buf.push(byte[0]);

        // Check for \r\n\r\n at the end
        if request_buf.len() >= 4 {
            let len = request_buf.len();
            if request_buf[len - 4..] == [b'\r', b'\n', b'\r', b'\n'] {
                headers_done = true;
            }
        }

        // Safety limit
        if request_buf.len() > 8192 {
            return Err("request headers too large".into());
        }
    }

    // Parse the request line from the buffer
    let request_str = String::from_utf8_lossy(&request_buf);
    let request_line = request_str
        .lines()
        .next()
        .ok_or("empty request")?
        .to_string();

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("invalid HTTP request line".into());
    }

    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTPS CONNECT
        let (host, port) = parse_host_port(target, 443)?;

        let metadata = Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Https,
            src_ip: Some(src_addr.ip()),
            src_port: src_addr.port(),
            host: host.clone(),
            dst_port: port,
            ..Default::default()
        };

        debug!("HTTP CONNECT to {}:{}", host, port);

        // Send 200 Connection Established
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;

        // Hand off to tunnel
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
                Err(e) => debug!("HTTP CONNECT relay error: {}", e),
            },
            Err(e) => warn!("HTTP CONNECT dial error: {}", e),
        }

        inner.stats.close_connection(&conn_id);
    } else {
        // Plain HTTP - for now just return 502
        stream
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            .await?;
    }

    Ok(())
}

fn parse_host_port(
    target: &str,
    default_port: u16,
) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    // target is like "host:port" or just "host"
    if let Some((host, port_str)) = target.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok((host.to_string(), port));
        }
    }
    Ok((target.to_string(), default_port))
}
