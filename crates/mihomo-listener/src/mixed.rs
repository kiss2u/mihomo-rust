use crate::http_proxy;
use crate::socks5;
use mihomo_tunnel::Tunnel;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

pub struct MixedListener {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    name: String,
}

impl MixedListener {
    pub fn new(tunnel: Tunnel, listen_addr: SocketAddr, name: String) -> Self {
        Self {
            tunnel,
            listen_addr,
            name,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!("Mixed listener '{}' on {}", self.name, self.listen_addr);

        loop {
            let (stream, src_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!("Accept error: {}", e);
                    continue;
                }
            };

            let tunnel = self.tunnel.clone();
            let name = self.name.clone();
            let port = self.listen_addr.port();
            tokio::spawn(async move {
                handle_connection(tunnel, stream, src_addr, name, port).await;
            });
        }
    }
}

async fn handle_connection(
    tunnel: Tunnel,
    stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    name: String,
    port: u16,
) {
    // Peek the first byte to determine protocol
    let mut peek = [0u8; 1];
    match stream.peek(&mut peek).await {
        Ok(0) => return,
        Ok(_) => {}
        Err(e) => {
            debug!("Peek error: {}", e);
            return;
        }
    }

    if peek[0] == 0x05 {
        // SOCKS5
        socks5::handle_socks5(&tunnel, stream, src_addr, &name, port).await;
    } else {
        // HTTP proxy
        http_proxy::handle_http(&tunnel, stream, src_addr, &name, port).await;
    }
}
