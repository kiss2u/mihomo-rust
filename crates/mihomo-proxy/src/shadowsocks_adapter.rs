use async_trait::async_trait;
use mihomo_common::{
    AdapterType, Metadata, MihomoError, ProxyAdapter, ProxyConn, ProxyPacketConn, Result,
};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend, DatagramSocket, ProxySocket};
use shadowsocks::relay::Address;
use shadowsocks::ProxyClientStream;
use std::net::SocketAddr;
use tracing::debug;

pub struct ShadowsocksAdapter {
    name: String,
    server_config: ServerConfig,
    context: shadowsocks::context::SharedContext,
    addr_str: String,
    support_udp: bool,
}

impl ShadowsocksAdapter {
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        cipher: &str,
        udp: bool,
    ) -> Result<Self> {
        let cipher_kind = cipher
            .parse::<CipherKind>()
            .map_err(|_| MihomoError::Config(format!("unknown cipher: {}", cipher)))?;
        let server_config = ServerConfig::new((server, port), password, cipher_kind)
            .map_err(|e| MihomoError::Config(format!("invalid ss config: {}", e)))?;
        let context = Context::new_shared(ServerType::Local);
        let addr_str = format!("{}:{}", server, port);
        Ok(Self {
            name: name.to_string(),
            server_config,
            context,
            addr_str,
            support_udp: udp,
        })
    }
}

// Wrapper for the SS proxy stream
struct SsConn<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync>(S);

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> tokio::io::AsyncRead
    for SsConn<S>
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> tokio::io::AsyncWrite
    for SsConn<S>
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> Unpin for SsConn<S> {}
impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static> ProxyConn
    for SsConn<S>
{
}

// Wrapper for SS UDP ProxySocket
struct SsPacketConn<S: DatagramSend + DatagramReceive + DatagramSocket + Send + Sync + 'static> {
    socket: ProxySocket<S>,
}

#[async_trait]
impl<S: DatagramSend + DatagramReceive + DatagramSocket + Send + Sync + 'static> ProxyPacketConn
    for SsPacketConn<S>
{
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (n, addr, _) = self
            .socket
            .recv(buf)
            .await
            .map_err(|e| MihomoError::Proxy(format!("ss udp recv: {}", e)))?;
        let sock_addr = match addr {
            Address::SocketAddress(sa) => sa,
            Address::DomainNameAddress(host, port) => format!("{}:{}", host, port)
                .parse()
                .map_err(|e| MihomoError::Proxy(format!("addr parse: {}", e)))?,
        };
        Ok((n, sock_addr))
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        let target = Address::SocketAddress(*addr);
        // ProxySocket::send returns the encrypted packet size (with protocol overhead),
        // but callers expect the payload size.
        self.socket
            .send(&target, buf)
            .await
            .map_err(|e| MihomoError::Proxy(format!("ss udp send: {}", e)))?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(MihomoError::Io)
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

fn parse_address(metadata: &Metadata) -> Address {
    if !metadata.host.is_empty() {
        Address::DomainNameAddress(metadata.host.clone(), metadata.dst_port)
    } else if let Some(ip) = metadata.dst_ip {
        Address::SocketAddress(SocketAddr::new(ip, metadata.dst_port))
    } else {
        Address::DomainNameAddress(metadata.host.clone(), metadata.dst_port)
    }
}

#[async_trait]
impl ProxyAdapter for ShadowsocksAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Shadowsocks
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        self.support_udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let addr = parse_address(metadata);
        debug!("SS connecting to {} via {}", addr, self.addr_str);
        let stream = ProxyClientStream::connect(self.context.clone(), &self.server_config, addr)
            .await
            .map_err(|e| MihomoError::Proxy(format!("ss connect: {}", e)))?;
        Ok(Box::new(SsConn(stream)))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let socket = ProxySocket::connect(self.context.clone(), &self.server_config)
            .await
            .map_err(|e| MihomoError::Proxy(format!("ss udp connect: {}", e)))?;
        debug!("SS UDP connected via {}", self.addr_str);
        Ok(Box::new(SsPacketConn { socket }))
    }
}
