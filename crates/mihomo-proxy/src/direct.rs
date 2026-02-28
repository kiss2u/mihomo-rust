use async_trait::async_trait;
use mihomo_common::{
    AdapterType, Metadata, MihomoError, ProxyAdapter, ProxyConn, ProxyPacketConn, Result,
};
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};

pub struct DirectAdapter;

impl DirectAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DirectAdapter {
    fn default() -> Self {
        Self::new()
    }
}

// Wrapper for TcpStream that implements ProxyConn
struct DirectConn(TcpStream);

impl tokio::io::AsyncRead for DirectConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for DirectConn {
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

impl Unpin for DirectConn {}
impl ProxyConn for DirectConn {}

// UDP wrapper
struct DirectPacketConn(UdpSocket);

#[async_trait]
impl ProxyPacketConn for DirectPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await.map_err(MihomoError::Io)
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        self.0.send_to(buf, addr).await.map_err(MihomoError::Io)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr().map_err(MihomoError::Io)
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for DirectAdapter {
    fn name(&self) -> &str {
        "DIRECT"
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let addr = metadata.remote_address();
        let stream = TcpStream::connect(&addr).await.map_err(MihomoError::Io)?;
        Ok(Box::new(DirectConn(stream)))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(MihomoError::Io)?;
        Ok(Box::new(DirectPacketConn(socket)))
    }
}
