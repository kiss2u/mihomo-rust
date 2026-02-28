use mihomo_common::ProxyConn;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps a `netstack_smoltcp::TcpStream` to implement the `ProxyConn` trait.
/// The original destination address is preserved for routing decisions.
pub struct TunTcpConn {
    inner: netstack_smoltcp::TcpStream,
    dst_addr: SocketAddr,
}

impl TunTcpConn {
    pub fn new(inner: netstack_smoltcp::TcpStream, dst_addr: SocketAddr) -> Self {
        Self { inner, dst_addr }
    }
}

impl AsyncRead for TunTcpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunTcpConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl ProxyConn for TunTcpConn {
    fn remote_destination(&self) -> String {
        self.dst_addr.to_string()
    }
}
