//! Built-in `v2ray-plugin` SIP003 client transport.
//!
//! Implements the WebSocket (and optional TLS) transport used by the
//! `v2ray-plugin` SIP003 plugin for Shadowsocks, natively in Rust so users
//! do not need the external `v2ray-plugin` Go binary installed. This
//! matches the behavior of the built-in v2ray-plugin transport in mihomo
//! (Go): `mux` is accepted but not turned into real SMUX — each SS stream
//! maps to one WebSocket connection.
//!
//! Entry points:
//! - [`parse_opts`] converts a SIP003 `k=v;k=v` opts string into a
//!   [`V2rayPluginConfig`].
//! - [`dial`] opens a TCP (optionally TLS) + WebSocket stream to the
//!   server and returns an `AsyncRead + AsyncWrite` that callers layer
//!   Shadowsocks encryption on top of via `ProxyClientStream::from_stream`.

use futures_util::sink::Sink;
use futures_util::stream::Stream;
use mihomo_common::{MihomoError, Result};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, warn};

/// Transport mode. Only WebSocket is supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Websocket,
}

/// Parsed v2ray-plugin client options.
#[derive(Debug, Clone)]
pub struct V2rayPluginConfig {
    pub mode: Mode,
    pub tls: bool,
    /// Host header and TLS SNI. Falls back to the SS server address if
    /// not set in the opts string.
    pub host: String,
    /// WebSocket upgrade path. Defaults to `/`.
    pub path: String,
    pub headers: HashMap<String, String>,
    pub skip_cert_verify: bool,
    /// Parsed, but not acted on (matches Go mihomo's built-in plugin).
    pub mux: bool,
}

impl Default for V2rayPluginConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Websocket,
            tls: false,
            host: String::new(),
            path: "/".to_string(),
            headers: HashMap::new(),
            skip_cert_verify: false,
            mux: false,
        }
    }
}

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Parse a SIP003 opts string (`mode=websocket;tls;host=...;path=/ws;mux=1`).
///
/// - Bare keys (e.g. `tls`) are treated as `key=true`.
/// - Unknown keys are logged at `warn` level and ignored.
/// - Only `mode=websocket` is accepted; other modes return an error.
pub fn parse_opts(s: &str) -> Result<V2rayPluginConfig> {
    let mut cfg = V2rayPluginConfig::default();

    for token in s.split(';').map(str::trim).filter(|t| !t.is_empty()) {
        let (key, value) = match token.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim().to_string()),
            None => (token, "true".to_string()),
        };

        match key {
            "mode" => {
                if value.eq_ignore_ascii_case("websocket") || value.eq_ignore_ascii_case("ws") {
                    cfg.mode = Mode::Websocket;
                } else {
                    return Err(MihomoError::Config(format!(
                        "v2ray-plugin: unsupported mode '{}' (only 'websocket' is supported)",
                        value
                    )));
                }
            }
            "tls" => cfg.tls = parse_bool(&value),
            "host" => cfg.host = value,
            "path" => cfg.path = value,
            "mux" => cfg.mux = parse_bool(&value),
            "skip-cert-verify" => cfg.skip_cert_verify = parse_bool(&value),
            "header" => {
                // Form: header=Key:Value
                if let Some((k, v)) = value.split_once(':') {
                    cfg.headers
                        .insert(k.trim().to_string(), v.trim().to_string());
                } else {
                    warn!("v2ray-plugin: malformed header entry '{}'", value);
                }
            }
            other => {
                warn!("v2ray-plugin: ignoring unknown opt '{}'", other);
            }
        }
    }

    Ok(cfg)
}

// ---------- TLS: insecure verifier (duplicated from `trojan.rs`) ----------

#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_tls_connector(skip_cert_verify: bool) -> TlsConnector {
    let config = if skip_cert_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
            .with_no_client_auth()
    } else {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    TlsConnector::from(Arc::new(config))
}

// ---------- Boxed stream used to unify TCP vs TLS below the WS layer ----

pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> IoStream for T {}

/// `AsyncRead + AsyncWrite` adapter over a `WebSocketStream`.
///
/// Writes turn into a single `Binary` frame per `poll_write` call. Reads
/// drain the bytes of the last received `Binary` frame before polling for
/// the next frame. Ping frames are replied to with a Pong.
pub struct WsStream<S> {
    inner: WebSocketStream<S>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> WsStream<S> {
    fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // Drain any leftover bytes from the previous binary frame.
            if self.read_pos < self.read_buf.len() {
                let remaining = &self.read_buf[self.read_pos..];
                let n = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..n]);
                self.read_pos += n;
                if self.read_pos == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // Poll the next WebSocket message.
            let next = match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(x) => x,
                Poll::Pending => return Poll::Pending,
            };
            match next {
                None => return Poll::Ready(Ok(())), // EOF
                Some(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Some(Ok(Message::Binary(data))) => {
                    self.read_buf = data;
                    self.read_pos = 0;
                    // loop to copy into buf
                }
                Some(Ok(Message::Ping(payload))) => {
                    // Best-effort pong; if the sink isn't ready, just drop it.
                    let _ = Pin::new(&mut self.inner).start_send(Message::Pong(payload));
                    // loop to poll next message
                }
                Some(Ok(Message::Pong(_))) => {
                    // ignore, poll again
                }
                Some(Ok(Message::Close(_))) => {
                    return Poll::Ready(Ok(())); // EOF
                }
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "v2ray-plugin: unexpected text frame",
                    )));
                }
                Some(Ok(Message::Frame(_))) => {
                    // Raw frames should not be surfaced by tokio-tungstenite
                    // on the client read path; treat defensively as noise.
                }
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Wait until the sink is ready, then send one binary frame.
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::other(e)));
            }
            Poll::Pending => return Poll::Pending,
        }

        if let Err(e) = Pin::new(&mut self.inner).start_send(Message::Binary(buf.to_vec())) {
            return Poll::Ready(Err(io::Error::other(e)));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}

/// Dial a TCP (+ optional TLS) + WebSocket connection to `server_host:server_port`
/// and return the framed stream ready to be wrapped by the SS layer.
pub async fn dial(
    cfg: &V2rayPluginConfig,
    server_host: &str,
    server_port: u16,
) -> Result<WsStream<Box<dyn IoStream>>> {
    let host_header = if cfg.host.is_empty() {
        server_host.to_string()
    } else {
        cfg.host.clone()
    };

    debug!(
        "v2ray-plugin: dialing {}:{} tls={} host={} path={} mux={}",
        server_host, server_port, cfg.tls, host_header, cfg.path, cfg.mux
    );

    // 1) Raw TCP.
    let tcp = TcpStream::connect((server_host, server_port))
        .await
        .map_err(MihomoError::Io)?;

    // 2) Optional TLS handshake.
    let io: Box<dyn IoStream> = if cfg.tls {
        let connector = build_tls_connector(cfg.skip_cert_verify);
        let server_name = ServerName::try_from(host_header.clone())
            .map_err(|e| MihomoError::Proxy(format!("v2ray-plugin tls sni: {}", e)))?;
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| MihomoError::Proxy(format!("v2ray-plugin tls: {}", e)))?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp)
    };

    // 3) WebSocket upgrade over the established stream.
    let scheme = if cfg.tls { "wss" } else { "ws" };
    let uri = format!("{}://{}{}", scheme, host_header, cfg.path);
    let mut req_builder = http::Request::builder()
        .method("GET")
        .uri(&uri)
        .header("Host", &host_header)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        );
    for (k, v) in &cfg.headers {
        req_builder = req_builder.header(k.as_str(), v.as_str());
    }
    let request = req_builder
        .body(())
        .map_err(|e| MihomoError::Proxy(format!("v2ray-plugin ws request: {}", e)))?;

    let (ws_stream, _response) = tokio_tungstenite::client_async(request, io)
        .await
        .map_err(|e| MihomoError::Proxy(format!("v2ray-plugin ws handshake: {}", e)))?;

    Ok(WsStream::new(ws_stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_websocket_mux() {
        let cfg = parse_opts("mode=websocket;mux=1;host=example.com;path=/ws").expect("parse ok");
        assert_eq!(cfg.mode, Mode::Websocket);
        assert!(!cfg.tls);
        assert!(cfg.mux);
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.path, "/ws");
        assert!(!cfg.skip_cert_verify);
    }

    #[test]
    fn parse_tls_websocket_mux_skip_verify() {
        let cfg =
            parse_opts("mode=websocket;tls;mux=1;host=example.com;path=/ws;skip-cert-verify=true")
                .expect("parse ok");
        assert!(cfg.tls);
        assert!(cfg.mux);
        assert!(cfg.skip_cert_verify);
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.path, "/ws");
    }

    #[test]
    fn parse_defaults_on_empty() {
        let cfg = parse_opts("").expect("parse ok");
        assert_eq!(cfg.mode, Mode::Websocket);
        assert!(!cfg.tls);
        assert_eq!(cfg.path, "/");
        assert!(!cfg.mux);
        assert!(cfg.host.is_empty());
    }

    #[test]
    fn parse_bare_tls_and_mux() {
        let cfg = parse_opts("tls;mux").expect("parse ok");
        assert!(cfg.tls);
        assert!(cfg.mux);
    }

    #[test]
    fn parse_unknown_key_ignored() {
        let cfg = parse_opts("mode=websocket;foo=bar;path=/ws").expect("parse ok");
        assert_eq!(cfg.path, "/ws");
    }

    #[test]
    fn parse_bad_mode_errors() {
        assert!(parse_opts("mode=quic").is_err());
    }

    #[test]
    fn parse_header_opt() {
        let cfg = parse_opts("mode=websocket;header=X-Foo:bar;host=example.com").expect("parse ok");
        assert_eq!(cfg.headers.get("X-Foo").map(String::as_str), Some("bar"));
    }
}
