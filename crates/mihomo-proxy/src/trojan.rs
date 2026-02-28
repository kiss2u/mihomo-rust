use async_trait::async_trait;
use mihomo_common::{
    AdapterType, Metadata, MihomoError, ProxyAdapter, ProxyConn, ProxyPacketConn, Result,
};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha224};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

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

#[allow(dead_code)]
pub struct TrojanAdapter {
    name: String,
    server: String,
    port: u16,
    hex_password: String,
    sni: String,
    skip_verify: bool,
    addr_str: String,
    support_udp: bool,
}

impl TrojanAdapter {
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        sni: &str,
        skip_verify: bool,
        udp: bool,
    ) -> Self {
        // SHA-224 hash of password, hex encoded = 56 chars
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let hex_password = hex::encode(hash);

        Self {
            name: name.to_string(),
            server: server.to_string(),
            port,
            hex_password,
            sni: if sni.is_empty() {
                server.to_string()
            } else {
                sni.to_string()
            },
            skip_verify,
            addr_str: format!("{}:{}", server, port),
            support_udp: udp,
        }
    }

    fn build_tls_connector(&self) -> Result<TlsConnector> {
        let config = if self.skip_verify {
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

        Ok(TlsConnector::from(Arc::new(config)))
    }

    fn build_header(&self, metadata: &Metadata, cmd: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        // hex password + CRLF
        buf.extend_from_slice(self.hex_password.as_bytes());
        buf.extend_from_slice(b"\r\n");
        // command byte
        buf.push(cmd);
        // SOCKS5 address format
        if !metadata.host.is_empty() {
            // Domain
            buf.push(0x03); // ATYP domain
            let host_bytes = metadata.host.as_bytes();
            buf.push(host_bytes.len() as u8);
            buf.extend_from_slice(host_bytes);
        } else if let Some(ip) = metadata.dst_ip {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    buf.push(0x01); // ATYP IPv4
                    buf.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    buf.push(0x04); // ATYP IPv6
                    buf.extend_from_slice(&v6.octets());
                }
            }
        }
        // Port (big-endian)
        buf.extend_from_slice(&metadata.dst_port.to_be_bytes());
        // CRLF
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

// Wrapper for TLS stream
struct TrojanConn<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync>(S);

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> tokio::io::AsyncRead
    for TrojanConn<S>
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
    for TrojanConn<S>
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

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> Unpin
    for TrojanConn<S>
{
}
impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static> ProxyConn
    for TrojanConn<S>
{
}

#[async_trait]
impl ProxyAdapter for TrojanAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Trojan
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        self.support_udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        debug!(
            "Trojan connecting to {} via {}",
            metadata.remote_address(),
            self.addr_str
        );

        // TCP connect
        let tcp = TcpStream::connect(&self.addr_str)
            .await
            .map_err(MihomoError::Io)?;

        // TLS handshake
        let connector = self.build_tls_connector()?;
        let server_name = ServerName::try_from(self.sni.clone())
            .map_err(|e| MihomoError::Proxy(format!("invalid SNI: {}", e)))?;
        let mut tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| MihomoError::Proxy(format!("TLS connect: {}", e)))?;

        // Send Trojan header (CMD_CONNECT = 0x01)
        let header = self.build_header(metadata, 0x01);
        tls_stream
            .write_all(&header)
            .await
            .map_err(MihomoError::Io)?;

        Ok(Box::new(TrojanConn(tls_stream)))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(MihomoError::NotSupported(
            "Trojan UDP not yet implemented".into(),
        ))
    }
}
