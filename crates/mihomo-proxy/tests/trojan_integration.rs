//! Integration tests for the Trojan adapter.
//!
//! Uses an embedded mock Trojan server with a self-signed certificate.
//! No external binaries required.

use mihomo_common::{Metadata, Network, ProxyAdapter};
use mihomo_proxy::TrojanAdapter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const TROJAN_PASSWORD: &str = "test-trojan-password";
const TIMEOUT: Duration = Duration::from_secs(10);

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a self-signed cert for "localhost" using rcgen.
fn generate_self_signed_cert() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
    );
    (cert_der, key_der)
}

/// Start a TCP echo server.
async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, handle)
}

/// Compute Trojan hex password (SHA-224).
fn trojan_hex_password(password: &str) -> String {
    use sha2::{Digest, Sha224};
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

/// Read a SOCKS5-style address from a reader.
async fn read_socks5_addr<R: AsyncReadExt + Unpin>(reader: &mut R) -> SocketAddr {
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await.unwrap();
    match atyp[0] {
        0x01 => {
            let mut ip = [0u8; 4];
            reader.read_exact(&mut ip).await.unwrap();
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.unwrap();
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(port))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            reader.read_exact(&mut ip).await.unwrap();
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.unwrap();
            SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                u16::from_be_bytes(port),
            )
        }
        0x03 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await.unwrap();
            let mut domain = vec![0u8; len[0] as usize];
            reader.read_exact(&mut domain).await.unwrap();
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.unwrap();
            let domain_str = String::from_utf8_lossy(&domain);
            let ip = if domain_str == "localhost" {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                panic!("mock server cannot resolve domain: {}", domain_str);
            };
            SocketAddr::new(ip, u16::from_be_bytes(port))
        }
        _ => panic!("unknown ATYP: {}", atyp[0]),
    }
}

/// Start a mock Trojan server with self-signed TLS.
///
/// Handles CMD=0x01 (TCP CONNECT) by relaying to the target address.
async fn start_mock_trojan_server(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_hex = trojan_hex_password(TROJAN_PASSWORD);

    let handle = tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let expected_hex = expected_hex.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("mock trojan: TLS accept error: {}", e);
                        return;
                    }
                };

                // Read Trojan header: 56-byte hex password
                let mut password_buf = [0u8; 56];
                tls.read_exact(&mut password_buf).await.unwrap();
                let received_hex = String::from_utf8_lossy(&password_buf);
                assert_eq!(received_hex.as_ref(), expected_hex.as_str());

                // CRLF
                let mut crlf = [0u8; 2];
                tls.read_exact(&mut crlf).await.unwrap();
                assert_eq!(&crlf, b"\r\n");

                // CMD
                let mut cmd = [0u8; 1];
                tls.read_exact(&mut cmd).await.unwrap();

                // Target address
                let target_addr = read_socks5_addr(&mut tls).await;

                // Trailing CRLF
                let mut crlf2 = [0u8; 2];
                tls.read_exact(&mut crlf2).await.unwrap();
                assert_eq!(&crlf2, b"\r\n");

                match cmd[0] {
                    0x01 => {
                        // TCP relay
                        let mut target = TcpStream::connect(target_addr).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut tls, &mut target).await;
                    }
                    other => {
                        eprintln!("mock trojan: unsupported cmd: {}", other);
                    }
                }
            });
        }
    });

    (addr, handle)
}

#[tokio::test]
async fn test_trojan_tcp_relay() {
    install_crypto_provider();

    // Generate self-signed cert
    let (cert_der, key_der) = generate_self_signed_cert();

    // Start echo server and mock trojan server
    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let (trojan_addr, _trojan_handle) = start_mock_trojan_server(cert_der, key_der).await;

    // Create adapter with skip_verify=true
    let adapter = TrojanAdapter::new(
        "test-trojan",
        "127.0.0.1",
        trojan_addr.port(),
        TROJAN_PASSWORD,
        "localhost", // SNI
        true,        // skip_verify
        false,       // udp
    );

    // Build metadata pointing to the echo server
    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // Dial TCP through the Trojan proxy
    let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
    let mut conn = result
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    // Write and read back
    let payload = b"hello trojan tcp";
    conn.write_all(payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");

    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(&buf, payload, "TCP echo mismatch");

    // Second round
    let payload2 = b"second trojan message";
    conn.write_all(payload2).await.expect("TCP write2 failed");
    conn.flush().await.expect("TCP flush2 failed");

    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("TCP read_exact2 failed");
    assert_eq!(&buf2, payload2, "TCP echo mismatch round 2");
}

#[tokio::test]
async fn test_trojan_tcp_large_payload() {
    install_crypto_provider();

    let (cert_der, key_der) = generate_self_signed_cert();
    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let (trojan_addr, _trojan_handle) = start_mock_trojan_server(cert_der, key_der).await;

    let adapter = TrojanAdapter::new(
        "test-trojan",
        "127.0.0.1",
        trojan_addr.port(),
        TROJAN_PASSWORD,
        "localhost",
        true,
        false,
    );

    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
    let mut conn = result
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    // Send a larger payload (64KB)
    let payload: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    conn.write_all(&payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");

    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(buf, payload, "large payload echo mismatch");
}
