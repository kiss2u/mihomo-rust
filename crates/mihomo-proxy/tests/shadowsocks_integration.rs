//! Integration tests for the Shadowsocks adapter.
//!
//! Requires `ssserver` (from shadowsocks-rust) to be installed and in PATH.
//! Tests are skipped automatically if `ssserver` is not available.

use mihomo_common::{Metadata, Network, ProxyAdapter};
use mihomo_proxy::ShadowsocksAdapter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout, Duration};

const SS_PASSWORD: &str = "test-password-1234";
const SS_CIPHER: &str = "aes-256-gcm";
const TIMEOUT: Duration = Duration::from_secs(10);

fn ssserver_available() -> bool {
    std::process::Command::new("ssserver")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Start a TCP echo server that reads data and writes it back.
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

/// Start a UDP echo server that receives datagrams and sends them back.
async fn start_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => break,
            };
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    (addr, handle)
}

/// Start ssserver with the given port and target echo servers configured.
async fn start_ssserver(ss_port: u16) -> Child {
    let child = Command::new("ssserver")
        .args([
            "-s",
            &format!("127.0.0.1:{}", ss_port),
            "-k",
            SS_PASSWORD,
            "-m",
            SS_CIPHER,
            "-U", // enable UDP relay
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start ssserver");

    // Wait for ssserver to be ready by attempting TCP connections
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ss_port))
            .await
            .is_ok()
        {
            return child;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("ssserver did not become ready within 5 seconds");
}

/// Find an available port by binding to port 0.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test]
async fn test_ss_tcp_relay() {
    if !ssserver_available() {
        eprintln!("SKIP: ssserver not found in PATH");
        return;
    }

    // Start echo server and ssserver
    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver(ss_port).await;

    // Create adapter
    let adapter = ShadowsocksAdapter::new(
        "test-ss",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
    )
    .unwrap();

    // Build metadata pointing to the echo server
    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // Dial TCP through the SS proxy
    let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
    let mut conn = result
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    // Write and read back
    let payload = b"hello shadowsocks tcp";
    conn.write_all(payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");

    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(&buf, payload, "TCP echo mismatch");

    // Second round
    let payload2 = b"second message";
    conn.write_all(payload2).await.expect("TCP write2 failed");
    conn.flush().await.expect("TCP flush2 failed");

    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("TCP read_exact2 failed");
    assert_eq!(&buf2, payload2, "TCP echo mismatch round 2");
}

#[tokio::test]
async fn test_ss_udp_relay() {
    if !ssserver_available() {
        eprintln!("SKIP: ssserver not found in PATH");
        return;
    }

    // Start echo server and ssserver
    let (echo_addr, _echo_handle) = start_udp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver(ss_port).await;

    // Create adapter with UDP enabled
    let adapter = ShadowsocksAdapter::new(
        "test-ss",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        true,
    )
    .unwrap();

    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // Dial UDP through the SS proxy
    let result = timeout(TIMEOUT, adapter.dial_udp(&metadata)).await;
    let conn = result
        .expect("UDP dial timed out")
        .expect("UDP dial failed");

    // Write a packet and read it back
    let payload = b"hello shadowsocks udp";
    let written = conn
        .write_packet(payload, &echo_addr)
        .await
        .expect("UDP write_packet failed");
    assert_eq!(written, payload.len());

    let mut buf = vec![0u8; 65536];
    let read_result = timeout(TIMEOUT, conn.read_packet(&mut buf)).await;
    let (n, from_addr) = read_result
        .expect("UDP read timed out")
        .expect("UDP read_packet failed");
    assert_eq!(&buf[..n], payload, "UDP echo mismatch");
    assert_eq!(from_addr, echo_addr, "UDP source address mismatch");

    // Second round
    let payload2 = b"udp round two";
    conn.write_packet(payload2, &echo_addr)
        .await
        .expect("UDP write2 failed");

    let read_result2 = timeout(TIMEOUT, conn.read_packet(&mut buf)).await;
    let (n2, _) = read_result2
        .expect("UDP read2 timed out")
        .expect("UDP read_packet2 failed");
    assert_eq!(&buf[..n2], payload2, "UDP echo mismatch round 2");
}
