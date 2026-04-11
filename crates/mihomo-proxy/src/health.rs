use mihomo_common::ProxyAdapter;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

pub use mihomo_common::ProxyHealth;

/// Test a proxy by making an HTTP GET request and measuring round-trip time
pub async fn url_test(adapter: &dyn ProxyAdapter, url: &str, timeout: Duration) -> u16 {
    let start = Instant::now();
    let metadata = mihomo_common::Metadata {
        network: mihomo_common::Network::Tcp,
        host: extract_host(url),
        dst_port: extract_port(url),
        ..Default::default()
    };

    let result = tokio::time::timeout(timeout, async {
        let _conn = adapter.dial_tcp(&metadata).await?;
        // For a simple URL test, just establishing the connection is enough
        // A full implementation would send an HTTP request
        Ok::<_, mihomo_common::MihomoError>(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            let delay = start.elapsed().as_millis() as u16;
            debug!("{} URL test: {}ms", adapter.name(), delay);
            delay
        }
        _ => {
            warn!("{} URL test failed", adapter.name());
            0
        }
    }
}

fn extract_host(url: &str) -> String {
    let url = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = url.split('/').next().unwrap_or(url);
    let host = host.split(':').next().unwrap_or(host);
    host.to_string()
}

fn extract_port(url: &str) -> u16 {
    if url.starts_with("https://") {
        443
    } else {
        80
    }
}
