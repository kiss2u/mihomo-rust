pub mod log_stream;
pub mod routes;
pub mod ui;

use log_stream::LogMessage;
use mihomo_config::raw::RawConfig;
use mihomo_tunnel::Tunnel;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

pub struct ApiServer {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    secret: Option<String>,
    config_path: String,
    raw_config: Arc<RwLock<RawConfig>>,
    log_tx: broadcast::Sender<LogMessage>,
}

impl ApiServer {
    pub fn new(
        tunnel: Tunnel,
        listen_addr: SocketAddr,
        secret: Option<String>,
        config_path: String,
        raw_config: Arc<RwLock<RawConfig>>,
        log_tx: broadcast::Sender<LogMessage>,
    ) -> Self {
        Self {
            tunnel,
            listen_addr,
            secret,
            config_path,
            raw_config,
            log_tx,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = Arc::new(routes::AppState {
            tunnel: self.tunnel.clone(),
            secret: self.secret.clone(),
            config_path: self.config_path.clone(),
            raw_config: self.raw_config.clone(),
            log_tx: self.log_tx.clone(),
        });

        let app = routes::create_router(state);

        let listener = tokio::net::TcpListener::bind(self.listen_addr).await?;
        info!("REST API listening on {}", self.listen_addr);
        info!("Web UI available at http://{}/ui", self.listen_addr);
        axum::serve(listener, app).await?;
        Ok(())
    }
}
