pub mod routes;
pub mod ui;

use mihomo_config::raw::RawConfig;
use mihomo_config::rule_provider::RuleProvider;
use mihomo_config::NamedListener;
use mihomo_tunnel::Tunnel;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

pub struct ApiServer {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    secret: Option<String>,
    config_path: String,
    raw_config: Arc<RwLock<RawConfig>>,
    rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
    listeners: Vec<NamedListener>,
}

impl ApiServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tunnel: Tunnel,
        listen_addr: SocketAddr,
        secret: Option<String>,
        config_path: String,
        raw_config: Arc<RwLock<RawConfig>>,
        rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
        listeners: Vec<NamedListener>,
    ) -> Self {
        Self {
            tunnel,
            listen_addr,
            secret,
            config_path,
            raw_config,
            rule_providers,
            listeners,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = Arc::new(routes::AppState {
            tunnel: self.tunnel.clone(),
            secret: self.secret.clone(),
            config_path: self.config_path.clone(),
            raw_config: self.raw_config.clone(),
            rule_providers: self.rule_providers.clone(),
            listeners: self.listeners.clone(),
        });

        let app = routes::create_router(state);

        let listener = tokio::net::TcpListener::bind(self.listen_addr).await?;
        info!("REST API listening on {}", self.listen_addr);
        info!("Web UI available at http://{}/ui", self.listen_addr);
        axum::serve(listener, app).await?;
        Ok(())
    }
}
