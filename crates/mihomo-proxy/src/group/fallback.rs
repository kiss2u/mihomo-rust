use async_trait::async_trait;
use mihomo_common::{
    AdapterType, DelayHistory, Metadata, MihomoError, Proxy, ProxyAdapter, ProxyConn,
    ProxyPacketConn, Result,
};
use std::sync::Arc;

pub struct FallbackGroup {
    name: String,
    proxies: Vec<Arc<dyn Proxy>>,
}

impl FallbackGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>) -> Self {
        Self {
            name: name.to_string(),
            proxies,
        }
    }

    fn first_alive(&self) -> Option<Arc<dyn Proxy>> {
        self.proxies
            .iter()
            .find(|p| p.alive())
            .cloned()
            .or_else(|| self.proxies.first().cloned())
    }
}

#[async_trait]
impl ProxyAdapter for FallbackGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Fallback
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.first_alive().is_some_and(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let proxy = self
            .first_alive()
            .ok_or_else(|| MihomoError::Proxy("no proxy available".into()))?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let proxy = self
            .first_alive()
            .ok_or_else(|| MihomoError::Proxy("no proxy available".into()))?;
        proxy.dial_udp(metadata).await
    }

    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.first_alive()
    }
}

impl Proxy for FallbackGroup {
    fn alive(&self) -> bool {
        self.first_alive().is_some_and(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.first_alive().is_some_and(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.first_alive().map(|p| p.last_delay()).unwrap_or(0)
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.first_alive()
            .map(|p| p.last_delay_for_url(url))
            .unwrap_or(0)
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.first_alive()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }
}
