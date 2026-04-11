use async_trait::async_trait;
use mihomo_common::{
    AdapterType, DelayHistory, Metadata, MihomoError, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use parking_lot::RwLock;
use std::sync::Arc;

pub struct UrlTestGroup {
    name: String,
    proxies: Vec<Arc<dyn Proxy>>,
    tolerance: u16,
    fastest: RwLock<usize>,
    health: ProxyHealth,
}

impl UrlTestGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>, tolerance: u16) -> Self {
        Self {
            name: name.to_string(),
            proxies,
            tolerance,
            fastest: RwLock::new(0),
            health: ProxyHealth::new(),
        }
    }

    pub fn update_fastest(&self) {
        let mut best_idx = 0;
        let mut best_delay = u16::MAX;
        for (idx, proxy) in self.proxies.iter().enumerate() {
            if proxy.alive() {
                let delay = proxy.last_delay();
                if delay > 0 && delay < best_delay {
                    best_delay = delay;
                    best_idx = idx;
                }
            }
        }
        // Only switch if the new fastest is better by tolerance
        let current = *self.fastest.read();
        let current_delay = self
            .proxies
            .get(current)
            .map(|p| p.last_delay())
            .unwrap_or(u16::MAX);
        if best_delay + self.tolerance < current_delay
            || !self.proxies.get(current).is_some_and(|p| p.alive())
        {
            *self.fastest.write() = best_idx;
        }
    }

    fn fastest_proxy(&self) -> Option<Arc<dyn Proxy>> {
        let idx = *self.fastest.read();
        self.proxies.get(idx).cloned()
    }
}

#[async_trait]
impl ProxyAdapter for UrlTestGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::UrlTest
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.fastest_proxy().is_some_and(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.update_fastest();
        let proxy = self
            .fastest_proxy()
            .ok_or_else(|| MihomoError::Proxy("no proxy available".into()))?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.update_fastest();
        let proxy = self
            .fastest_proxy()
            .ok_or_else(|| MihomoError::Proxy("no proxy available".into()))?;
        proxy.dial_udp(metadata).await
    }

    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.fastest_proxy()
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for UrlTestGroup {
    fn alive(&self) -> bool {
        self.fastest_proxy().is_some_and(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.fastest_proxy().is_some_and(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.fastest_proxy().map(|p| p.last_delay()).unwrap_or(0)
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.fastest_proxy()
            .map(|p| p.last_delay_for_url(url))
            .unwrap_or(0)
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.fastest_proxy()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        Some(self.proxies.iter().map(|p| p.name().to_string()).collect())
    }

    fn current(&self) -> Option<String> {
        self.fastest_proxy().map(|p| p.name().to_string())
    }
}
