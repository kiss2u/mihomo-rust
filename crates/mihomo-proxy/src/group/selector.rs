use async_trait::async_trait;
use mihomo_common::{
    AdapterType, DelayHistory, Metadata, MihomoError, Proxy, ProxyAdapter, ProxyConn,
    ProxyPacketConn, Result,
};
use parking_lot::RwLock;
use std::sync::Arc;

pub struct SelectorGroup {
    name: String,
    proxies: Vec<Arc<dyn Proxy>>,
    selected: RwLock<usize>,
}

impl SelectorGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>) -> Self {
        Self {
            name: name.to_string(),
            proxies,
            selected: RwLock::new(0),
        }
    }

    pub fn select(&self, name: &str) -> bool {
        if let Some(idx) = self.proxies.iter().position(|p| p.name() == name) {
            *self.selected.write() = idx;
            true
        } else {
            false
        }
    }

    pub fn selected_proxy(&self) -> Option<Arc<dyn Proxy>> {
        let idx = *self.selected.read();
        self.proxies.get(idx).cloned()
    }

    pub fn proxy_names(&self) -> Vec<String> {
        self.proxies.iter().map(|p| p.name().to_string()).collect()
    }
}

#[async_trait]
impl ProxyAdapter for SelectorGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Selector
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.selected_proxy().is_some_and(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let proxy = self
            .selected_proxy()
            .ok_or_else(|| MihomoError::Proxy("no proxy selected".into()))?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let proxy = self
            .selected_proxy()
            .ok_or_else(|| MihomoError::Proxy("no proxy selected".into()))?;
        proxy.dial_udp(metadata).await
    }

    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.selected_proxy()
    }
}

impl Proxy for SelectorGroup {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn alive(&self) -> bool {
        self.selected_proxy().is_some_and(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.selected_proxy().is_some_and(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.selected_proxy().map(|p| p.last_delay()).unwrap_or(0)
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.selected_proxy()
            .map(|p| p.last_delay_for_url(url))
            .unwrap_or(0)
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.selected_proxy()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }
}
