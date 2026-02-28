use async_trait::async_trait;
use mihomo_common::{
    AdapterType, DelayHistory, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyPacketConn, Result,
};
use mihomo_proxy::{FallbackGroup, SelectorGroup, ShadowsocksAdapter, TrojanAdapter, UrlTestGroup};
use std::collections::HashMap;
use std::sync::Arc;

/// Wraps a ProxyAdapter to implement the full Proxy trait
pub struct WrappedProxy {
    adapter: Box<dyn ProxyAdapter>,
}

impl WrappedProxy {
    pub fn new(adapter: Box<dyn ProxyAdapter>) -> Self {
        Self { adapter }
    }
}

#[async_trait]
impl ProxyAdapter for WrappedProxy {
    fn name(&self) -> &str {
        self.adapter.name()
    }
    fn adapter_type(&self) -> AdapterType {
        self.adapter.adapter_type()
    }
    fn addr(&self) -> &str {
        self.adapter.addr()
    }
    fn support_udp(&self) -> bool {
        self.adapter.support_udp()
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.adapter.dial_tcp(metadata).await
    }
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.adapter.dial_udp(metadata).await
    }
}

impl Proxy for WrappedProxy {
    fn alive(&self) -> bool {
        true
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        true
    }
    fn last_delay(&self) -> u16 {
        0
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        0
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        Vec::new()
    }
}

pub fn parse_proxy(
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let name = config
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("missing proxy name")?;
    let proxy_type = config
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or("missing proxy type")?;

    match proxy_type {
        "ss" => {
            let server = config
                .get("server")
                .and_then(|v| v.as_str())
                .ok_or("missing server")?;
            let port = config
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or("missing port")? as u16;
            let password = config
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or("missing password")?;
            let cipher = config
                .get("cipher")
                .and_then(|v| v.as_str())
                .ok_or("missing cipher")?;
            let udp = config.get("udp").and_then(|v| v.as_bool()).unwrap_or(false);

            let adapter = ShadowsocksAdapter::new(name, server, port, password, cipher, udp)
                .map_err(|e| format!("ss: {}", e))?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        "trojan" => {
            let server = config
                .get("server")
                .and_then(|v| v.as_str())
                .ok_or("missing server")?;
            let port = config
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or("missing port")? as u16;
            let password = config
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or("missing password")?;
            let sni = config.get("sni").and_then(|v| v.as_str()).unwrap_or("");
            let skip_verify = config
                .get("skip-cert-verify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let udp = config.get("udp").and_then(|v| v.as_bool()).unwrap_or(false);

            let adapter = TrojanAdapter::new(name, server, port, password, sni, skip_verify, udp);
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        _ => Err(format!("unsupported proxy type: {}", proxy_type)),
    }
}

pub fn parse_proxy_group(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<String, Arc<dyn Proxy>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let proxy_names = config.proxies.as_deref().unwrap_or(&[]);
    let mut proxies: Vec<Arc<dyn Proxy>> = Vec::new();
    for name in proxy_names {
        if let Some(proxy) = existing_proxies.get(name.as_str()) {
            proxies.push(proxy.clone());
        } else {
            tracing::warn!("Proxy '{}' not found for group '{}'", name, config.name);
        }
    }

    if proxies.is_empty() {
        return Err(format!("group '{}' has no valid proxies", config.name));
    }

    match config.group_type.as_str() {
        "select" => Ok(Arc::new(SelectorGroup::new(&config.name, proxies))),
        "url-test" => {
            let tolerance = config.tolerance.unwrap_or(150);
            Ok(Arc::new(UrlTestGroup::new(
                &config.name,
                proxies,
                tolerance,
            )))
        }
        "fallback" => Ok(Arc::new(FallbackGroup::new(&config.name, proxies))),
        _ => Err(format!("unsupported group type: {}", config.group_type)),
    }
}
