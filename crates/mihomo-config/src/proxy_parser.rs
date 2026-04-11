use async_trait::async_trait;
use mihomo_common::{
    AdapterType, DelayHistory, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
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

    fn health(&self) -> &ProxyHealth {
        self.adapter.health()
    }
}

impl Proxy for WrappedProxy {
    fn alive(&self) -> bool {
        self.adapter.health().alive()
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        self.adapter.health().alive()
    }
    fn last_delay(&self) -> u16 {
        self.adapter.health().last_delay()
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        self.adapter.health().last_delay()
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        self.adapter.health().delay_history()
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
            let plugin = config.get("plugin").and_then(|v| v.as_str());
            let plugin_opts_str = config.get("plugin-opts").and_then(serialize_plugin_opts);

            let adapter = ShadowsocksAdapter::new(
                name,
                server,
                port,
                password,
                cipher,
                udp,
                plugin,
                plugin_opts_str.as_deref(),
            )
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

/// Convert a YAML `plugin-opts` value to the SIP003 semicolon-separated format.
/// Accepts either a string (passed through) or a YAML map (serialized as `key=value;...`).
fn serialize_plugin_opts(opts: &serde_yaml::Value) -> Option<String> {
    match opts {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Mapping(map) => {
            let parts: Vec<String> = map
                .iter()
                .filter_map(|(k, v)| {
                    let key = k.as_str()?;
                    let val = match v {
                        serde_yaml::Value::String(s) => s.clone(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        serde_yaml::Value::Number(n) => n.to_string(),
                        _ => return None,
                    };
                    Some(format!("{}={}", key, val))
                })
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(";"))
            }
        }
        _ => None,
    }
}

pub fn parse_proxy_group(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<String, Arc<dyn Proxy>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(config, existing_proxies, true)
}

/// Lenient variant: unknown members are warned and skipped rather than
/// erroring out. Used by the multi-pass group loop on its final (stall) pass
/// so groups that reference a truly-missing proxy still build with whatever
/// members *did* resolve — matching upstream mihomo's warn-not-fail contract.
pub fn parse_proxy_group_lenient(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<String, Arc<dyn Proxy>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(config, existing_proxies, false)
}

fn parse_proxy_group_inner(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<String, Arc<dyn Proxy>>,
    strict: bool,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let proxy_names = config.proxies.as_deref().unwrap_or(&[]);
    let mut proxies: Vec<Arc<dyn Proxy>> = Vec::with_capacity(proxy_names.len());
    for name in proxy_names {
        match existing_proxies.get(name.as_str()) {
            Some(proxy) => proxies.push(proxy.clone()),
            None if strict => {
                return Err(format!(
                    "group '{}' references unknown proxy '{}'",
                    config.name, name
                ));
            }
            None => {
                tracing::warn!(
                    "Proxy '{}' not found for group '{}', skipping",
                    name,
                    config.name
                );
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_plugin_opts_map() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
mode: websocket
host: example.com
tls: true
"#,
        )
        .unwrap();
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert!(result.contains("mode=websocket"));
        assert!(result.contains("host=example.com"));
        assert!(result.contains("tls=true"));
        // Verify semicolon-separated format
        assert_eq!(result.matches(';').count(), 2);
    }

    #[test]
    fn test_serialize_plugin_opts_string_passthrough() {
        let yaml = serde_yaml::Value::String("obfs=http;obfs-host=example.com".to_string());
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert_eq!(result, "obfs=http;obfs-host=example.com");
    }

    #[test]
    fn test_serialize_plugin_opts_empty_map() {
        let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        assert!(serialize_plugin_opts(&yaml).is_none());
    }

    #[test]
    fn test_serialize_plugin_opts_null() {
        let yaml = serde_yaml::Value::Null;
        assert!(serialize_plugin_opts(&yaml).is_none());
    }

    #[test]
    fn test_serialize_plugin_opts_number_value() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("port: 8080").unwrap();
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert_eq!(result, "port=8080");
    }
}
