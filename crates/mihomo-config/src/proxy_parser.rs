use async_trait::async_trait;
use mihomo_common::{
    AdapterType, DelayHistory, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use mihomo_proxy::{
    FallbackGroup, SelectorGroup, ShadowsocksAdapter, TransportChain, TrojanAdapter, UrlTestGroup,
};
#[cfg(feature = "vless")]
use mihomo_proxy::{VlessAdapter, VlessFlow};
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
        #[cfg(feature = "vless")]
        "vless" => {
            let adapter = parse_vless(name, config)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        _ => Err(format!("unsupported proxy type: {}", proxy_type)),
    }
}

/// Parse a `type: vless` proxy config block into a `VlessAdapter`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `flow: xtls-rprx-direct` / `xtls-rprx-splice` — deprecated and insecure
/// - Unknown `flow` values — may skip expected security processing
/// - `reality-opts` present — Reality transport not implemented
/// - `flow: xtls-rprx-vision` + no TLS-enforcing transport
/// - `encryption: <non-empty non-"none">` — unsupported cipher
/// - `uuid` invalid
/// - `server` domain > 255 bytes
/// - `vless-vision` feature absent + `flow: xtls-rprx-vision`
///
/// # Warn-once (Class B per ADR-0002)
///
/// - `tls: false` with plain VLESS — plaintext, but correct destination
/// - `mux: { enabled: true }` — Mux.Cool not implemented; warn and ignore
/// - `flow: xtls-rprx-vision` + `udp: true` — Vision is TCP-only; UDP uses plain VLESS
#[cfg(feature = "vless")]
fn parse_vless(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<VlessAdapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("vless: missing server")?;
    let port = config
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or("vless: missing port")? as u16;
    let uuid_str = config
        .get("uuid")
        .and_then(|v| v.as_str())
        .ok_or("vless: missing uuid")?;
    let uuid_bytes = parse_uuid(uuid_str).map_err(|e| format!("vless: {}", e))?;

    // Validate server domain length (Class A — wrong destination with no diagnostic).
    if server.len() > 255 {
        return Err(format!(
            "vless: server '{}…' domain is {} bytes; max 255 \
             (would be silently truncated — wrong destination, no diagnostic)",
            &server[..server.len().min(20)],
            server.len()
        ));
    }

    let udp = config.get("udp").and_then(|v| v.as_bool()).unwrap_or(false);
    let tls = config.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let servername = config
        .get("servername")
        .and_then(|v| v.as_str())
        .unwrap_or(server)
        .to_string();
    let alpn: Vec<String> = config
        .get("alpn")
        .and_then(|v| v.as_sequence())
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    let network = config
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");
    let client_fingerprint = config.get("client-fingerprint").and_then(|v| v.as_str());

    // ── Hard error: reality-opts present (Class A) ────────────────────────
    if config.contains_key("reality-opts") {
        return Err("vless: reality-opts is not yet implemented; \
             Reality transport is tracked for post-M1. \
             Remove reality-opts or wait for the Reality spec to land."
            .into());
    }

    // ── Hard error: encryption != "" / "none" ─────────────────────────────
    let encryption = config
        .get("encryption")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    if !encryption.is_empty() && encryption != "none" {
        return Err(format!(
            "vless: encryption '{}' is not supported; VLESS uses no body cipher \
             (set `encryption: none` or omit the field)",
            encryption
        ));
    }

    // ── client-fingerprint: warn + ignore (no uTLS yet) ───────────────────
    if let Some(fp) = client_fingerprint {
        tracing::warn!(
            proxy = %name,
            fingerprint = %fp,
            "vless: client-fingerprint is accepted but not yet acted on \
             (uTLS fingerprinting is tracked as a post-M1 feature)"
        );
    }

    // ── Flow parsing ──────────────────────────────────────────────────────
    let flow_str = config.get("flow").and_then(|v| v.as_str()).unwrap_or("");

    let flow: Option<VlessFlow> = match flow_str {
        "" => None,

        "xtls-rprx-vision" => {
            // Hard error if vless-vision feature is not compiled in (Class A).
            #[cfg(not(feature = "vless-vision"))]
            {
                return Err(
                    "vless: flow xtls-rprx-vision requires the `vless-vision` Cargo feature; \
                     rebuild with --features vless-vision"
                        .into(),
                );
            }
            #[cfg(feature = "vless-vision")]
            Some(VlessFlow::XtlsRprxVision)
        }

        "xtls-rprx-direct" | "xtls-rprx-splice" => {
            // Class A: upstream accepts these as deprecated aliases; we reject them.
            // upstream: adapter/outbound/vless.go — accepts deprecated flows.
            // NOT warn-ignore — security regression vs Vision if user assumes Vision protection.
            return Err(format!(
                "vless: flow '{}' is deprecated and insecure; \
                 use `flow: xtls-rprx-vision` instead. \
                 (upstream: adapter/outbound/vless.go accepts this; we reject — Class A ADR-0002)",
                flow_str
            ));
        }

        other => {
            // Class A: unknown flow may skip expected security processing.
            // upstream: adapter/outbound/vless.go ignores unknown flows.
            // NOT warn-ignore — unknown flow value may silently degrade security.
            return Err(format!(
                "vless: unknown flow '{}'; valid values: '' or 'xtls-rprx-vision'. \
                 (upstream: ignores unknown flows; we reject — Class A ADR-0002)",
                other
            ));
        }
    };

    // ── Gating: Vision requires TLS (or a TLS-enforcing transport) (Class A) ─
    if flow == Some(VlessFlow::XtlsRprxVision) {
        let tls_transport = network == "grpc" || network == "h2";
        if !tls && !tls_transport {
            return Err(
                "vless: flow xtls-rprx-vision requires an encrypting transport; \
                 set `tls: true` or use a TLS-enforcing network (grpc, h2). \
                 Without outer TLS, Vision splice is a no-op and the user has no protection."
                    .into(),
            );
        }
    }

    // ── Warn: tls: false with plain VLESS (Class B) ───────────────────────
    if !tls && flow.is_none() && network != "grpc" && network != "h2" {
        tracing::warn!(
            proxy = %name,
            "vless: tls is false and no TLS-enforcing transport is set; \
             traffic will be plaintext (correct destination, absent crypto). \
             Set `tls: true` to encrypt. (Class B divergence — upstream is silent)"
        );
    }

    // ── Warn: mux enabled (Class B) ───────────────────────────────────────
    if let Some(mux) = config.get("mux") {
        let mux_enabled = mux
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if mux_enabled {
            tracing::warn!(
                proxy = %name,
                "vless: mux is not implemented (Mux.Cool); \
                 the `mux` option is ignored. \
                 (Class B divergence — upstream runs Mux.Cool)"
            );
        }
    }

    // ── Warn: Vision + UDP (Class B) ─────────────────────────────────────
    if flow == Some(VlessFlow::XtlsRprxVision) && udp {
        tracing::warn!(
            proxy = %name,
            "flow: xtls-rprx-vision applies to TCP only; UDP relays on \
             this proxy will use plain VLESS (Vision's inner-TLS splice \
             is not defined for UDP datagrams). (Class B divergence)"
        );
    }

    // ── Build transport chain ──────────────────────────────────────────────
    let mut chain = TransportChain::empty();

    if tls {
        use mihomo_transport::tls::{TlsConfig, TlsLayer};
        let sni = if servername.is_empty() {
            server.to_string()
        } else {
            servername.clone()
        };
        let mut tls_cfg = TlsConfig::new(sni);
        tls_cfg.skip_cert_verify = skip_cert_verify;
        tls_cfg.alpn = alpn;
        let tls_layer =
            TlsLayer::new(&tls_cfg).map_err(|e| format!("vless: TLS layer error: {}", e))?;
        chain.push(Box::new(tls_layer));
    }

    match network {
        "tcp" => {} // no extra layer
        "ws" => {
            use mihomo_transport::ws::{WsConfig, WsLayer};
            let ws_opts = config.get("ws-opts");
            let path = ws_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            // host_header: user-supplied Host, or fall back to server address.
            // WsLayer::new requires Some; normalization is the config layer's job
            // (ADR-0001 §1 — transport never infers values from context).
            let host_header = ws_opts
                .and_then(|o| o.get("headers"))
                .and_then(|h| h.get("Host"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| server.to_string());
            let max_early_data = ws_opts
                .and_then(|o| o.get("max-early-data"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            let early_data_header_name = ws_opts
                .and_then(|o| o.get("early-data-header-name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let ws_cfg = WsConfig {
                path,
                host_header: Some(host_header),
                extra_headers: vec![],
                max_early_data,
                early_data_header_name,
            };
            let ws_layer =
                WsLayer::new(ws_cfg).map_err(|e| format!("vless: ws layer error: {}", e))?;
            chain.push(Box::new(ws_layer));
        }
        "grpc" | "h2" | "httpupgrade" => {
            // These transports are not yet implemented in M1.
            // They are accepted at parse time (for the Vision-requires-TLS gate)
            // but will fail at dial time.
            tracing::warn!(
                proxy = %name,
                network = %network,
                "vless: network transport '{}' is not yet implemented in M1; \
                 connections will fail at dial time",
                network
            );
        }
        other => {
            return Err(format!(
                "vless: unsupported network '{}'; valid values: tcp, ws, grpc, h2, httpupgrade",
                other
            ));
        }
    }

    Ok(VlessAdapter::new(
        name, server, port, uuid_bytes, flow, udp, chain,
    ))
}

/// Parse a UUID string (dashed or hex-only) into a 16-byte array.
///
/// Accepts: `"b831381d-6324-4d53-ad4f-8cda48b30811"` or
///          `"b831381d63244d53ad4f8cda48b30811"`.
fn parse_uuid(s: &str) -> std::result::Result<[u8; 16], String> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(format!(
            "invalid uuid '{}': expected 32 hex chars (with or without dashes), got {}",
            s,
            hex.len()
        ));
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk)
            .map_err(|_| format!("invalid uuid '{}': non-UTF8 chars", s))?;
        bytes[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| format!("invalid uuid '{}': invalid hex char at byte {}", s, i))?;
    }
    Ok(bytes)
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
