use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawConfig {
    pub port: Option<u16>,
    pub socks_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub allow_lan: Option<bool>,
    pub bind_address: Option<String>,
    pub mode: Option<String>,
    pub log_level: Option<String>,
    pub ipv6: Option<bool>,
    pub external_controller: Option<String>,
    pub secret: Option<String>,
    pub dns: Option<RawDns>,
    pub proxies: Option<Vec<HashMap<String, serde_yaml::Value>>>,
    pub proxy_groups: Option<Vec<RawProxyGroup>>,
    pub rules: Option<Vec<String>>,
    pub rule_providers: Option<HashMap<String, RawRuleProvider>>,
    /// Named sub-rule blocks. Each key is a block name; each value is a
    /// list of rule strings parsed identically to the top-level `rules:`
    /// section. Referenced from `rules:` via `SUB-RULE,<name>`.
    pub sub_rules: Option<HashMap<String, Vec<String>>>,
    pub subscriptions: Option<Vec<RawSubscription>>,
    pub tproxy_port: Option<u16>,
    pub tproxy_sni: Option<bool>,
    pub routing_mark: Option<u32>,
    /// Static host → IP mappings, preferred over upstream DNS lookups.
    /// Values may be a single IP string or a list of IPs.
    pub hosts: Option<HashMap<String, HostsValue>>,
}

/// A `hosts:` map value: either a single IP address or a list of addresses.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum HostsValue {
    One(String),
    Many(Vec<String>),
}

impl HostsValue {
    pub fn as_slice(&self) -> Vec<&str> {
        match self {
            HostsValue::One(s) => vec![s.as_str()],
            HostsValue::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawDns {
    pub enable: Option<bool>,
    pub listen: Option<String>,
    pub enhanced_mode: Option<String>,
    pub fake_ip_range: Option<String>,
    pub default_nameserver: Option<Vec<String>>,
    pub nameserver: Option<Vec<String>>,
    pub fallback: Option<Vec<String>>,
    pub fake_ip_filter: Option<Vec<String>>,
    /// If false, the hosts trie lookup is skipped entirely at query time.
    pub use_hosts: Option<bool>,
    /// If true, `/etc/hosts` is read at startup and merged (lower priority than
    /// `dns.hosts` config entries). No-op + warn on Windows.
    pub use_system_hosts: Option<bool>,
    /// Per-domain nameserver routing: each key is an exact domain or a `+.`
    /// wildcard prefix; value is a single server URL or a list of URLs.
    pub nameserver_policy: Option<HashMap<String, RawNspValue>>,
    /// Controls when the `fallback:` nameservers replace the primary result.
    pub fallback_filter: Option<RawFallbackFilter>,
}

/// A nameserver-policy value: either a single URL string or a list of URLs.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawNspValue {
    One(String),
    Many(Vec<String>),
}

impl RawNspValue {
    pub fn as_urls(&self) -> Vec<&str> {
        match self {
            RawNspValue::One(s) => vec![s.as_str()],
            RawNspValue::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

/// `fallback-filter` YAML block.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawFallbackFilter {
    pub geoip: Option<bool>,
    pub geoip_code: Option<String>,
    pub ipcidr: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawProxyGroup {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: String,
    pub proxies: Option<Vec<String>>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub tolerance: Option<u16>,
    pub strategy: Option<String>,
    pub lazy: Option<bool>,
}

/// A single entry in the top-level `rule-providers:` map.
///
/// `interval` is accepted for upstream-config compatibility but is currently
/// ignored — providers are loaded exactly once at startup.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawRuleProvider {
    #[serde(rename = "type")]
    pub provider_type: String, // "http" | "file" | "inline"
    pub behavior: String,       // "domain" | "ipcidr" | "classical"
    pub format: Option<String>, // "yaml" (default) | "text" | "mrs"
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: Option<u64>,
    /// Inline payload: list of rule strings (only for type=inline).
    pub payload: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawSubscription {
    pub name: String,
    pub url: String,
    pub interval: Option<u64>,
    pub last_updated: Option<i64>,
}
