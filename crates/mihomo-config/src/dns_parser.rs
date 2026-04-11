use crate::raw::{HostsValue, RawConfig};
use crate::DnsConfig;
use mihomo_common::DnsMode;
use mihomo_dns::Resolver;
use mihomo_trie::DomainTrie;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::warn;

pub fn parse_dns(raw: &RawConfig) -> Result<DnsConfig, anyhow::Error> {
    let dns = match &raw.dns {
        Some(dns) if dns.enable.unwrap_or(false) => dns,
        _ => {
            // DNS disabled, use system defaults. Static `hosts:` still apply.
            let hosts = build_hosts_trie(raw.hosts.as_ref());
            let resolver = Arc::new(Resolver::new(
                vec!["8.8.8.8:53".parse().unwrap()],
                vec![],
                DnsMode::Normal,
                hosts,
            ));
            return Ok(DnsConfig {
                resolver,
                listen_addr: None,
            });
        }
    };

    // Parse nameservers
    let main_servers = parse_nameservers(dns.nameserver.as_deref().unwrap_or(&[]));
    let fallback_servers = parse_nameservers(dns.fallback.as_deref().unwrap_or(&[]));

    // Parse DNS mode. FakeIP was removed; fall back to Normal with a warning
    // so existing Clash-style configs still load.
    let mode = match dns.enhanced_mode.as_deref() {
        Some("fake-ip") => {
            warn!("dns.enhanced-mode: 'fake-ip' is no longer supported; falling back to 'normal'");
            DnsMode::Normal
        }
        Some("redir-host") => DnsMode::Mapping,
        _ => DnsMode::Normal,
    };

    // DNS listen address
    let listen_addr = dns
        .listen
        .as_deref()
        .and_then(|s| s.parse::<SocketAddr>().ok());

    let hosts = build_hosts_trie(raw.hosts.as_ref());

    let resolver = Arc::new(Resolver::new(main_servers, fallback_servers, mode, hosts));

    Ok(DnsConfig {
        resolver,
        listen_addr,
    })
}

/// Build a `DomainTrie<Vec<IpAddr>>` from the top-level `hosts:` map.
///
/// Skips entries whose value fails to parse as an `IpAddr`, emitting a warn
/// log so config errors are visible without failing the whole load. Supports
/// upstream mihomo's `+.wildcard` prefix by virtue of `DomainTrie::insert`,
/// and also inserts the bare host for `+.foo.com` so queries for `foo.com`
/// hit the entry (matches upstream semantics and our classical rule-set
/// behaviour).
fn build_hosts_trie(hosts: Option<&HashMap<String, HostsValue>>) -> DomainTrie<Vec<IpAddr>> {
    let mut trie: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
    let Some(hosts) = hosts else { return trie };
    for (host, value) in hosts {
        let ips: Vec<IpAddr> = value
            .as_slice()
            .into_iter()
            .filter_map(|s| match s.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(e) => {
                    warn!("hosts: skipping invalid IP for '{}': {} ({})", host, s, e);
                    None
                }
            })
            .collect();
        if ips.is_empty() {
            warn!("hosts: entry '{}' has no valid IPs, skipping", host);
            continue;
        }
        let entry = host.trim();
        if !trie.insert(entry, ips.clone()) {
            warn!("hosts: failed to insert '{}' into trie", entry);
            continue;
        }
        // `+.foo.com` should also match the bare `foo.com` (upstream parity,
        // matches DomainRuleSet in rule_set.rs).
        if let Some(bare) = entry.strip_prefix("+.") {
            let _ = trie.insert(bare, ips);
        }
    }
    trie
}

fn parse_nameservers(servers: &[String]) -> Vec<SocketAddr> {
    servers
        .iter()
        .filter_map(|s| {
            // Handle various formats: "8.8.8.8", "8.8.8.8:53", "udp://8.8.8.8:53"
            let s = s.trim();
            let s = s.strip_prefix("udp://").unwrap_or(s);
            let s = s.strip_prefix("tcp://").unwrap_or(s);

            // Try as-is
            if let Ok(addr) = s.parse::<SocketAddr>() {
                return Some(addr);
            }

            // Try adding default port
            if let Ok(ip) = s.parse::<IpAddr>() {
                return Some(SocketAddr::new(ip, 53));
            }

            // Try with port
            if let Ok(addr) = format!("{}:53", s).parse::<SocketAddr>() {
                return Some(addr);
            }

            warn!("Failed to parse nameserver: {}", s);
            None
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn one(s: &str) -> HostsValue {
        HostsValue::One(s.to_string())
    }
    fn many(ss: &[&str]) -> HostsValue {
        HostsValue::Many(ss.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn build_hosts_trie_none_is_empty() {
        let trie = build_hosts_trie(None);
        assert!(trie.search("example.com").is_none());
    }

    #[test]
    fn build_hosts_trie_single_ip() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), one("1.2.3.4"));
        let trie = build_hosts_trie(Some(&map));
        let v = trie.search("example.com").expect("must hit");
        assert_eq!(v, &vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn build_hosts_trie_many_ips() {
        let mut map = HashMap::new();
        map.insert("dual.test".to_string(), many(&["1.1.1.1", "::1"]));
        let trie = build_hosts_trie(Some(&map));
        let v = trie.search("dual.test").expect("must hit");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn build_hosts_trie_invalid_skipped() {
        let mut map = HashMap::new();
        map.insert("bad.test".to_string(), one("not-an-ip"));
        map.insert("good.test".to_string(), one("9.9.9.9"));
        let trie = build_hosts_trie(Some(&map));
        assert!(trie.search("bad.test").is_none());
        assert!(trie.search("good.test").is_some());
    }

    #[test]
    fn build_hosts_trie_wildcard_and_bare() {
        let mut map = HashMap::new();
        map.insert("+.corp.example".to_string(), one("10.0.0.1"));
        let trie = build_hosts_trie(Some(&map));
        assert!(trie.search("host.corp.example").is_some());
        // Bare host alias — matches DomainRuleSet behaviour.
        assert!(trie.search("corp.example").is_some());
    }
}
