use crate::cache::DnsCache;
use dashmap::DashMap;
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use mihomo_common::DnsMode;
use mihomo_trie::DomainTrie;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::{debug, warn};

/// Broadcast channel used to share a singleflight lookup result.
/// Capacity 1 is enough — subscribers call `recv()` at most once.
type InflightTx = tokio::sync::broadcast::Sender<Option<Vec<IpAddr>>>;

pub struct Resolver {
    main: TokioResolver,
    fallback: Option<TokioResolver>,
    cache: DnsCache,
    mode: DnsMode,
    // Policy: domain trie mapping to specific resolver index
    hosts: DomainTrie<Vec<IpAddr>>,
    /// Singleflight in-flight dedup: maps host → broadcast sender held by the
    /// leader task. Subscribers receive the leader's result and never launch
    /// their own hickory query.
    inflight: DashMap<String, InflightTx>,
}

/// RAII guard that removes the inflight entry on drop, whether the leader
/// completes normally or panics. Without this, a panicking leader would leave
/// a dangling entry whose broadcast sender has been dropped — subsequent
/// callers would subscribe, get `RecvError::Closed`, and the stale key would
/// never be reaped.
struct InflightGuard<'a> {
    map: &'a DashMap<String, InflightTx>,
    key: String,
    _armed: (),
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

fn clamp_ttl(raw: Duration) -> Duration {
    const MIN_TTL: Duration = Duration::from_secs(10);
    const MAX_TTL: Duration = Duration::from_secs(3600);
    raw.clamp(MIN_TTL, MAX_TTL)
}

/// Extract a usable cache TTL from a hickory LookupIp response.
/// Clamps the time-until-expiry reported by hickory to [10s, 3600s].
/// If hickory reports an already-expired entry (`valid_until` in the past),
/// this returns `MIN_TTL` so we cache for the shortest allowed window
/// instead of a misleading longer fallback.
fn ttl_from_lookup(lookup: &hickory_resolver::lookup_ip::LookupIp) -> Duration {
    let raw = lookup
        .valid_until()
        .saturating_duration_since(std::time::Instant::now());
    clamp_ttl(raw)
}

impl Resolver {
    pub fn new(
        main_servers: Vec<SocketAddr>,
        fallback_servers: Vec<SocketAddr>,
        mode: DnsMode,
        hosts: DomainTrie<Vec<IpAddr>>,
    ) -> Self {
        let main = Self::build_resolver(&main_servers);
        let fallback = if fallback_servers.is_empty() {
            None
        } else {
            Some(Self::build_resolver(&fallback_servers))
        };

        Self {
            main,
            fallback,
            cache: DnsCache::new(4096),
            mode,
            hosts,
            inflight: DashMap::new(),
        }
    }

    fn build_resolver(servers: &[SocketAddr]) -> TokioResolver {
        let mut config = ResolverConfig::new();
        for &addr in servers {
            config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
            config.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
        }
        let mut builder =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
        let opts = builder.options_mut();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;
        opts.cache_size = 0; // We use our own cache
        builder.build()
    }

    pub async fn resolve_ip(&self, host: &str) -> Option<IpAddr> {
        // 1. Check hosts file
        if let Some(ips) = self.hosts.search(host) {
            return ips.first().copied();
        }

        // 2. Check cache
        if let Some(ips) = self.cache.get(host) {
            return ips.first().copied();
        }

        // 3. Resolve via DNS
        self.lookup_actual(host).await
    }

    /// Resolve a hostname to a routable IP address. Kept as a separate entry
    /// point so callers that specifically need a real IP for rule matching
    /// (GeoIP / IP-CIDR) remain explicit; currently identical to
    /// [`resolve_ip`].
    pub async fn resolve_ip_real(&self, host: &str) -> Option<IpAddr> {
        self.resolve_ip(host).await
    }

    pub async fn lookup_ipv4(&self, host: &str) -> Option<IpAddr> {
        if let Some(ips) = self.hosts.search(host) {
            return ips.iter().find(|ip| ip.is_ipv4()).copied();
        }
        if let Some(ips) = self.cache.get(host) {
            return ips.iter().find(|ip| ip.is_ipv4()).copied();
        }
        let ips = self.lookup_actual_all(host).await?;
        ips.into_iter().find(|ip| ip.is_ipv4())
    }

    pub async fn lookup_ipv6(&self, host: &str) -> Option<IpAddr> {
        if let Some(ips) = self.hosts.search(host) {
            return ips.iter().find(|ip| ip.is_ipv6()).copied();
        }
        if let Some(ips) = self.cache.get(host) {
            return ips.iter().find(|ip| ip.is_ipv6()).copied();
        }
        let ips = self.lookup_actual_all(host).await?;
        ips.into_iter().find(|ip| ip.is_ipv6())
    }

    async fn lookup_actual(&self, host: &str) -> Option<IpAddr> {
        let ips = self.lookup_actual_all(host).await?;
        ips.into_iter().next()
    }

    /// Singleflight wrapper around [`Self::do_lookup`]. The first caller for a
    /// given host becomes the leader and launches one upstream query; any
    /// concurrent callers subscribe to a broadcast channel and receive the
    /// leader's result. An RAII guard removes the inflight entry on all exit
    /// paths (including panics), so a panicking leader can't leak entries.
    async fn lookup_actual_all(&self, host: &str) -> Option<Vec<IpAddr>> {
        use dashmap::mapref::entry::Entry;

        // Fast path: another task is already resolving this host — subscribe
        // and wait. `get()` takes a read lock which we drop before awaiting
        // to avoid blocking other DashMap shards. `recv()` returning Err
        // means the leader's sender was dropped without sending (panic or
        // task cancellation) — fall through to None, matching the "lookup
        // failed" contract.
        if let Some(entry) = self.inflight.get(host) {
            let mut rx = entry.subscribe();
            drop(entry);
            return rx.recv().await.ok().flatten();
        }

        // Slow path: try to become the leader. The entry API closes the race
        // where two tasks both observed the map as empty above.
        let tx = match self.inflight.entry(host.to_string()) {
            Entry::Occupied(existing) => {
                let mut rx = existing.get().subscribe();
                drop(existing);
                return rx.recv().await.ok().flatten();
            }
            Entry::Vacant(v) => {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                v.insert(tx.clone());
                tx
            }
        };

        let _guard = InflightGuard {
            map: &self.inflight,
            key: host.to_string(),
            _armed: (),
        };

        let result = self.do_lookup(host).await;
        // Subscribers may have all dropped by now; send error is not
        // actionable and there's nothing to do about it.
        let _ = tx.send(result.clone());
        result
    }

    async fn do_lookup(&self, host: &str) -> Option<Vec<IpAddr>> {
        debug!("DNS lookup: {}", host);

        // Try main resolver
        match self.main.lookup_ip(host).await {
            Ok(lookup) => {
                let ttl = ttl_from_lookup(&lookup);
                let ips: Vec<IpAddr> = lookup.iter().collect();
                if !ips.is_empty() {
                    self.cache.put(host, ips.clone(), ttl);
                    return Some(ips);
                }
            }
            Err(e) => {
                debug!("Main DNS lookup failed for {}: {}", host, e);
            }
        }

        // Try fallback resolver
        if let Some(fallback) = &self.fallback {
            match fallback.lookup_ip(host).await {
                Ok(lookup) => {
                    let ttl = ttl_from_lookup(&lookup);
                    let ips: Vec<IpAddr> = lookup.iter().collect();
                    if !ips.is_empty() {
                        self.cache.put(host, ips.clone(), ttl);
                        return Some(ips);
                    }
                }
                Err(e) => {
                    warn!("Fallback DNS lookup failed for {}: {}", host, e);
                }
            }
        }

        None
    }

    /// Reverse lookup via DNS snooping: given a real IP, return the domain
    /// that was recently resolved to it (from the DNS cache).
    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        self.cache.reverse_lookup(ip)
    }

    pub fn mode(&self) -> DnsMode {
        self.mode
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn resolve_ip_uses_hosts_file() {
        let mut hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let real = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        hosts.insert("example.test", vec![real]);

        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts);
        assert_eq!(resolver.resolve_ip("example.test").await, Some(real));
        assert_eq!(resolver.resolve_ip_real("example.test").await, Some(real));
    }

    #[tokio::test]
    async fn resolve_ip_returns_cached_entry() {
        let hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts);

        let real = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        resolver
            .cache
            .put("cached.test", vec![real], Duration::from_secs(60));

        assert_eq!(resolver.resolve_ip("cached.test").await, Some(real));
    }

    #[test]
    fn clamp_ttl_zero_returns_min() {
        assert_eq!(clamp_ttl(Duration::ZERO), Duration::from_secs(10));
    }

    #[test]
    fn clamp_ttl_below_min_returns_min() {
        assert_eq!(clamp_ttl(Duration::from_secs(3)), Duration::from_secs(10));
    }

    #[test]
    fn clamp_ttl_in_range_returns_raw() {
        assert_eq!(
            clamp_ttl(Duration::from_secs(120)),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn clamp_ttl_above_max_returns_max() {
        assert_eq!(
            clamp_ttl(Duration::from_secs(99_999)),
            Duration::from_secs(3600)
        );
    }

    #[tokio::test]
    async fn inflight_entry_cleared_after_lookup_miss() {
        // No nameservers → lookup_actual_all returns None quickly. After it
        // returns, the inflight map must not retain the host key.
        let hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts);
        let _ = resolver.lookup_actual_all("nonexistent.test").await;
        assert!(
            resolver.inflight.is_empty(),
            "inflight map must be empty after lookup, had {} entries",
            resolver.inflight.len()
        );
    }

    #[tokio::test]
    async fn inflight_concurrent_callers_share_one_lookup() {
        // Two concurrent callers for the same host should collapse into a
        // single upstream lookup. With zero nameservers both branches of
        // `lookup_actual_all` return None; the test verifies (a) both calls
        // return the same result, (b) the map is clean on exit.
        let hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let resolver = std::sync::Arc::new(Resolver::new(vec![], vec![], DnsMode::Normal, hosts));
        let r1 = resolver.clone();
        let r2 = resolver.clone();
        let (a, b) = tokio::join!(
            r1.lookup_actual_all("concurrent.test"),
            r2.lookup_actual_all("concurrent.test"),
        );
        assert_eq!(a, b, "concurrent callers must see the same result");
        assert!(resolver.inflight.is_empty());
    }
}
