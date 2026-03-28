use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

struct CacheEntry {
    ips: Vec<IpAddr>,
    expire_at: Instant,
}

struct ReverseEntry {
    domain: String,
    expire_at: Instant,
}

pub struct DnsCache {
    cache: Mutex<LruCache<String, CacheEntry>>,
    /// Reverse mapping: IP → domain (for DNS snooping / tproxy hostname recovery)
    reverse: DashMap<IpAddr, ReverseEntry>,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1024).unwrap()),
            )),
            reverse: DashMap::new(),
        }
    }

    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get(domain) {
            if entry.expire_at > Instant::now() {
                return Some(entry.ips.clone());
            }
            // Expired, but don't remove here to avoid borrow issues
        }
        cache.pop(domain);
        None
    }

    pub fn put(&self, domain: &str, ips: Vec<IpAddr>, ttl: Duration) {
        let expire_at = Instant::now() + ttl;

        // Record reverse mappings for each resolved IP
        for &ip in &ips {
            self.reverse.insert(
                ip,
                ReverseEntry {
                    domain: domain.to_string(),
                    expire_at,
                },
            );
        }

        let entry = CacheEntry { ips, expire_at };
        self.cache.lock().put(domain.to_string(), entry);
    }

    /// Reverse lookup: given an IP, return the domain that resolved to it.
    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        let entry = self.reverse.get(&ip)?;
        if entry.expire_at > Instant::now() {
            Some(entry.domain.clone())
        } else {
            drop(entry);
            self.reverse.remove(&ip);
            None
        }
    }

    pub fn clear(&self) {
        self.cache.lock().clear();
        self.reverse.clear();
    }
}
