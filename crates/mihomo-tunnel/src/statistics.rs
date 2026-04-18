use dashmap::DashMap;
use mihomo_common::Metadata;
use serde::Serialize;
use std::sync::atomic::{AtomicI64, Ordering};
use uuid::Uuid;

#[derive(Serialize, Clone)]
pub struct ConnectionInfo {
    pub id: String,
    #[serde(skip)]
    pub metadata: Metadata,
    pub upload: i64,
    pub download: i64,
    pub start: String,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

pub struct Statistics {
    pub upload_total: AtomicI64,
    pub download_total: AtomicI64,
    pub connections: DashMap<String, ConnectionInfo>,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            upload_total: AtomicI64::new(0),
            download_total: AtomicI64::new(0),
            connections: DashMap::new(),
        }
    }

    pub fn add_upload(&self, n: i64) {
        self.upload_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_download(&self, n: i64) {
        self.download_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn track_connection(
        &self,
        metadata: Metadata,
        rule: &str,
        rule_payload: &str,
        chains: Vec<String>,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        let info = ConnectionInfo {
            id: id.clone(),
            metadata,
            upload: 0,
            download: 0,
            start: chrono_now(),
            chains,
            rule: rule.to_string(),
            rule_payload: rule_payload.to_string(),
        };
        self.connections.insert(id.clone(), info);
        id
    }

    pub fn close_connection(&self, id: &str) {
        self.connections.remove(id);
    }

    pub fn snapshot(&self) -> (i64, i64) {
        (
            self.upload_total.load(Ordering::Relaxed),
            self.download_total.load(Ordering::Relaxed),
        )
    }

    pub fn active_connections(&self) -> Vec<ConnectionInfo> {
        self.connections.iter().map(|e| e.value().clone()).collect()
    }

    pub fn close_all_connections(&self) {
        self.connections.clear();
    }
}

impl Default for Statistics {
    fn default() -> Self {
        Self::new()
    }
}

fn chrono_now() -> String {
    // Simple ISO timestamp without chrono dependency
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}
