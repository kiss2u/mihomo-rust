use crate::adapter_type::AdapterType;
use crate::conn::{ProxyConn, ProxyPacketConn};
use crate::error::Result;
use crate::metadata::Metadata;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelayHistory {
    pub time: SystemTime,
    pub delay: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyState {
    pub alive: bool,
    pub history: Vec<DelayHistory>,
}

#[async_trait]
pub trait ProxyAdapter: Send + Sync {
    fn name(&self) -> &str;
    fn adapter_type(&self) -> AdapterType;
    fn addr(&self) -> &str;
    fn support_udp(&self) -> bool;
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>>;
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>>;
    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        None
    }
}

pub trait Proxy: ProxyAdapter {
    fn alive(&self) -> bool;
    fn alive_for_url(&self, url: &str) -> bool;
    fn last_delay(&self) -> u16;
    fn last_delay_for_url(&self, url: &str) -> u16;
    fn delay_history(&self) -> Vec<DelayHistory>;
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }
}
