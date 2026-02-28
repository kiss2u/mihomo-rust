use mihomo_config::load_config_from_str;

#[test]
fn test_minimal_config() {
    let yaml = r#"
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(config.listeners.mixed_port, Some(7890));
    assert!(config.listeners.socks_port.is_none());
    assert!(config.listeners.http_port.is_none());
    // Default mode is Rule
    assert_eq!(config.general.mode.to_string(), "rule");
    // Built-in proxies: DIRECT, REJECT, REJECT-DROP
    assert!(config.proxies.contains_key("DIRECT"));
    assert!(config.proxies.contains_key("REJECT"));
    assert!(config.proxies.contains_key("REJECT-DROP"));
}

#[test]
fn test_general_config_defaults() {
    let yaml = "";
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(config.general.mode.to_string(), "rule");
    assert_eq!(config.general.log_level, "info");
    assert!(!config.general.ipv6);
    assert!(!config.general.allow_lan);
    assert_eq!(config.general.bind_address, "127.0.0.1");
}

#[test]
fn test_general_config_custom() {
    let yaml = r#"
mode: global
log-level: debug
ipv6: true
allow-lan: true
bind-address: "0.0.0.0"
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(config.general.mode.to_string(), "global");
    assert_eq!(config.general.log_level, "debug");
    assert!(config.general.ipv6);
    assert!(config.general.allow_lan);
    assert_eq!(config.general.bind_address, "0.0.0.0");
}

#[test]
fn test_direct_mode_config() {
    let yaml = r#"
mode: direct
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(config.general.mode.to_string(), "direct");
}

#[test]
fn test_invalid_mode_defaults_to_rule() {
    let yaml = r#"
mode: bogus
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(config.general.mode.to_string(), "rule");
}

#[test]
fn test_listener_ports() {
    let yaml = r#"
port: 7891
socks-port: 7892
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(config.listeners.http_port, Some(7891));
    assert_eq!(config.listeners.socks_port, Some(7892));
    assert_eq!(config.listeners.mixed_port, Some(7890));
}

#[test]
fn test_listener_bind_address_allow_lan() {
    let yaml = r#"
allow-lan: true
bind-address: "0.0.0.0"
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(config.listeners.bind_address, "0.0.0.0");
}

#[test]
fn test_listener_bind_address_no_lan() {
    let yaml = r#"
allow-lan: false
bind-address: "0.0.0.0"
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).unwrap();
    // When allow-lan is false, bind_address is forced to 127.0.0.1
    assert_eq!(config.listeners.bind_address, "127.0.0.1");
}

#[test]
fn test_api_config() {
    let yaml = r#"
external-controller: "127.0.0.1:9090"
secret: "my-secret"
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(
        config.api.external_controller.unwrap().to_string(),
        "127.0.0.1:9090"
    );
    assert_eq!(config.api.secret.as_deref(), Some("my-secret"));
}

#[test]
fn test_api_config_none() {
    let yaml = "";
    let config = load_config_from_str(yaml).unwrap();
    assert!(config.api.external_controller.is_none());
    assert!(config.api.secret.is_none());
}

#[test]
fn test_tun_config() {
    let yaml = r#"
tun:
  enable: true
  device: utun42
  mtu: 9000
  inet4-address: "198.18.0.1/16"
  dns-hijack:
    - "198.18.0.2:53"
  auto-route: true
"#;
    let config = load_config_from_str(yaml).unwrap();
    let tun = config.tun.unwrap();
    assert!(tun.enable);
    assert_eq!(tun.device.as_deref(), Some("utun42"));
    assert_eq!(tun.mtu, 9000);
    assert_eq!(tun.inet4_address, "198.18.0.1/16");
    assert_eq!(tun.dns_hijack.len(), 1);
    assert_eq!(tun.dns_hijack[0].to_string(), "198.18.0.2:53");
    assert!(tun.auto_route);
}

#[test]
fn test_tun_config_defaults() {
    let yaml = r#"
tun:
  enable: false
"#;
    let config = load_config_from_str(yaml).unwrap();
    let tun = config.tun.unwrap();
    assert!(!tun.enable);
    assert!(tun.device.is_none());
    assert_eq!(tun.mtu, 1500);
    assert_eq!(tun.inet4_address, "198.18.0.1/16");
    assert!(tun.dns_hijack.is_empty());
    assert!(!tun.auto_route);
}

#[test]
fn test_no_tun_config() {
    let yaml = "";
    let config = load_config_from_str(yaml).unwrap();
    assert!(config.tun.is_none());
}

#[test]
fn test_dns_disabled_by_default() {
    let yaml = "";
    let config = load_config_from_str(yaml).unwrap();
    // DNS listen addr should be None when DNS is not configured
    assert!(config.dns.listen_addr.is_none());
}

#[test]
fn test_dns_config_enabled() {
    let yaml = r#"
dns:
  enable: true
  listen: "0.0.0.0:5353"
  enhanced-mode: fake-ip
  fake-ip-range: "198.18.0.1/16"
  nameserver:
    - "8.8.8.8"
    - "8.8.4.4:53"
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(
        config.dns.listen_addr.unwrap().to_string(),
        "0.0.0.0:5353"
    );
}

#[test]
fn test_dns_config_disabled() {
    let yaml = r#"
dns:
  enable: false
  listen: "0.0.0.0:5353"
"#;
    let config = load_config_from_str(yaml).unwrap();
    // When DNS is disabled, listen_addr should be None
    assert!(config.dns.listen_addr.is_none());
}

#[test]
fn test_proxy_parsing_ss() {
    let yaml = r#"
proxies:
  - name: "ss-server"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    udp: true
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert!(config.proxies.contains_key("ss-server"));
}

#[test]
fn test_proxy_parsing_trojan() {
    let yaml = r#"
proxies:
  - name: "trojan-server"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    sni: "example.com"
    skip-cert-verify: true
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert!(config.proxies.contains_key("trojan-server"));
}

#[test]
fn test_unsupported_proxy_type_skipped() {
    let yaml = r#"
proxies:
  - name: "vmess-server"
    type: vmess
    server: "1.2.3.4"
    port: 443
"#;
    let config = load_config_from_str(yaml).unwrap();
    // vmess is not yet supported, so it should be skipped
    assert!(!config.proxies.contains_key("vmess-server"));
}

#[test]
fn test_rule_parsing() {
    let yaml = r#"
rules:
  - "DOMAIN-SUFFIX,google.com,DIRECT"
  - "DOMAIN-KEYWORD,facebook,REJECT"
  - "MATCH,DIRECT"
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(config.rules.len(), 3);
}

#[test]
fn test_rule_parsing_with_comments() {
    let yaml = r#"
rules:
  - "DOMAIN,example.com,DIRECT"
  - "MATCH,DIRECT"
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(config.rules.len(), 2);
}

#[test]
fn test_empty_rules() {
    let yaml = "";
    let config = load_config_from_str(yaml).unwrap();
    assert!(config.rules.is_empty());
}

#[test]
fn test_proxy_group_select() {
    let yaml = r#"
proxies:
  - name: "ss1"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "pass"

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - ss1
      - DIRECT
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert!(config.proxies.contains_key("Proxy"));
}

#[test]
fn test_proxy_group_missing_proxy_warn_not_fail() {
    let yaml = r#"
proxies:
  - name: "ss1"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "pass"

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - ss1
      - nonexistent-proxy
"#;
    // Should succeed even with missing proxy reference
    let config = load_config_from_str(yaml).unwrap();
    assert!(config.proxies.contains_key("Proxy"));
}

#[test]
fn test_full_config() {
    let yaml = r#"
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: false
external-controller: "127.0.0.1:9090"

dns:
  enable: true
  listen: "0.0.0.0:5353"
  enhanced-mode: fake-ip
  fake-ip-range: "198.18.0.1/16"
  nameserver:
    - "8.8.8.8"
    - "8.8.4.4"

proxies:
  - name: "ss-test"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "test-password"
    udp: true

proxy-groups:
  - name: "auto"
    type: url-test
    proxies:
      - ss-test
    url: "http://www.gstatic.com/generate_204"
    interval: 300

rules:
  - "DOMAIN-SUFFIX,google.com,auto"
  - "MATCH,DIRECT"
"#;
    let config = load_config_from_str(yaml).unwrap();
    assert_eq!(config.listeners.mixed_port, Some(7890));
    assert_eq!(config.general.mode.to_string(), "rule");
    assert!(config.proxies.contains_key("ss-test"));
    assert!(config.proxies.contains_key("auto"));
    assert!(config.proxies.contains_key("DIRECT"));
    assert_eq!(config.rules.len(), 2);
    assert!(config.dns.listen_addr.is_some());
    assert!(config.api.external_controller.is_some());
}

#[test]
fn test_invalid_yaml() {
    let yaml = "{{invalid yaml}}";
    assert!(load_config_from_str(yaml).is_err());
}

#[test]
fn test_dns_hijack_invalid_address_skipped() {
    let yaml = r#"
tun:
  enable: true
  dns-hijack:
    - "198.18.0.2:53"
    - "not-a-valid-address"
"#;
    let config = load_config_from_str(yaml).unwrap();
    let tun = config.tun.unwrap();
    // Only valid addresses are kept
    assert_eq!(tun.dns_hijack.len(), 1);
}
