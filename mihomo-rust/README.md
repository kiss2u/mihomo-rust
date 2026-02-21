# mihomo-rust

A high-performance Rust implementation of the [mihomo](https://github.com/MetaCubeX/mihomo) (Clash Meta) proxy kernel. Rule-based tunneling with support for multiple proxy protocols, DNS with FakeIP, and a REST API for runtime control.

## Features

### Proxy Protocols
- **Shadowsocks** — TCP and UDP relay, AEAD and stream ciphers (aes-256-gcm, chacha20-ietf-poly1305, etc.)
- **Trojan** — TLS 1.2/1.3 via rustls, SNI, optional skip-cert-verify
- **Direct** — Direct connection to destination
- **Reject** — Drop connections (with configurable behavior)

### Proxy Groups
- **Selector** — Manual proxy selection via REST API
- **URLTest** — Automatic selection based on latency with tolerance threshold
- **Fallback** — Automatic failover to first alive proxy

### Rule Engine
| Rule | Example | Description |
|------|---------|-------------|
| DOMAIN | `DOMAIN,google.com,Proxy` | Exact domain match |
| DOMAIN-SUFFIX | `DOMAIN-SUFFIX,google.com,Proxy` | Domain and subdomains |
| DOMAIN-KEYWORD | `DOMAIN-KEYWORD,google,Proxy` | Substring match |
| DOMAIN-REGEX | `DOMAIN-REGEX,^ads?\.,Proxy` | Regex pattern |
| IP-CIDR | `IP-CIDR,10.0.0.0/8,DIRECT,no-resolve` | Destination IP range |
| SRC-IP-CIDR | `SRC-IP-CIDR,192.168.0.0/16,DIRECT` | Source IP range |
| DST-PORT | `DST-PORT,80,443,8080,Proxy` | Destination port(s) |
| SRC-PORT | `SRC-PORT,1234,DIRECT` | Source port(s) |
| NETWORK | `NETWORK,udp,Proxy` | TCP or UDP |
| PROCESS-NAME | `PROCESS-NAME,curl,DIRECT` | Process name |
| GEOIP | `GEOIP,CN,DIRECT,no-resolve` | MaxMind GeoIP lookup |
| MATCH | `MATCH,Proxy` | Catch-all fallback |

Logic composition rules (AND, OR, NOT) are also supported for combining conditions.

### DNS
- UDP DNS server with configurable listen address
- Main + fallback nameserver groups
- **FakeIP** mode for transparent proxying (configurable CIDR range)
- Response caching and in-flight request deduplication

### Inbound Listeners
- **Mixed** — Auto-detects HTTP or SOCKS5 on a single port
- **HTTP Proxy** — HTTP CONNECT and plain HTTP forwarding
- **SOCKS5** — SOCKS5 with optional authentication

### REST API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/version` | GET | Version info |
| `/proxies` | GET | List all proxies |
| `/proxies/{name}` | GET/PUT | Get or switch proxy |
| `/rules` | GET | List active rules |
| `/connections` | GET | Active connections with traffic stats |
| `/connections/{id}` | DELETE | Close a connection |
| `/configs` | GET/PATCH | Get or update running config |
| `/traffic` | GET | Upload/download statistics |
| `/dns/query` | POST | Direct DNS query |

### Tunnel
- Three routing modes: **Rule**, **Global**, **Direct**
- Bidirectional TCP relay and UDP NAT session tracking
- Per-connection traffic statistics with connection lifecycle management

## Architecture

```
Listeners (HTTP/SOCKS5/Mixed)
        |
        v
    Tunnel (routing engine)  <-->  DNS Resolver (FakeIP/Normal)
        |
    Rule Matching Engine
        |
        v
  Proxy Adapters / Groups  --->  Remote Server

  REST API Server (Axum)   --->  Runtime control
```

10 workspace crates with clear separation of concerns:

| Crate | Purpose |
|-------|---------|
| `mihomo-common` | Core traits and types (ProxyAdapter, Rule, Metadata) |
| `mihomo-trie` | Domain trie for efficient pattern matching |
| `mihomo-proxy` | Proxy protocol implementations and groups |
| `mihomo-rules` | Rule matching engine and parser |
| `mihomo-dns` | DNS resolver, FakeIP pool, cache, server |
| `mihomo-tunnel` | Core routing, TCP/UDP relay, statistics |
| `mihomo-listener` | Inbound protocol handlers |
| `mihomo-config` | YAML configuration parsing |
| `mihomo-api` | REST API (Axum) |
| `mihomo-app` | CLI entry point |

## Build

Requires Rust 1.70+.

```bash
cargo build --release
```

## Usage

```bash
# Run with config file
./target/release/mihomo -f config.yaml

# Test config validity
./target/release/mihomo -f config.yaml -t
```

### Example Configuration

```yaml
mixed-port: 7890
mode: rule
log-level: info

external-controller: 127.0.0.1:9090

dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 8.8.8.8
  fallback:
    - 8.8.4.4

proxies:
  - name: my-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "secret"
    udp: true

  - name: my-trojan
    type: trojan
    server: 5.6.7.8
    port: 443
    password: "secret"
    sni: example.com
    skip-cert-verify: false

proxy-groups:
  - name: Proxy
    type: select
    proxies: [my-ss, my-trojan]

  - name: Auto
    type: url-test
    proxies: [my-ss, my-trojan]
    url: http://www.gstatic.com/generate_204
    interval: 300

rules:
  - DOMAIN-SUFFIX,local,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - DOMAIN-SUFFIX,google.com,Proxy
  - MATCH,Proxy
```

## Testing

```bash
# Unit tests
cargo test --lib

# Rules tests (78 tests covering all rule types)
cargo test --test rules_test

# Trojan integration tests (embedded mock server, no external deps)
cargo test --test trojan_integration

# Shadowsocks integration tests (requires ssserver)
cargo install shadowsocks-rust --features "stream-cipher aead-cipher-2022" --locked
cargo test --test shadowsocks_integration
```

## License

GPL-3.0
