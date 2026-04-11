# Spec: Geodata YAML subsection (M2+)

Status: Draft (design sketch — M1 uses file-discovery; this subsection lands in M2)
Owner: pm
Tracks roadmap item: **M2** (task #47)
Architect decision 2026-04-11: no `geodata:` YAML key in M1.
See also: [`docs/specs/rules-parser-completion.md`](rules-parser-completion.md) —
ASN file-discovery chain used in M1 for IP-ASN rule;
[`docs/specs/rule-geosite.md`](rule-geosite.md) — geosite file path also covered here.

## Motivation

Upstream Go mihomo exposes a `geodata:` (and scattered `geo-*`) config section
that lets users override DB file paths, set download URLs, and enable periodic
auto-update. In M1 mihomo-rust discovers DB files via a XDG-compliant path chain
and never downloads them — the user is expected to provision them manually or
via their package manager.

M2 adds the full config surface so operators can:

1. Override discovery with explicit paths (`mmdb-path`, `asn-path`, `geosite-path`).
2. Point to alternative download URLs instead of the defaults.
3. Enable background auto-update on a configurable interval.

## M1 state (no action required — document only)

In M1 mihomo-rust discovers each DB file at runtime in order:

| DB | Discovery chain (tried in order, first found wins) |
|----|-----------------------------------------------------|
| GeoIP MMDB | `$XDG_CONFIG_HOME/mihomo/Country.mmdb` → `$HOME/.config/mihomo/Country.mmdb` → `./mihomo/Country.mmdb` |
| ASN MMDB | `$XDG_CONFIG_HOME/mihomo/GeoLite2-ASN.mmdb` → `$HOME/.config/mihomo/GeoLite2-ASN.mmdb` → `./mihomo/GeoLite2-ASN.mmdb` |
| Geosite | `$XDG_CONFIG_HOME/mihomo/geosite.mrs` → `$HOME/.config/mihomo/geosite.mrs` → `./mihomo/geosite.mrs` |

If a DB is absent, any rule requiring it returns an error at rule-match time
(not at parse time), matching the error-at-use behaviour described in
`rules-parser-completion.md` §GEOIP and `rule-geosite.md` §GEOSITE.

No auto-update, no `geodata:` YAML key, no explicit-path override in M1.

## Planned M2 YAML surface

```yaml
geodata:
  # Path overrides — skip file-discovery for that DB
  mmdb-path: /etc/mihomo/Country.mmdb        # optional
  asn-path: /etc/mihomo/GeoLite2-ASN.mmdb   # optional
  geosite-path: /etc/mihomo/geosite.mrs      # optional

  # Auto-update
  auto-update: false            # default: false
  auto-update-interval: 24      # hours; ignored when auto-update: false

  # Download URLs (used when auto-update: true and file absent/stale)
  url:
    mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country.mmdb"
    asn: "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb"
    geosite: "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.mrs"
```

Field reference:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `mmdb-path` | string | — | Explicit path to GeoIP MMDB. Skips discovery chain. |
| `asn-path` | string | — | Explicit path to ASN MMDB. Skips discovery chain. |
| `geosite-path` | string | — | Explicit path to geosite `.mrs` file. Skips discovery chain. |
| `auto-update` | bool | `false` | If true, background task checks for stale DBs and re-downloads. |
| `auto-update-interval` | u32 | `24` | Hours between update checks. Minimum: 1. Maximum: 168 (7 days). |
| `url.mmdb` | string | *(default above)* | Download URL for Country.mmdb. |
| `url.asn` | string | *(default above)* | Download URL for GeoLite2-ASN.mmdb. |
| `url.geosite` | string | *(default above)* | Download URL for geosite.mrs. |

**Fields absent from upstream that we intentionally omit:**

| Upstream field | Reason omitted |
|----------------|----------------|
| `geodata-mode` | Go mihomo supports `.dat` (V2Ray binary) and `.mmdb`. We use mmdb for GeoIP/ASN and `.mrs` for geosite — no mode switch needed. |
| `geodata-loader` | Go-specific memory-vs-speed tradeoff for `.dat` loader. Not applicable. |
| `geoip-matcher` | Go-specific (`succinct` vs `aho-corasick`). We use our own trie. |

## Internal design

### Path resolution

```
fn resolve_db_path(explicit: Option<&str>, discovery: &[&str]) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(PathBuf::from(p));   // explicit wins, even if file absent
    }
    discovery.iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}
```

Explicit path override is accepted even if the file does not yet exist
(auto-update may download it before first use). Absence at first-use
is a runtime error, not a parse-time error.

### Auto-update task

Spawned once at startup when `auto-update: true`. Wakes every
`auto-update-interval` hours, downloads each configured URL, writes
to a temp file, and atomically replaces the live file via `rename(2)`.
Hot-reload of the in-memory DB follows (the DB is wrapped in `Arc<RwLock<_>>`
so readers continue with the old version until the write completes).

Download failure: log `warn!` and retry next interval. Do NOT abort
the update task or panic.

## Divergences from upstream (classified per ADR-0002)

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | `geodata-mode` / `geodata-loader` / `geoip-matcher` — present in upstream | B | Fields are silently ignored if present (forward-compat). Warn-once at parse time with names of ignored fields. |
| 2 | Auto-update download failure — upstream logs and continues | — | We match: warn! and retry next interval. Not an error. |
| 3 | Explicit path to absent file — upstream rejects at parse time | A | We accept at parse time; error at first use. Supports auto-update provisioning the file before first rule match. |

## Acceptance criteria

1. With no `geodata:` subsection, file-discovery chain runs as in M1.
2. `mmdb-path` set → discovery chain skipped; explicit path used.
3. `mmdb-path` absent file + GEOIP rule → error at first rule match, not at parse.
4. `auto-update: true` → background task spawned; after `auto-update-interval`
   hours, updated DB loaded without restart.
5. Download failure → `warn!` logged, retry next interval, no crash.
6. `url.mmdb` override → auto-update uses custom URL.
7. Upstream-only fields (`geodata-mode`, `geodata-loader`) → parsed without
   error, `warn!` logged once per field.
8. `auto-update-interval: 0` → hard parse error ("minimum is 1 hour").

## Implementation checklist (engineer handoff — M2)

- [ ] Add `GeoDataConfig` struct to `mihomo-config` for the `geodata:` subsection.
- [ ] Update `resolve_db_path()` in `mihomo-rules` and `mihomo-dns` to accept
      optional explicit path before discovery chain.
- [ ] Spawn auto-update task in `main.rs` when `auto-update: true`; wrap each
      DB in `Arc<RwLock<_>>` if not already.
- [ ] Implement atomic file replace (`tempfile` + `rename`).
- [ ] Warn-once on unrecognised `geodata.*` fields.

## Open questions (for architect review)

1. Should `mmdb-path`/`asn-path`/`geosite-path` be top-level (`geoip-db: ...`)
   or nested under `geodata:` as sketched? Top-level matches upstream's scatter;
   nested is cleaner for our config structure.
2. Format of download URLs: should we use the MetaCubeX defaults above or
   defer URL defaults to a later decision (user must provide `url.*` when
   `auto-update: true`)?
3. Should auto-update also update rule-set files referenced by `rule-providers`?
   If yes, that spec (`rule-provider-upgrade.md`) should cross-reference this one.
