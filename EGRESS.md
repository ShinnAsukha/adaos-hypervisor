# OXware Egress Lockdown — Dışa-Çıkış Güvenliği

**Amaç:** OXware host'undan **izinsiz hiçbir bilginin dışarı çıkmaması**. Güvenlik
tamamen içeride; internete açılan her nokta ya kapalı ya da açık allowlist arkasında.

Bu, hava-boşluklu (air-gapped) / KVKK-VDS kurulumları için tasarlanmıştır. Varsayılan
duruş: **loopback + özel ağlara izin, public internete deny**.

---

## Mimari — iki katman

### Katman 1 — Merkezi Egress Guard (`oxware/backend/egress_guard.py`)
Socket seviyesinde tek chokepoint. `requests` / `urllib` / `boto3` / `ldap3` /
`paramiko` / `anthropic` SDK — hepsi eninde sonunda `socket.connect()` çağırdığı için
**tek noktadan** denetlenir. `app.py`'de eventlet/flask import edilmeden **önce**
kurulur; böylece eventlet yeşil socket'leri de korumalı primitifler üzerine biner.

- **Her zaman izinli:** loopback (127/8, ::1), RFC1918 (10/8, 172.16/12, 192.168/16),
  link-local (169.254/16, fe80::/10), ULA (fc00::/7), CGNAT/Tailscale (100.64/10),
  multicast, AF_UNIX (libvirt `qemu:///system`). → Hipervizör'ün LAN üzerindeki
  SSH/LDAP/libvirt/node trafiği asla kırılmaz.
- **Public internet:** allowlist'te değilse **reddedilir** + audit'e yazılır.

### Katman 2 — Per-feature offline sertliği
OXware-origin phone-home'lar guard'a ek olarak proaktif kendini kapatır (guard enforce
iken hiç deneme yapmaz, gürültü/log kirliliği olmaz):
- `telemetry_collector.send_once()` → `egress-offline` ile atlar.
- `updater.check_updates()` → uzak kontrolü atlar, açık hata mesajı döner.

---

## Yapılandırma

`/etc/oxware/oxware.conf`:
```ini
[egress]
mode          = monitor        ; monitor (VARSAYILAN, loglar/bloklamaz) | enforce | off
allow_private = true           ; loopback+özel ağlara her zaman izin
allow         =                ; virgülle: hostname son-eki VEYA CIDR
audit         = true           ; reddedilen/izinli-dış -> log_dir/egress.jsonl
```

Örnek — sadece kendi güncelleme repo'suna ve zorunlu bir yansıya izin:
```ini
[egress]
mode  = enforce
allow = github.com, api.github.com, 203.0.113.0/24
```

**Env karşılıkları** (config'ten öncelikli — systemd/konteyner için):
`OXWARE_EGRESS_MODE`, `OXWARE_EGRESS_ALLOW`, `OXWARE_EGRESS_ALLOW_PRIVATE`,
`OXWARE_EGRESS_AUDIT`, `OXWARE_LOG_DIR`.

### Modlar
| Mod | Davranış | Ne zaman |
|-----|----------|----------|
| `monitor` | Bloklama, **sadece logla** | **VARSAYILAN** — güncelleme/marketplace/SSO gibi giden çağrıları kırmaz; neyin dışarı gittiğini gör |
| `enforce` | Dışarıyı **blokla** + logla | Bilinçli kilit; giden çağrılar için `allow` gerekir. Dark Site açıkken otomatik |
| `off` | Guard devre dışı | Sadece geliştirme |

> **Neden default enforce değil?** enforce out-of-box tüm giden çağrıları (güncelleme
> kontrolü, marketplace, SSO, bildirim) allowlist olmadan bloklar — mevcut kurulumlarda
> güncelleme sistemi dâhil özellikleri sessizce kırar. Bu yüzden default `monitor`;
> tam kilit için bilinçli `enforce` veya Dark Site.

**Önerilen açış:** önce `monitor` ile birkaç gün çalıştır → `egress.jsonl`'i incele →
gereken host'ları `allow`'a ekle → `enforce`'a al.

---

## Egress envanteri (denetim: 2026-07-03)

Aşağıdaki tüm noktalar Katman 1 guard'ı tarafından yönetilir. "Dokunulmadı" =
kod değişmedi (kullanıcı kararı: AI ve admin-entegrasyonları elleme), ama guard
enforce modunda hepsi allowlist'siz **bloklanır**.

### OXware-origin (ürünün kendi phone-home'ları)
| Nokta | Dosya | Hedef | Varsayılan | Katman 2 |
|-------|-------|-------|-----------|----------|
| Telemetri | `telemetry_collector.py`, `telemetry/collector.py` | telemetry.oxware.top | KAPALI (opt-in) | ✅ offline-hard |
| Brand canary | `brand_integrity.py` | telemetri ile gider | telemetri kapalıysa gitmez | guard bloklar |
| Güncelleyici | `updater.py` | github/ShinnAsukha | auto_check=false | ✅ offline-hard |
| Marketplace | `app_marketplace.py` | oxware.top | aktif | guard bloklar |
| Bildirim akışı | `notifications.py` | raw.githubusercontent.com | aktif | guard bloklar |
| Hız testi | `app.py` | turkcell/linode/cloudflare | aktif | guard bloklar |
| Paket kurucu | `cloudflare_tunnel_manager.py`, `app.py` | plesk/cyberpanel/coollabs | admin tetikli | guard bloklar |

### AI (kullanıcı kararı: **dokunulmadı**)
| Nokta | Dosya | Hedef | Not |
|-------|-------|-------|-----|
| AI agent | `ai_agent.py`, `app.py` | api.anthropic.com / api.openai.com / openrouter.ai / **localhost** | Kod değişmedi. Guard enforce'ta harici LLM bloklanır. AI istiyorsan ya endpoint'i `localhost` (Ollama) yap ya da ilgili host'u `allow`'a ekle. |

### Admin-yapılandırmalı entegrasyonlar (kullanıcı kararı: **dokunulmadı, belgele**)
| Entegrasyon | Dosya | Hedef | Not |
|-------------|-------|-------|-----|
| SSO / OAuth | `oauth2_sso.py`, `sso_manager.py`, `oauth2_presets.py` | google / microsoft / github / gitlab | Doğası gereği dış. İstenirse `allow`'a ekle. |
| ChatOps | `chatops.py`, `notifications.py` | api.telegram.org | Kullanmak için `api.telegram.org` allowlist'e. |
| SIEM export | `siem_exporter.py` | admin-config | Harici SIEM'e log akıtır — bilinçli allowlist gerekir. |
| Webhook | `webhook_manager.py` | admin-config | Giden webhook; allowlist gerekir. |
| Vault | `vault_integration.py` | admin-config | Harici vault ise allowlist gerekir. |
| Geo-DNS | `geo_dns_manager.py` | api.cloudflare.com | Cloudflare DNS API. |
| Cloud export | `cloud_export.py` | aws/azure/gcp | OVA/imaj dışa aktarımı. |

> `ova_export.py`, `boot_splash.py` içindeki URL'ler XML namespace / şema; ağ çağrısı
> **değil**. Frontend JS zaten yerel (`oxware/frontend/static/`), CDN kullanmaz.

---

## Doğrulama / kanıt

```bash
# Guard'ı tek başına test et:
python oxware/backend/egress_guard.py example.com     # -> BLOKLANDI (beklenen)

# Canlı sistemde reddedilenleri izle:
tail -f /var/log/oxware/egress.jsonl
# {"ts":..., "decision":"block", "reason":"external-denied", "host":"...", "ip":"...", ...}
```

`egress.jsonl` = "dışarı hiçbir bilgi çıkmadı" için denetlenebilir kanıt.
Her `block` kaydı, engellenmiş bir dış bağlantı denemesidir.
