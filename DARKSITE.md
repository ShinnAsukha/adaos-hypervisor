# OXware Dark Site Mode — Offline / Air-Gapped Çalışma

**Amaç:** İnternetsiz kurumların (kamu, savunma, banka, izole VDS, endüstriyel
OT ağları) OXware'i **tek anahtarla** tam offline çalıştırması.

Dark Site Mode, [egress lockdown](EGRESS.md) katmanının üstüne kurulan bir **niyet
katmanıdır**: "bu kurulum internetsiz" dediğinizde, dışarı konuşan tüm yolları tek
noktadan kapatır.

---

## Açtığınızda ne olur

| Bileşen | Dark Site ON |
|---------|--------------|
| **Egress guard** | `enforce`'a **zorlanır** (config `monitor`/`off` dese bile override) — tüm public çıkış bloklu |
| **App Marketplace** | Uzak index/indirme kapalı → bundled uygulamalar + yerel mirror |
| **Cloud image / template prefetch** | Uzak indirme kapalı → önbellek + yerel mirror (cache'teki imajlar çalışır) |
| **Updater** | Egress enforce olduğu için zaten susar (`is_offline`) |
| **Telemetri** | Egress enforce olduğu için zaten susar |

Yani tek `enabled = true` → kanıtlanabilir tam offline. Zorlama socket
seviyesinde (`egress_guard`), bu yüzden yanlışlıkla eklenmiş bir çağrı bile çıkamaz.

---

## Yapılandırma

`/etc/oxware/oxware.conf`:
```ini
[darksite]
enabled    = true                      ; tam offline mod
mirror_dir = /var/lib/oxware/mirror    ; offline paket/imaj yansı dizini
```

Env karşılıkları (öncelikli — systemd/konteyner):
`OXWARE_DARK_SITE=1`, `OXWARE_MIRROR_DIR=/var/lib/oxware/mirror`.

> Dark Site açıkken egress modu **enforce**'a sabitlenir. Yerel ağ (LAN) trafiği
> (SSH/LDAP/libvirt/node/DHCP) her zaman çalışır — sadece public internet kapalıdır.
> Belirli bir dış host'a izin gerekiyorsa `[egress] allow` listesini kullanın
> (bkz. [EGRESS.md](EGRESS.md)); ama tam dark-site'ta amaç sıfır dış çıkıştır.

---

## Durum / UI

`GET /api/security/egress` (admin) → egress guard + dark site durumunu birlikte döner:
```json
{
  "egress":    { "installed": true, "mode": "enforce", "allow_hosts": [], ... },
  "dark_site": { "enabled": true, "mirror_dir": "/var/lib/oxware/mirror",
                 "effects": { "egress": "enforce (forced)", "app_marketplace": "offline (bundled+mirror)", ... } }
}
```
UI bu endpoint'i banner için kullanır ("🔒 Dark Site — Offline").

---

## Yerel mirror (offline besleme)

Dark site'ta uzak fetch kapalıdır; paket/imaj ihtiyacı `mirror_dir`'den karşılanır:
- **App Marketplace:** bundled uygulamalar her zaman gelir; ek uygulamalar için
  tarball'ları `mirror_dir`'e koyup app URL'sini yerel dosya yoluna ayarlayın.
- **Cloud image:** golden image'ları vm_manager önbelleğine önceden yerleştirin
  (internetli bir makinede `prefetch` → cache dizinini kopyalayın).

---

## Doğrulama

```bash
# Modülü tek başına test et:
OXWARE_DARK_SITE=1 python oxware/backend/dark_site.py
# -> {"enabled": true, "effects": {"egress": "enforce (forced)", ...}}

# Canlı: egress denetim logunda bloklanan çıkışları izle
tail -f /var/log/oxware/egress.jsonl
```

Dark Site + `egress.jsonl` = internetsiz kuruma "hiçbir veri dışarı çıkmadı"
denetim kanıtı.
