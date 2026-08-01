# Provisioning Tenant İzolasyonu

`/api/provision/*` uçları (WHMCS / WiseCP / HostBill / Blesta modüllerinin
kullandığı API) `X-API-Key` ile kimlik doğruluyor — ama **anahtarın kimin olduğu
hedef VM ile karşılaştırılmıyordu.**

## Kapatılan açık

Bayi A'nın anahtarı, müşteri B'nin VM UUID'sini bilirse (ya da denerse) şunları
yapabiliyordu:

| Uç | Sonuç |
|---|---|
| `DELETE /api/provision/<vm_id>` | Başka müşterinin VM'ini **siler** (disk dahil) |
| `POST .../reinstall` | Diski **uçurur**, yeniden kurar |
| `GET .../credentials` | Vault'taki **root/SSH şifresini okur** |
| `POST .../console-token` | 5 dakikalık **noVNC konsol linki** üretir (tam klavye) |
| `.../start,stop,reboot,resize,assign-ip` | Kesinti / kaynak değişikliği |

## Nasıl çalışıyor

`provision_owner.py` bir `vm_id → owner` kaydı tutar
(`/var/lib/oxware/provision_owners.json`, `0600`).

- `POST /api/provision/create` → VM'i oluşturan anahtarın sahibi kaydedilir.
- Her `/api/provision/<vm_id>/...` çağrısı → `_require_provision_key(vm_id)`
  sahipliği doğrular; eşleşmezse **403**.
- `DELETE` → kayıt da temizlenir.

## Geçiş politikası (yükseltmede kimse kırılmaz)

| Durum | Davranış |
|---|---|
| Sahibi kayıtlı VM, anahtar eşleşiyor | ✅ izin |
| Sahibi kayıtlı VM, **başka** anahtar | ⛔ 403 — asıl düzeltme |
| Sahibi kayıtlı **olmayan** VM (yükseltmeden önce oluşturulmuş) | ✅ izin + uyarı logu |
| `all` iznine sahip anahtar (ana operatör paneli) | ✅ her zaman izin |

Yani yükseltmeden sonra **mevcut entegrasyonlar çalışmaya devam eder**; yeni
oluşturulan her VM otomatik korunur.

## Tam sıkılaştırma

Eski VM'lerin sahipleri doldurulduktan sonra sahipsiz VM'lere erişimi de kesin:

```ini
[provision]
enforce_owner = true
```
veya `OXWARE_PROVISION_ENFORCE_OWNER=1`.

Durum: `python oxware/backend/provision_owner.py` → izlenen VM sayısı + mod.

## Aynı turda kapatılan diğer erişim açıkları

- `GET/POST/DELETE /api/vms/<id>/credentials[/<type>]` — cleartext guest şifresi
  döndürüyordu, sadece `@require_auth` vardı (yani `viewer` de okuyabiliyordu).
  Artık `admin`/`operator`.
- SocketIO `vnc_proxy_connect` — yalnızca token'ın **varlığına** bakıyordu, rol
  kontrolü yoktu; `viewer` herhangi bir VM'in konsolunda tam klavye/fare
  erişimi alabiliyordu. Artık `/ws/vnc` middleware'iyle aynı kapı (operator+)
  ve iptal edilmiş oturum kontrolü.
