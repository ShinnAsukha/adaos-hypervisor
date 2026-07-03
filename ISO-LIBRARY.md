# OXware ISO Library

Mevcut ISO yönetimi (upload/list/delete) üstüne **resmi kaynaktan indir → SHA256
doğrula → mirror seç** katmanı. İndirilenler `config.ISO_DIR`'e yazılır, mevcut
ISO listesinde otomatik görünür (ayrı depo yok).

> Cloud-init golden image'ları (Ubuntu/Debian/Rocky/Alma qcow2) BURADA DEĞİL —
> onlar `template_marketplace` + `/api/vgpu`... hayır, `catalog()` (cloud image
> marketplace). Burası **kurulum ISO'ları**: Linux dağıtımları + firewall/NAS
> appliance'ları + Windows Server eval.

---

## Katalog (v2.8.5)

| Kategori | ISO'lar |
|----------|---------|
| linux | Ubuntu Server 24.04 LTS, Debian 12 netinst, Rocky 9 minimal, AlmaLinux 9 minimal |
| appliance | pfSense CE, OPNsense, TrueNAS SCALE |
| windows | Windows Server 2022 (eval) |

Her giriş: çoklu mirror + (varsa) `sha256` veya yayıncı `SHA256SUMS` URL'si.

---

## Endpoint'ler

| İşlem | Endpoint |
|-------|----------|
| Katalog + indirme durumu | `GET /api/storage/iso-library` |
| Katalogdan indir | `POST /api/storage/iso-library/download` `{id, mirror}` |
| Yereldeki ISO'yu doğrula | `POST /api/storage/isos/<name>/verify` `{sha256?}` |

İndirme `admin`/`operator`, arka planda çalışır: `.part` dosyasına indirir →
SHA256 doğrular (biliniyorsa) → atomik `os.replace` ile yerine koyar. Bir mirror
başarısızsa **sıradaki mirror'a otomatik geçer**; hepsi başarısızsa hata.

## Checksum politikası
- Katalogda sabit `sha256` varsa onunla; yoksa yayıncının `SHA256SUMS`/`CHECKSUM`
  dosyasından ilgili dosya adının hash'i online iken çekilir.
- **Yanlış hash göndermemek için** bilinmeyen sabit hash'ler boş bırakılır;
  doğrulanamıyorsa indirilen dosya kabul edilir ama `verified=false` işaretlenir.
- `verify` endpoint'i elle `sha256` de kabul eder (offline doğrulama).

## Dark Site Mode
[Dark Site](DARKSITE.md) açıkken uzak indirme reddedilir; yerel mirror'daki
ISO'lar (upload edilmiş) kullanılmaya devam eder.
