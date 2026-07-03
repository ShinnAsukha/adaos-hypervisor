# OXware GPU Passthrough Wizard

Tam-GPU **VFIO passthrough**'u (bir GPU → tek VM, tam performans) rehberli hale
getirir. Kullanıcı IOMMU / VFIO / kernel parametre / ACS override ile elle
uğraşmaz.

> Paylaşımlı vGPU (bir GPU → N VM, NVIDIA GRID/MIG mdev) için ayrı özellik var:
> `vgpu_manager` + `/api/vgpu/*`. Bu wizard TAM GPU'yu tek VM'e verir.

---

## Wizard akışı (6 adım)

| Adım | Endpoint | Ne yapar |
|------|----------|----------|
| 1. Genel bakış | `GET /api/gpu/wizard/overview` | IOMMU durumu + passthrough'a uygun GPU'lar (grup/sürücü/ses fonksiyonu ile) |
| 2. Preflight | `GET /api/gpu/wizard/preflight/<pci>` | Hazır mı? Her kontrol pass/fail + düzeltme ipucu |
| 3. Plan | `GET /api/gpu/wizard/plan/<pci>` | Otomatik remediation: kernel cmdline, modprobe, initramfs, reboot |
| 4. Bind | `POST /api/gpu/wizard/bind/<pci>` | GPU'yu canlı vfio-pci'ye bağla (reboot'suz, mümkünse) |
| 5. Attach | `POST /api/vms/<vm>/gpu/attach` `{pci, with_audio}` | GPU + ses fonksiyonunu VM'e `<hostdev>` PCI olarak ekle |
| 6. Detach | `POST /api/vms/<vm>/gpu/detach` `{pci}` | GPU'yu VM'den çıkar |

Hepsi `admin` rolü ister.

---

## Otomatik çözdüğü acılar

- **IOMMU tespiti** — CPU vendor'a göre (`intel_iommu=on` / `amd_iommu=on iommu=pt`)
  doğru kernel cmdline'ı üretir; `/proc/cmdline` ve `/sys/kernel/iommu_groups`'u okur.
- **IOMMU grup temizliği** — GPU'nun grubunda başka aygıt varsa (ACS sorunu) uyarır;
  güvenli çözümü (başka PCIe slotu) önerir, `pcie_acs_override`'ın **güvenlik riski**
  olduğunu açıkça belirtir (üretimde önermez).
- **Ses fonksiyonu** — GPU'nun HDMI ses aygıtını (ör. `65:00.1`) otomatik bulur ve
  GPU ile birlikte bind/attach eder (yoksa ses/çökme sorunları olur).
- **vfio-pci bağlama** — `/etc/modprobe.d/vfio-oxware.conf` içeriğini (`ids=`,
  `softdep`) üretir; mümkünse canlı `new_id`/`bind` ile reboot'suz bağlar.

---

## Örnek: preflight çıktısı

```json
{
  "pci": "0000:65:00.0", "ready": false,
  "gpu": { "name": "NVIDIA ... [10de:2204]", "iommu_group": "34",
           "audio_companion": "0000:65:00.1", "group_clean": true },
  "checks": [
    {"id": "iommu_enabled", "ok": false, "severity": "critical",
     "msg": "IOMMU KAPALI", "fix": "Kernel cmdline'a intel_iommu=on iommu=pt ekleyin, reboot."},
    {"id": "iommu_group_clean", "ok": true, "severity": "critical", "msg": "IOMMU grubu temiz"}
  ]
}
```

`ready=true` olduğunda bind → attach → VM başlat. Linux + root + libvirt gerektirir;
diğer ortamlarda güvenli/boş döner (çökmez).
