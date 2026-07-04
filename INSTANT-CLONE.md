# OXware Instant Clone (memory-fork)

VMware Instant Clone benzeri — bir klon, kaynağın **çalışan bellek durumundan**
saniyeler içinde ayağa kalkar (boot yok). Linked clone yalnızca diski COW
paylaşır ve klon sıfırdan boot eder; instant clone RAM'i de forklar.

## Nasıl çalışır (virsh + qemu-img)

1. Kaynak VM çalışıyor olmalı.
2. `virsh save` → kaynağın RAM'i dosyaya alınır (kaynak **kısa süre duraklar**).
3. Her klon için:
   - dosya-tabanlı disklerin COW overlay'i (backing = kaynak disk),
   - memory-state dosyasının kopyası,
   - save-image XML'i düzenlenir (name / uuid / mac / disk yolları),
   - `virsh save-image-define` + `virsh restore` → klon RAM'den ayağa kalkar,
   - `virsh define` ile kalıcılaştırılır.
4. `virsh restore` → kaynak kaldığı yerden devam eder.

## Endpoint'ler
| İşlem | Endpoint |
|-------|----------|
| Instant clone üret | `POST /api/vms/<vm_id>/instant-clone` `{prefix, count}` |
| Durum | `GET /api/instant-clone/status` |

`count` 1–64. Klonlar `<prefix>-1`, `<prefix>-2`, … olarak adlandırılır; her
birinin yeni UUID + rastgele MAC'i olur.

## Linked clone ile fark
| | Linked Clone | Instant Clone |
|-|--------------|---------------|
| Disk | COW paylaşımlı | COW paylaşımlı |
| RAM | — (sıfırdan boot) | fork (çalışan durumdan) |
| Hazır olma | boot süresi | **saniyeler** |

## Dürüstlük / sınırlar (durum: experimental)
- Kaynak, `virsh save` sırasında **kısa süre duraklar** — VMware vmfork gibi
  tam-canlı (kesintisiz) değildir.
- Linux + KVM + libvirt + `qemu-img` gerektirir; diğer ortamlarda güvenli hata döner.
- Gerçek KVM host'unda uçtan-uca test edilmelidir; ağ çakışmalarına dikkat
  (aynı IP/hostname'li N klon — cloud-init/DHCP ile ayrıştırın).
- Başarısızlıkta oluşturulan disk/mem dosyaları otomatik temizlenir; kaynak
  `finally` bloğunda her hâlükârda geri yüklenir.
