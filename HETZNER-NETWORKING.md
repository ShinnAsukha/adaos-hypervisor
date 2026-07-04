# OXware + Hetzner Ağ Kurulumu (Dedicated Sunucu)

Hetzner dedicated sunucularda ağ modeli standart bir switch'ten farklıdır. Bu
rehber, OXware VM'lerinin Hetzner ek IP'leri ve subnet'leri ile sorunsuz
çalışması için gerekenleri anlatır.

> **TL;DR:** Hetzner IP'yi çoğu zaman VM'in kendi subnet'i **dışında** bir gateway
> ile verir → netplan'da `on-link: true` şart. Tek ek IP'ler için Hetzner Robot'ta
> **Separate MAC** oluşturun. OXware v2.8.x+ netplan'ı otomatik `on-link` üretir.

---

## 1. Neden "farklı gateway kabul etmiyor"?

Hetzner ek tek IP'yi genelde `/32` olarak verir ve gateway farklı bir `/24`'tedir.
Örnek:

| | Değer |
|-|-------|
| VM IP | `5.6.7.8/32` |
| Gateway | `5.6.7.1` (VM'in `/32` subnet'inde **değil**) |

Klasik `gateway4:` yapılandırması bu gateway'i "unreachable" sayıp default
route'u atar → VM'in interneti yoktur. Çözüm **on-link route**:

```yaml
network:
  version: 2
  ethernets:
    eth0:                       # kendi arayüz adın: `ip a`
      dhcp4: false
      addresses: [5.6.7.8/32]   # Hetzner'ın verdiği IP
      routes:
        - to: default
          via: 5.6.7.1          # Hetzner panelindeki gateway
          on-link: true         # ← KRİTİK: subnet dışı gateway'i kabul ettirir
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
```

```bash
sudo netplan apply
```

**OXware v2.8.x ve üzeri** bunu otomatik üretir — panelden statik IP + gateway
girmen yeterli. Eski sürümdeysen güncelle:

```bash
cd /opt/oxware && git fetch origin main && git reset --hard origin/main
/opt/oxware/venv/bin/pip install -r oxware/backend/requirements.txt -q
systemctl restart oxware
```

---

## 2. Tek ek IP → Separate MAC (Hetzner Robot)

Hetzner switch'leri **kayıtsız MAC adreslerini düşürür**. Bir VM'e Hetzner'ın ek
tek IP'sini verecekseniz, o IP için Robot'ta ayrı bir MAC üretip VM'i o MAC ile
açmalısınız:

1. **Hetzner Robot → Server → IPs** → ilgili ek IP → **Separate MAC** → *Generate MAC*.
2. OXware'de VM'in ağ arayüzüne bu MAC'i verin
   (VM → Donanım → Ağ Arayüzü → MAC = Hetzner'ın verdiği MAC).
3. VM içinde on-link netplan (yukarıdaki blok) ile IP'yi statikle.

> Separate MAC olmadan bridged VM trafiği Hetzner tarafından sessizce düşürülür —
> route doğru olsa bile ping gitmez.

---

## 3. Subnet (routed) — birden çok IP

Hetzner ek **subnet**'i (ör. `/29`, `/28`) ana sunucu IP'nize **route eder**;
ayrı MAC gerekmez. İki kurulum yolu:

### 3a. Routed / NAT (önerilen — en dayanıklı)
Host router olur; VM'ler iç köprüde (oxbr0), host subnet'i onlara yönlendirir.
- Host'ta IP forwarding aç:
  ```bash
  echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-oxware.conf
  sudo sysctl --system
  ```
- OXware'de ağ modu **NAT** veya **Routed** seçin (Ağ → Mod). Panel gerisini
  (dnsmasq/route) halleder.
- VM public IP istiyorsa: subnet IP'sini VM'e verin, gateway = host'un iç köprü IP'si.

### 3b. Bridge (yalnızca Separate MAC ile)
Subnet'i doğrudan bridge'e verecekseniz her IP için Separate MAC gerekir (bkz. §2).
Genelde routed setup daha az sorunludur — bridge'i sadece MAC kaydı yaptıysanız kullanın.

---

## 4. IPv6

Hetzner `/64` IPv6 subnet verir. VM'de:
```yaml
      addresses: [2a01:4f8:xxxx::2/64]
      routes:
        - to: default
          via: fe80::1              # Hetzner IPv6 gateway (link-local)
          on-link: true
```
Gateway `fe80::1` link-local'dir; `on-link: true` burada da gerekir.

---

## 5. Sorun giderme — belirtiye göre

| Belirti | Olası neden | Çözüm |
|---------|-------------|-------|
| `netplan apply` hata / default route yok | subnet dışı gateway, on-link yok | §1 on-link route |
| Route var ama ping/trafik yok | Hetzner MAC filtresi | §2 Separate MAC |
| Sadece host'a ping var, dışarı yok | ip_forward kapalı / gateway yanlış | §3a `ip_forward=1`, gateway'i doğrula |
| Panelde IP yanlış/host IP görünüyor | Bridge modda libvirt lease yok | guest-agent kur; ya da NAT/Routed moda geç |
| VM açılışta IP almıyor | cloud-init network-config yok | OXware'de statik IP alanlarını doldur (v2.8.x+) |

Kontrol komutları (VM içinde):
```bash
ip a                 # arayüz adı + IP
ip route             # 'default via <gw>' satırı olmalı
ping -c2 <gateway>   # gateway'e erişim
ping -c2 1.1.1.1     # dışarı
```

---

## 6. Özet

1. OXware v2.8.x+ güncelle → netplan otomatik `on-link`.
2. Tek ek IP → Robot'ta **Separate MAC** + VM'e ata.
3. Subnet → **NAT/Routed** mod (host route eder) en pratiği.
4. Sorun sürerse §5 tablosundan belirtiyi eşle.

Takıldığın yerde `ip a` + `ip route` çıktısı ve Hetzner'ın verdiği IP/gateway/MAC
bilgisiyle bize yaz.
