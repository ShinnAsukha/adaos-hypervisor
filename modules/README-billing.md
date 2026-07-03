# OXware Billing / Provisioning Modules

OXware'i hosting otomasyon panellerine bağlayan provisioning modülleri. Hepsi
**aynı** OXware REST sözleşmesini kullanır: `/api/provision/*`, `X-API-Key`
başlığı. Böylece davranış paneller arasında birebir tutarlıdır.

| Panel | Yol | Durum |
|-------|-----|-------|
| WHMCS | `modules/whmcs/servers/oxware/` | stable (üretimde) |
| WISECP | `modules/wisecp/oxware/` | stable |
| **HostBill** | `modules/hostbill/oxware/` | **beta (yeni)** |
| **Blesta** | `modules/blesta/oxware/` | **beta (yeni)** |

## Ortak yaşam döngüsü
Create → Suspend → Unsuspend → Terminate → ChangePackage(resize) + TestConnection.
VM ID servise kaydedilir; sonraki tüm işlemler onun üzerinden gider. Create rastgele
root şifresi üretip servise (şifreli) yazar; IP havuzu verilmişse otomatik IP atar.

## Kurulum

**HostBill:** `modules/hostbill/oxware/` → HostBill `includes/modules/Server/oxware/`.
Admin → Modules → Hosting Modules → OXware → Activate. Server: Host=API URL,
Hash=API key (`oxw_...`).

**Blesta:** `modules/blesta/oxware/` → Blesta `components/modules/oxware/`.
Settings → Company → Modules → OXware → Install. Module Row: API URL + API Key.
Paket alanları: vcpus / memory_mb / disk_gb / os_template / network / ip_pool.

## Dürüstlük notu
HostBill ve Blesta modülleri **beta** — API sözleşmesi WHMCS/WISECP ile birebir
aynı ve PHP syntax'ı doğrulanmıştır, ancak gerçek bir HostBill/Blesta kurulumunda
uçtan uca entegrasyon testi yapılmalıdır. WHMCS modülü referans/kanonik implementasyondur.

## OXware API uçları (referans)
```
POST   /api/provision/create              {name,vcpus,memory_mb,disk_gb,os_template,network,auto_start,username,password,ip_pool}
POST   /api/provision/<id>/suspend|unsuspend|start|stop|reboot
DELETE /api/provision/<id>
PUT    /api/provision/<id>/resize         {vcpus,memory_mb,disk_gb}
POST   /api/provision/<id>/reinstall      {os_template}
POST   /api/provision/<id>/assign-ip      {pool}
POST   /api/provision/<id>/console-token  -> {console_url}
GET    /api/provision/<id>/status | /credentials
GET    /api/provision/ping                (API key doğrulama)
```
