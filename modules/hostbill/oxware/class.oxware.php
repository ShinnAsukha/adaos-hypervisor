<?php
/**
 * OXware Hypervisor — HostBill Server Module v1.0.0 (beta)
 *
 * Kurulum:
 *   Bu dizini HostBill'de includes/modules/Server/oxware/ altına kopyalayın.
 *   Admin → Settings → Modules → Hosting Modules → OXware → Activate.
 *   Server ekle: Host = OXware API URL, Hash/Password = OXware API key (oxw_...).
 *
 * OXware REST API'sini (WHMCS modülüyle aynı /api/provision/* uçları,
 * X-API-Key başlığı) kullanır. Çekirdek yaşam döngüsü: Create / Suspend /
 * Unsuspend / Terminate / ChangePackage + TestConnection + istemci durumu.
 *
 * NOT (dürüstlük): Gerçek bir HostBill kurulumunda entegrasyon testi gerekir;
 * durum = beta. API sözleşmesi WHMCS modülüyle birebir aynıdır.
 */

if (!defined('HBADMIN') && !defined('HBCLIENT') && !defined('HBEXEC')) {
    die('Bu dosya doğrudan çalıştırılamaz.');
}

class oxware extends ServerModule
{
    protected $modname     = 'OXware Hypervisor';
    protected $description = 'OXware KVM Hypervisor otomasyonu — VM oluştur/askıya al/sil, resize, console';
    protected $version     = '1.0.0';

    /** Ürün/paket yapılandırma alanları */
    public function getOptions()
    {
        return [
            'vCPU'        => ['value' => '2',            'type' => 'input', 'description' => 'Sanal CPU (1-256)'],
            'RAM_MB'      => ['value' => '2048',         'type' => 'input', 'description' => 'Bellek (MB)'],
            'Disk_GB'     => ['value' => '50',           'type' => 'input', 'description' => 'Disk (GB)'],
            'OS_Template' => ['value' => 'ubuntu-22.04', 'type' => 'input', 'description' => 'OXware template ID'],
            'Network'     => ['value' => 'default',      'type' => 'input', 'description' => 'Libvirt ağ adı'],
            'IP_Pool'     => ['value' => '',             'type' => 'input', 'description' => 'IP havuzu (boş=atama yok)'],
            'SSL'         => ['value' => '',             'type' => 'input', 'description' => 'boş=sistem CA, "skip"=self-signed, /path/ca.crt'],
        ];
    }

    // ── OXware REST çağrısı ──────────────────────────────────────────────────
    private function api($method, $endpoint, $body = null)
    {
        $base = rtrim($this->options['hostname'] ?? $this->getHost(), '/');
        $key  = trim($this->options['hash'] ?? $this->options['password'] ?? '');

        $ssl  = strtolower(trim($this->getOption('SSL') ?? ''));
        $skip = in_array($ssl, ['skip', '0', 'false', 'no'], true);
        $ca   = '';
        if (!$skip) {
            if ($ssl && file_exists($ssl)) {
                $ca = $ssl;
            } else {
                foreach (['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt'] as $f) {
                    if (file_exists($f)) { $ca = $f; break; }
                }
            }
        }

        $ch = curl_init($base . '/api' . $endpoint);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_CUSTOMREQUEST  => strtoupper($method),
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'X-API-Key: ' . $key],
            CURLOPT_SSL_VERIFYPEER => !$skip,
            CURLOPT_SSL_VERIFYHOST => $skip ? 0 : 2,
        ];
        if ($ca) { $opts[CURLOPT_CAINFO] = $ca; }
        curl_setopt_array($ch, $opts);
        if ($body !== null) { curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body)); }

        $raw  = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);

        if ($raw === false)  { return ['error' => 'cURL: ' . $err]; }
        $data = json_decode($raw, true);
        if ($code >= 400)    { return ['error' => ($data['error'] ?? "HTTP $code")]; }
        return $data ?? [];
    }

    private function validVmId($id)
    {
        return (bool)preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $id);
    }

    private function vmId()
    {
        // VM ID, Create sırasında servisin username alanına yazılır.
        return $this->details['username'] ?? '';
    }

    private function randPassword($len = 20)
    {
        $chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $out = '';
        for ($i = 0; $i < $len; $i++) { $out .= $chars[random_int(0, strlen($chars) - 1)]; }
        return $out;
    }

    private function randName()
    {
        $adj = ['fast','blue','dark','iron','nova','star','bold','pure','cool','free'];
        $nou = ['wolf','hawk','lion','bear','fox','owl','ray','arc','oak','sky'];
        return $adj[random_int(0, 9)] . '-' . $nou[random_int(0, 9)] . '-' . bin2hex(random_bytes(3));
    }

    // ── Yaşam döngüsü ─────────────────────────────────────────────────────────
    public function Create()
    {
        $pass = $this->randPassword();
        $body = [
            'name'        => $this->randName(),
            'vcpus'       => (int)$this->getOption('vCPU'),
            'memory_mb'   => (int)$this->getOption('RAM_MB'),
            'disk_gb'     => (int)$this->getOption('Disk_GB'),
            'os_template' => $this->getOption('OS_Template'),
            'network'     => $this->getOption('Network'),
            'auto_start'  => true,
            'username'    => 'root',
            'password'    => $pass,
        ];
        $pool = trim($this->getOption('IP_Pool'));
        if ($pool) { $body['ip_pool'] = $pool; }

        $r = $this->api('POST', '/provision/create', $body);
        if (!empty($r['error'])) { return $this->AddError('Create', $r['error']); }

        $vm   = $r['vm'] ?? [];
        $vmId = $vm['id'] ?? ($r['vm_id'] ?? '');
        $ip   = $vm['ip'] ?? ($vm['networks'][0]['ip'] ?? '');
        if (!$vmId) { return $this->AddError('Create', 'VM ID alınamadı'); }

        // VM ID + şifre + IP servise yaz
        $this->setDetails(['username' => $vmId, 'password' => $pass] + ($ip ? ['ip' => $ip] : []));
        return true;
    }

    public function Suspend()
    {
        $id = $this->vmId();
        if (!$id || !$this->validVmId($id)) { return $this->AddError('Suspend', 'Geçersiz VM ID'); }
        $r = $this->api('POST', "/provision/$id/suspend");
        return empty($r['error']) ? true : $this->AddError('Suspend', $r['error']);
    }

    public function Unsuspend()
    {
        $id = $this->vmId();
        if (!$id || !$this->validVmId($id)) { return $this->AddError('Unsuspend', 'Geçersiz VM ID'); }
        $r = $this->api('POST', "/provision/$id/unsuspend");
        return empty($r['error']) ? true : $this->AddError('Unsuspend', $r['error']);
    }

    public function Terminate()
    {
        $id = $this->vmId();
        if (!$id) { return true; } // zaten yok
        if (!$this->validVmId($id)) { return $this->AddError('Terminate', 'Geçersiz VM ID'); }
        $r = $this->api('DELETE', "/provision/$id");
        return empty($r['error']) ? true : $this->AddError('Terminate', $r['error']);
    }

    public function ChangePackage()
    {
        $id = $this->vmId();
        if (!$id || !$this->validVmId($id)) { return $this->AddError('ChangePackage', 'Geçersiz VM ID'); }
        $r = $this->api('PUT', "/provision/$id/resize", [
            'vcpus'     => (int)$this->getOption('vCPU'),
            'memory_mb' => (int)$this->getOption('RAM_MB'),
            'disk_gb'   => (int)$this->getOption('Disk_GB'),
        ]);
        return empty($r['error']) ? true : $this->AddError('ChangePackage', $r['error']);
    }

    public function TestConnection()
    {
        $r = $this->api('GET', '/provision/ping');
        return empty($r['error']) ? true : $this->AddError('TestConnection', $r['error']);
    }

    // ── İstemci alanı: canlı durum ────────────────────────────────────────────
    public function getStatus()
    {
        $id = $this->vmId();
        if (!$id) { return []; }
        $s = $this->api('GET', "/provision/$id/status");
        return empty($s['error']) ? $s : [];
    }

    // ── Client tuş işlemleri ──────────────────────────────────────────────────
    public function StartVM()   { return $this->power('start'); }
    public function StopVM()    { return $this->power('stop'); }
    public function RebootVM()  { return $this->power('reboot'); }

    private function power($action)
    {
        $id = $this->vmId();
        if (!$id || !$this->validVmId($id)) { return $this->AddError('power', 'Geçersiz VM ID'); }
        $r = $this->api('POST', "/provision/$id/$action");
        return empty($r['error']) ? true : $this->AddError('power', $r['error']);
    }
}
