<?php
/**
 * OXware Hypervisor — Blesta Module v1.0.0 (beta)
 *
 * Kurulum:
 *   Bu dizini Blesta'da components/modules/oxware/ altına kopyalayın.
 *   Settings → Company → Modules → Available → OXware → Install.
 *   Module Row ekle: API URL + API Key (oxw_...).
 *
 * OXware REST API'sini (WHMCS/HostBill modülleriyle aynı /api/provision/*,
 * X-API-Key) kullanır. Yaşam döngüsü: addService / suspend / unsuspend /
 * cancel / changeServicePackage.
 *
 * NOT (dürüstlük): Gerçek bir Blesta kurulumunda entegrasyon testi gerekir;
 * durum = beta.
 */

class Oxware extends Module
{
    public function __construct()
    {
        Language::loadLang('oxware', null, dirname(__FILE__) . DS . 'language' . DS);
        $this->loadConfig(dirname(__FILE__) . DS . 'config.json');
    }

    public function getName()    { return Language::_('Oxware.name', true); }
    public function getVersion() { return '1.0.0'; }
    public function getAuthors()
    {
        return [['name' => 'Ada Gürsoy', 'url' => 'https://github.com/ShinnAsukha/oxware-hypervisor']];
    }

    // ── Module Row (sunucu bağlantısı) alanları ───────────────────────────────
    public function getModuleRowFields()
    {
        $fields = new ModuleFields();
        $fields->label(Language::_('Oxware.row.api_url', true), 'api_url');
        $fields->setField($fields->fieldText('api_url', null,
            ['id' => 'api_url', 'placeholder' => 'https://oxware.example.com']));
        $fields->label(Language::_('Oxware.row.api_key', true), 'api_key');
        $fields->setField($fields->fieldText('api_key', null,
            ['id' => 'api_key', 'placeholder' => 'oxw_...']));
        return $fields;
    }

    public function getRowMeta($vars)
    {
        return [
            ['key' => 'api_url', 'value' => $vars['api_url'] ?? '', 'encrypted' => 0],
            ['key' => 'api_key', 'value' => $vars['api_key'] ?? '', 'encrypted' => 1],
        ];
    }

    // ── Paket (ürün) alanları ─────────────────────────────────────────────────
    public function getPackageFields($vars = null)
    {
        $fields = new ModuleFields();
        foreach ([
            'vcpus'       => ['OXware.package.vcpus', '2'],
            'memory_mb'   => ['OXware.package.memory', '2048'],
            'disk_gb'     => ['OXware.package.disk', '50'],
            'os_template' => ['OXware.package.os', 'ubuntu-22.04'],
            'network'     => ['OXware.package.network', 'default'],
            'ip_pool'     => ['OXware.package.ip_pool', ''],
        ] as $k => $meta) {
            $fields->label(Language::_($meta[0], true), $k);
            $fields->setField($fields->fieldText("meta[$k]",
                $vars->meta[$k] ?? $meta[1], ['id' => $k]));
        }
        return $fields;
    }

    // ── OXware REST çağrısı ───────────────────────────────────────────────────
    private function api($row, $method, $endpoint, $body = null)
    {
        $base = rtrim($row->meta->api_url ?? '', '/');
        $key  = $row->meta->api_key ?? '';

        $ch = curl_init($base . '/api' . $endpoint);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_CUSTOMREQUEST  => strtoupper($method),
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'X-API-Key: ' . $key],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ];
        curl_setopt_array($ch, $opts);
        if ($body !== null) { curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body)); }

        $raw  = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);

        if ($raw === false) { return ['error' => 'cURL: ' . $err]; }
        $data = json_decode($raw, true);
        if ($code >= 400)   { return ['error' => ($data['error'] ?? "HTTP $code")]; }
        return $data ?? [];
    }

    private function pkgVal($package, $key, $default = '')
    {
        foreach (($package->meta ?? []) as $k => $v) {
            if ($k === $key) { return $v; }
        }
        return $default;
    }

    private function svcVmId($service)
    {
        foreach (($service->fields ?? []) as $f) {
            if ($f->key === 'oxware_vm_id') { return $f->value; }
        }
        return '';
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

    // ── addService (VM oluştur) ───────────────────────────────────────────────
    public function addService($package, array $vars = null, $parent_package = null,
                               $parent_service = null, $status = 'pending')
    {
        $row = $this->getModuleRow();
        if (!$row) { $this->Input->setErrors(['module_row' => ['missing' => 'Module row yok']]); return; }
        if ($status !== 'active') { return []; }   // sadece aktifleşince oluştur

        $pass = $this->randPassword();
        $body = [
            'name'        => $this->randName(),
            'vcpus'       => (int)$this->pkgVal($package, 'vcpus', 2),
            'memory_mb'   => (int)$this->pkgVal($package, 'memory_mb', 2048),
            'disk_gb'     => (int)$this->pkgVal($package, 'disk_gb', 50),
            'os_template' => $this->pkgVal($package, 'os_template', 'ubuntu-22.04'),
            'network'     => $this->pkgVal($package, 'network', 'default'),
            'auto_start'  => true,
            'username'    => 'root',
            'password'    => $pass,
        ];
        $pool = trim($this->pkgVal($package, 'ip_pool', ''));
        if ($pool) { $body['ip_pool'] = $pool; }

        $r = $this->api($row, 'POST', '/provision/create', $body);
        if (!empty($r['error'])) {
            $this->Input->setErrors(['api' => ['create' => $r['error']]]);
            return;
        }
        $vm   = $r['vm'] ?? [];
        $vmId = $vm['id'] ?? ($r['vm_id'] ?? '');
        $ip   = $vm['ip'] ?? ($vm['networks'][0]['ip'] ?? '');
        if (!$vmId) {
            $this->Input->setErrors(['api' => ['create' => 'VM ID alınamadı']]);
            return;
        }

        return [
            ['key' => 'oxware_vm_id',   'value' => $vmId, 'encrypted' => 0],
            ['key' => 'oxware_root_pw', 'value' => $pass, 'encrypted' => 1],
            ['key' => 'oxware_ip',      'value' => $ip,   'encrypted' => 0],
        ];
    }

    public function suspendService($package, $service, $parent_package = null, $parent_service = null)
    {
        $r = $this->lifecycle($service, 'POST', '/suspend');
        if (!empty($r['error'])) { $this->Input->setErrors(['api' => ['suspend' => $r['error']]]); }
        return null;
    }

    public function unsuspendService($package, $service, $parent_package = null, $parent_service = null)
    {
        $r = $this->lifecycle($service, 'POST', '/unsuspend');
        if (!empty($r['error'])) { $this->Input->setErrors(['api' => ['unsuspend' => $r['error']]]); }
        return null;
    }

    public function cancelService($package, $service, $parent_package = null, $parent_service = null)
    {
        $id = $this->svcVmId($service);
        if (!$id) { return null; }
        $r = $this->api($this->getModuleRow(), 'DELETE', "/provision/$id");
        if (!empty($r['error'])) { $this->Input->setErrors(['api' => ['cancel' => $r['error']]]); }
        return null;
    }

    public function changeServicePackage($package_from, $package_to, $service,
                                         $parent_package = null, $parent_service = null)
    {
        $id = $this->svcVmId($service);
        if (!$id) { return null; }
        $r = $this->api($this->getModuleRow(), 'PUT', "/provision/$id/resize", [
            'vcpus'     => (int)$this->pkgVal($package_to, 'vcpus', 2),
            'memory_mb' => (int)$this->pkgVal($package_to, 'memory_mb', 2048),
            'disk_gb'   => (int)$this->pkgVal($package_to, 'disk_gb', 50),
        ]);
        if (!empty($r['error'])) { $this->Input->setErrors(['api' => ['resize' => $r['error']]]); }
        return null;
    }

    private function lifecycle($service, $method, $suffix)
    {
        $id = $this->svcVmId($service);
        if (!$id) { return ['error' => 'VM ID yok']; }
        return $this->api($this->getModuleRow(), $method, "/provision/$id" . $suffix);
    }
}
