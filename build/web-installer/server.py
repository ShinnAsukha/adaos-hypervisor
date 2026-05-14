#!/usr/bin/env python3
"""OXware Web Installer — pure Python HTTP server, no external deps required."""

import http.server
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

PORT = 8888
BASE = Path(__file__).parent

# ── Shared state ──────────────────────────────────────────────────────────────
_cfg = {
    'disk': '', 'fs': 'ext4',
    'hostname': 'oxware',
    'username': 'oxadmin', 'password': '',
    'net_mode': 'dhcp', 'iface': '',
    'net_ip': '', 'net_mask': '24', 'net_gw': '', 'net_dns': '8.8.8.8',
}
_prog = {
    'pct': 0, 'msg': 'Bekleniyor…',
    'done': False, 'error': None, 'log': [],
}
_install_proc = None


def _get_disks():
    try:
        r = subprocess.run(
            ['lsblk', '-J', '-b', '-o', 'NAME,SIZE,TYPE,MODEL,TRAN'],
            capture_output=True, text=True, timeout=5)
        devs = json.loads(r.stdout).get('blockdevices', [])
        out = []
        for d in devs:
            if d.get('type') != 'disk':
                continue
            sz = int(d.get('size') or 0)
            gb = sz / 1024 ** 3
            model = (d.get('model') or 'Unknown').strip()
            tran = (d.get('tran') or '').upper()
            name = f"/dev/{d['name']}"
            label = f"{name}  ({gb:.0f} GB  ·  {model})" + (f"  [{tran}]" if tran else "")
            out.append({'name': name, 'label': label, 'gb': f"{gb:.0f}"})
        return out
    except Exception:
        return [{'name': '/dev/sda', 'label': '/dev/sda  (? GB  ·  Unknown)', 'gb': '?'}]


def _get_ifaces():
    try:
        r = subprocess.run(['ip', '-j', 'link', 'show'],
                           capture_output=True, text=True, timeout=5)
        ifaces = json.loads(r.stdout)
        skip_prefixes = ('lo', 'vir', 'docker', 'br', 'veth', 'dummy', 'tun', 'wl')
        return [i['ifname'] for i in ifaces
                if not any(i['ifname'].startswith(p) for p in skip_prefixes)]
    except Exception:
        return ['eth0', 'ens33', 'enp0s3']


def _run_install():
    global _prog, _install_proc
    cfg_file = '/tmp/oxware-install-config.json'
    with open(cfg_file, 'w') as f:
        json.dump(_cfg, f)
    _prog = {'pct': 0, 'msg': 'Kurulum başlatılıyor…',
             'done': False, 'error': None, 'log': []}
    try:
        cmd = [sys.executable, '/opt/oxware-installer/install.py', '--headless', cfg_file]
        _install_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        for line in _install_proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                _prog['pct'] = data.get('pct', _prog['pct'])
                _prog['msg'] = data.get('msg', _prog['msg'])
                _prog['log'].append(f"[{_prog['pct']}%] {_prog['msg']}")
                if data.get('error'):
                    _prog['error'] = data['error']
                    _prog['done'] = True
                    return
                if data.get('done'):
                    _prog['done'] = True
                    return
            except json.JSONDecodeError:
                _prog['log'].append(line)
        _install_proc.wait()
        if _install_proc.returncode != 0:
            _prog['error'] = f"Kurulum hata koduyla çıktı: {_install_proc.returncode}"
        _prog['done'] = True
    except Exception as e:
        _prog['error'] = str(e)
        _prog['done'] = True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        pass

    def _json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _file(self, relpath, mime):
        p = BASE / relpath
        try:
            data = p.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        routes = {
            '/': ('index.html', 'text/html; charset=utf-8'),
            '/style.css': ('style.css', 'text/css'),
            '/app.js': ('app.js', 'application/javascript'),
        }
        if p in routes:
            self._file(*routes[p])
        elif p == '/api/disks':
            self._json(_get_disks())
        elif p == '/api/ifaces':
            self._json(_get_ifaces())
        elif p == '/api/progress':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            last = 0
            try:
                while True:
                    d = dict(_prog)
                    d['new_logs'] = d['log'][last:]
                    last = len(d['log'])
                    self.wfile.write(f"data: {json.dumps(d)}\n\n".encode())
                    self.wfile.flush()
                    if d['done'] or d['error']:
                        break
                    time.sleep(0.4)
            except Exception:
                pass
        else:
            self.send_error(404)

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        if p == '/api/config':
            _cfg.update(body)
            self._json({'ok': True})
        elif p == '/api/start':
            _cfg.update(body)
            threading.Thread(target=_run_install, daemon=True).start()
            self._json({'ok': True})
        elif p == '/api/reboot':
            self._json({'ok': True})
            time.sleep(0.5)
            subprocess.run(['reboot'], check=False)
        else:
            self.send_error(404)


if __name__ == '__main__':
    print(f"[OXware Web Installer] http://127.0.0.1:{PORT}", flush=True)
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', PORT), Handler)
    srv.serve_forever()
