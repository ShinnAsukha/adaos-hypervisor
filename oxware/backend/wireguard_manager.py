"""
wireguard_manager.py — WireGuard VPN yönetimi (OXware Hypervisor)
Root yetkisi gerekir.
"""

import subprocess
import json
import logging
import os
import ipaddress
import threading

log = logging.getLogger("oxware.wireguard")

WG_DIR = "/etc/wireguard"
PEERS_FILE = "/var/lib/oxware/wg_peers.json"

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# İç yardımcılar
# ---------------------------------------------------------------------------

def _run(*cmd, input_data=None):
    """subprocess.run çalıştırır; hata fırlatmaz."""
    try:
        result = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input_data,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            log.warning("Komut başarısız [%d]: %s | stderr: %s",
                        result.returncode, " ".join(cmd), result.stderr.strip())
        return result
    except FileNotFoundError:
        log.error("Komut bulunamadı: %s", cmd[0])
        return None
    except Exception as exc:
        log.exception("_run hatası: %s", exc)
        return None


def _wg_conf_path(interface):
    """WireGuard config dosyası yolunu döner."""
    return os.path.join(WG_DIR, f"{interface}.conf")


def _generate_keypair():
    """(private_key, public_key) tuple döner."""
    try:
        priv_result = subprocess.run(
            ["wg", "genkey"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=True,
        )
        private_key = priv_result.stdout.strip()

        pub_result = subprocess.run(
            ["wg", "pubkey"],
            input=private_key,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=True,
        )
        public_key = pub_result.stdout.strip()
        return private_key, public_key
    except subprocess.CalledProcessError as exc:
        log.error("Keypair oluşturma hatası: %s", exc.stderr)
        raise
    except FileNotFoundError:
        log.error("wg komutu bulunamadı. WireGuard kurulu mu?")
        raise


def _load_peers():
    """PEERS_FILE'dan peer listesini yükler."""
    try:
        if not os.path.exists(PEERS_FILE):
            return {}
        with open(PEERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.error("Peers dosyası okunamadı: %s", exc)
        return {}


def _save_peers(peers):
    """Peer listesini PEERS_FILE'a kaydeder."""
    try:
        os.makedirs(os.path.dirname(PEERS_FILE), exist_ok=True)
        with open(PEERS_FILE, "w", encoding="utf-8") as f:
            json.dump(peers, f, indent=2, ensure_ascii=False)
    except OSError as exc:
        log.error("Peers dosyası yazılamadı: %s", exc)
        raise

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_status(interface="wg0"):
    """
    WireGuard arayüzünün durumunu döner.
    {"active": bool, "public_key": str, "listen_port": int, "peers": [...]}
    """
    try:
        result = _run("wg", "show", interface)
        if result is None:
            return {"active": False, "error": "wg bulunamadı"}

        if result.returncode != 0:
            return {"active": False, "interface": interface,
                    "error": result.stderr.strip()}

        info = {
            "active": True,
            "interface": interface,
            "public_key": "",
            "listen_port": None,
            "peers": [],
        }

        current_peer = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("public key:"):
                info["public_key"] = line.split(":", 1)[1].strip()
            elif line.startswith("listening port:"):
                try:
                    info["listen_port"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("peer:"):
                current_peer = {"public_key": line.split(":", 1)[1].strip(),
                                "allowed_ips": "", "endpoint": "", "latest_handshake": ""}
                info["peers"].append(current_peer)
            elif current_peer:
                if line.startswith("allowed ips:"):
                    current_peer["allowed_ips"] = line.split(":", 1)[1].strip()
                elif line.startswith("endpoint:"):
                    current_peer["endpoint"] = line.split(":", 1)[1].strip()
                elif line.startswith("latest handshake:"):
                    current_peer["latest_handshake"] = line.split(":", 1)[1].strip()

        return info
    except Exception as exc:
        log.exception("get_status hatası: %s", exc)
        return {"active": False, "error": str(exc)}


def init_server(interface="wg0", address="10.8.0.1/24", listen_port=51820):
    """
    WireGuard sunucu arayüzünü başlatır.
    Config dosyası oluşturur, arayüzü ayağa kaldırır.
    """
    with _lock:
        try:
            os.makedirs(WG_DIR, exist_ok=True)
            conf_path = _wg_conf_path(interface)

            private_key, public_key = _generate_keypair()

            # Keypair dosyalarını kaydet
            priv_path = os.path.join(WG_DIR, f"{interface}_private.key")
            pub_path = os.path.join(WG_DIR, f"{interface}_public.key")
            with open(priv_path, "w", encoding="utf-8") as f:
                f.write(private_key + "\n")
            os.chmod(priv_path, 0o600)
            with open(pub_path, "w", encoding="utf-8") as f:
                f.write(public_key + "\n")

            # wg0.conf oluştur
            conf_content = (
                f"[Interface]\n"
                f"Address = {address}\n"
                f"ListenPort = {listen_port}\n"
                f"PrivateKey = {private_key}\n"
                f"PostUp = iptables -A FORWARD -i {interface} -j ACCEPT; "
                f"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n"
                f"PostDown = iptables -D FORWARD -i {interface} -j ACCEPT; "
                f"iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n"
            )
            with open(conf_path, "w", encoding="utf-8") as f:
                f.write(conf_content)
            os.chmod(conf_path, 0o600)

            log.info("WireGuard config oluşturuldu: %s", conf_path)

            # Arayüzü ayağa kaldır
            _run("ip", "link", "add", interface, "type", "wireguard")
            _run("ip", "addr", "add", address, "dev", interface)
            _run("wg", "setconf", interface, conf_path)
            _run("ip", "link", "set", interface, "up")

            return {
                "success": True,
                "interface": interface,
                "public_key": public_key,
                "address": address,
                "listen_port": listen_port,
                "conf_path": conf_path,
            }
        except Exception as exc:
            log.exception("init_server hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def get_server_config(interface="wg0"):
    """wg0.conf dosyasının içeriğini döner."""
    try:
        conf_path = _wg_conf_path(interface)
        if not os.path.exists(conf_path):
            return {"success": False, "error": f"{conf_path} bulunamadı"}
        with open(conf_path, "r", encoding="utf-8") as f:
            content = f.read()
        return {"success": True, "content": content, "path": conf_path}
    except OSError as exc:
        log.error("Config okunamadı: %s", exc)
        return {"success": False, "error": str(exc)}


def add_peer(peer_name, allowed_ips=None, endpoint=None, interface="wg0"):
    """
    Yeni bir WireGuard peer ekler.
    Keypair oluşturur, config'e ekler ve wg set ile anında uygular.
    """
    with _lock:
        try:
            if allowed_ips is None:
                allowed_ips = "10.8.0.2/32"

            private_key, public_key = _generate_keypair()

            # Config dosyasına [Peer] bloğu ekle
            conf_path = _wg_conf_path(interface)
            peer_block = (
                f"\n[Peer]\n"
                f"# Name: {peer_name}\n"
                f"PublicKey = {public_key}\n"
                f"AllowedIPs = {allowed_ips}\n"
            )
            if endpoint:
                peer_block += f"Endpoint = {endpoint}\n"

            if os.path.exists(conf_path):
                with open(conf_path, "a", encoding="utf-8") as f:
                    f.write(peer_block)

            # wg set ile anında uygula
            wg_set_cmd = ["wg", "set", interface, "peer", public_key,
                          "allowed-ips", allowed_ips]
            if endpoint:
                wg_set_cmd += ["endpoint", endpoint]
            _run(*wg_set_cmd)

            # peers.json'a kaydet
            peers = _load_peers()
            peers[peer_name] = {
                "name": peer_name,
                "public_key": public_key,
                "private_key": private_key,
                "allowed_ips": allowed_ips,
                "endpoint": endpoint,
                "interface": interface,
            }
            _save_peers(peers)

            log.info("Peer eklendi: %s (%s)", peer_name, public_key[:16])
            return {
                "success": True,
                "peer_name": peer_name,
                "public_key": public_key,
                "allowed_ips": allowed_ips,
            }
        except Exception as exc:
            log.exception("add_peer hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def remove_peer(peer_name_or_pubkey, interface="wg0"):
    """Peer'ı arayüzden ve config dosyasından kaldırır."""
    with _lock:
        try:
            peers = _load_peers()

            # İsim mi public key mi?
            target_pubkey = None
            target_name = None
            if peer_name_or_pubkey in peers:
                target_name = peer_name_or_pubkey
                target_pubkey = peers[peer_name_or_pubkey]["public_key"]
            else:
                # public key ile ara
                for name, info in peers.items():
                    if info.get("public_key") == peer_name_or_pubkey:
                        target_name = name
                        target_pubkey = peer_name_or_pubkey
                        break

            if not target_pubkey:
                return {"success": False, "error": "Peer bulunamadı"}

            # wg set ile kaldır
            _run("wg", "set", interface, "peer", target_pubkey, "remove")

            # peers.json'dan kaldır
            if target_name:
                peers.pop(target_name, None)
                _save_peers(peers)

            log.info("Peer kaldırıldı: %s", peer_name_or_pubkey)
            return {"success": True, "removed": peer_name_or_pubkey}
        except Exception as exc:
            log.exception("remove_peer hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def list_peers(interface="wg0"):
    """
    Peer listesini döner; aktif olanları wg show ile işaretler.
    """
    try:
        peers = _load_peers()
        status = get_status(interface)
        active_keys = {p["public_key"] for p in status.get("peers", [])}

        result = []
        for name, info in peers.items():
            entry = dict(info)
            entry["active"] = info.get("public_key") in active_keys
            entry.pop("private_key", None)  # private key'i dışarı verme
            result.append(entry)

        return result
    except Exception as exc:
        log.exception("list_peers hatası: %s", exc)
        return []


def get_peer_config(peer_name, server_public_key="", server_endpoint="", interface="wg0"):
    """
    Client .conf dosyası içeriğini döner.
    """
    try:
        peers = _load_peers()
        if peer_name not in peers:
            return {"success": False, "error": "Peer bulunamadı"}

        peer = peers[peer_name]
        client_conf = (
            f"[Interface]\n"
            f"PrivateKey = {peer.get('private_key', '<PRIVATE_KEY>')}\n"
            f"Address = {peer.get('allowed_ips', '10.8.0.x/32')}\n"
            f"DNS = 1.1.1.1\n\n"
            f"[Peer]\n"
            f"PublicKey = {server_public_key}\n"
            f"Endpoint = {server_endpoint}\n"
            f"AllowedIPs = 0.0.0.0/0, ::/0\n"
            f"PersistentKeepalive = 25\n"
        )
        return {"success": True, "config": client_conf, "peer_name": peer_name}
    except Exception as exc:
        log.exception("get_peer_config hatası: %s", exc)
        return {"success": False, "error": str(exc)}


def start(interface="wg0"):
    """wg-quick up ile arayüzü başlatır."""
    log.info("WireGuard başlatılıyor: %s", interface)
    result = _run("wg-quick", "up", interface)
    if result is None:
        return {"success": False, "error": "wg-quick bulunamadı"}
    return {
        "success": result.returncode == 0,
        "stderr": result.stderr.strip(),
    }


def stop(interface="wg0"):
    """wg-quick down ile arayüzü durdurur."""
    log.info("WireGuard durduruluyor: %s", interface)
    result = _run("wg-quick", "down", interface)
    if result is None:
        return {"success": False, "error": "wg-quick bulunamadı"}
    return {
        "success": result.returncode == 0,
        "stderr": result.stderr.strip(),
    }
