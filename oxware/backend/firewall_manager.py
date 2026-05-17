"""
firewall_manager.py — nftables kural yönetimi (OXware Hypervisor)
Root yetkisi gerekir.
"""

import subprocess
import json
import logging
import re
import threading

log = logging.getLogger("oxware.firewall")
_lock = threading.Lock()

# ---------------------------------------------------------------------------
# İç yardımcılar
# ---------------------------------------------------------------------------

def _run(*cmd):
    """subprocess.run ile komutu çalıştırır; stdout+stderr döner, hata fırlatmaz."""
    try:
        result = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            log.warning("Komut başarısız [%d]: %s | stderr: %s",
                        result.returncode, " ".join(cmd), result.stderr.strip())
        return result
    except FileNotFoundError:
        log.error("nft bulunamadı. nftables kurulu mu?")
        return None
    except Exception as exc:
        log.exception("_run hatası: %s", exc)
        return None


def _nft_json():
    """nft -j list ruleset çalıştırır; başarısızsa None döner."""
    result = _run("nft", "-j", "list", "ruleset")
    if result is None or result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        log.warning("JSON parse hatası: %s", exc)
        return None

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_status():
    """nftables'ın aktif olup olmadığını ve toplam kural sayısını döner."""
    try:
        result = _run("nft", "list", "ruleset")
        if result is None:
            return {"active": False, "available": False, "error": "nft bulunamadı"}

        active = result.returncode == 0
        rule_count = 0
        if active:
            rule_count = result.stdout.count("rule ")

        return {
            "active": active,
            "available": active,
            "rule_count": rule_count,
            "returncode": result.returncode,
        }
    except Exception as exc:
        log.exception("get_status hatası: %s", exc)
        return {"active": False, "available": False, "error": str(exc)}


def list_rules():
    """
    Tüm kuralları listeler.
    Önce JSON parse dener; başarısızsa text parse yapar.
    Dönüş: [{"table":..., "chain":..., "handle":..., "expr":...}, ...]
    """
    with _lock:
        data = _nft_json()
        rules = []

        if data:
            try:
                for item in data.get("nftables", []):
                    rule = item.get("rule")
                    if rule:
                        rules.append({
                            "table": rule.get("table", ""),
                            "chain": rule.get("chain", ""),
                            "handle": rule.get("handle"),
                            "family": rule.get("family", ""),
                            "expr": rule.get("expr", []),
                        })
                return rules
            except Exception as exc:
                log.warning("JSON parse sonrası kural çıkarma hatası: %s", exc)

        # Fallback: text parse
        try:
            result = _run("nft", "list", "ruleset")
            if result is None or result.returncode != 0:
                return []

            current_table = ""
            current_chain = ""
            for line in result.stdout.splitlines():
                line = line.strip()
                m_table = re.match(r"table (\w+) (\w+) \{", line)
                if m_table:
                    current_table = f"{m_table.group(1)} {m_table.group(2)}"
                    continue
                m_chain = re.match(r"chain (\w+) \{", line)
                if m_chain:
                    current_chain = m_chain.group(1)
                    continue
                m_handle = re.search(r"# handle (\d+)", line)
                if m_handle and line and not line.startswith("#"):
                    rules.append({
                        "table": current_table,
                        "chain": current_chain,
                        "handle": int(m_handle.group(1)),
                        "expr": line,
                    })
        except Exception as exc:
            log.exception("text parse hatası: %s", exc)

        return rules


def list_chains():
    """
    Tüm chain'leri listeler.
    Dönüş: [{"table":..., "name":..., "type":..., "hook":..., "policy":...}, ...]
    """
    with _lock:
        chains = []
        data = _nft_json()

        if data:
            try:
                for item in data.get("nftables", []):
                    chain = item.get("chain")
                    if chain:
                        chains.append({
                            "table": chain.get("table", ""),
                            "family": chain.get("family", ""),
                            "name": chain.get("name", ""),
                            "type": chain.get("type", ""),
                            "hook": chain.get("hook", ""),
                            "policy": chain.get("policy", ""),
                            "prio": chain.get("prio"),
                        })
                return chains
            except Exception as exc:
                log.warning("JSON chain parse hatası: %s", exc)

        # Fallback: text parse
        try:
            result = _run("nft", "list", "ruleset")
            if result is None:
                return []
            current_table = ""
            for line in result.stdout.splitlines():
                line = line.strip()
                m_table = re.match(r"table (\w+) (\w+) \{", line)
                if m_table:
                    current_table = f"{m_table.group(1)} {m_table.group(2)}"
                    continue
                m_chain = re.match(r"chain (\w+) \{", line)
                if m_chain:
                    chains.append({"table": current_table, "name": m_chain.group(1)})
        except Exception as exc:
            log.exception("text chain parse hatası: %s", exc)

        return chains


def add_rule(table, chain, protocol=None, src_ip=None, dst_ip=None,
             dst_port=None, action="accept", comment=""):
    """
    nftables'a kural ekler.
    Örnek: add_rule("inet filter", "input", protocol="tcp", dst_port=80, action="accept")
    """
    with _lock:
        parts = ["nft", "add", "rule"] + table.split() + [chain]

        if protocol:
            parts += [protocol]
        if src_ip:
            parts += ["ip", "saddr", src_ip]
        if dst_ip:
            parts += ["ip", "daddr", dst_ip]
        if dst_port:
            proto = protocol or "tcp"
            parts += [proto, "dport", str(dst_port)]

        parts += [action]

        if comment:
            parts += ["comment", f'"{comment}"']

        log.info("Kural ekleniyor: %s", " ".join(parts))
        result = _run(*parts)
        if result is None:
            return {"success": False, "error": "nft bulunamadı"}
        return {
            "success": result.returncode == 0,
            "stderr": result.stderr.strip(),
        }


def delete_rule(table, chain, handle):
    """Belirtilen handle numarasına sahip kuralı siler."""
    with _lock:
        log.info("Kural siliniyor: %s %s handle %s", table, chain, handle)
        result = _run("nft", "delete", "rule", *table.split(), chain, "handle", str(handle))
        if result is None:
            return {"success": False, "error": "nft bulunamadı"}
        return {
            "success": result.returncode == 0,
            "stderr": result.stderr.strip(),
        }


def add_chain(table, chain_name, type_="filter", hook=None, priority=0, policy="accept"):
    """
    Yeni chain oluşturur.
    Örnek: add_chain("inet filter", "my_chain", hook="input", priority=0)
    """
    with _lock:
        # Önce chain'i oluştur
        result = _run("nft", "add", "chain", *table.split(), chain_name)
        if result is None:
            return {"success": False, "error": "nft bulunamadı"}
        if result.returncode != 0:
            return {"success": False, "stderr": result.stderr.strip()}

        # Hook varsa type/hook/priority/policy ayarla
        if hook:
            expr = f"type {type_} hook {hook} priority {priority}; policy {policy};"
            result2 = _run("nft", "add", "chain", *table.split(), chain_name,
                           "{", expr, "}")
            if result2 and result2.returncode != 0:
                log.warning("Chain hook ayarı başarısız: %s", result2.stderr.strip())

        log.info("Chain oluşturuldu: %s / %s", table, chain_name)
        return {"success": True}


def delete_chain(table, chain_name):
    """Chain'i siler."""
    with _lock:
        log.info("Chain siliniyor: %s / %s", table, chain_name)
        result = _run("nft", "delete", "chain", *table.split(), chain_name)
        if result is None:
            return {"success": False, "error": "nft bulunamadı"}
        return {
            "success": result.returncode == 0,
            "stderr": result.stderr.strip(),
        }


def flush_chain(table, chain):
    """Chain içindeki tüm kuralları temizler."""
    with _lock:
        log.info("Chain temizleniyor: %s / %s", table, chain)
        result = _run("nft", "flush", "chain", *table.split(), chain)
        if result is None:
            return {"success": False, "error": "nft bulunamadı"}
        return {
            "success": result.returncode == 0,
            "stderr": result.stderr.strip(),
        }


def save_ruleset(path="/etc/nftables.conf"):
    """Mevcut kural setini dosyaya kaydeder."""
    with _lock:
        log.info("Ruleset kaydediliyor: %s", path)
        try:
            result = _run("nft", "list", "ruleset")
            if result is None or result.returncode != 0:
                return {"success": False, "error": "ruleset okunamadı"}
            with open(path, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            return {"success": True, "path": path}
        except OSError as exc:
            log.error("Dosya yazma hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def restore_ruleset(path="/etc/nftables.conf"):
    """Kural setini dosyadan geri yükler."""
    with _lock:
        log.info("Ruleset geri yükleniyor: %s", path)
        result = _run("nft", "-f", path)
        if result is None:
            return {"success": False, "error": "nft bulunamadı"}
        return {
            "success": result.returncode == 0,
            "stderr": result.stderr.strip(),
        }


def get_default_policy(chain):
    """Belirtilen chain'in varsayılan policy'sini döner."""
    try:
        chains = list_chains()
        for c in chains:
            if c.get("name") == chain:
                return c.get("policy", "unknown")
        return "not_found"
    except Exception as exc:
        log.exception("get_default_policy hatası: %s", exc)
        return "error"


def set_default_policy(table, chain, policy):
    """Chain'in varsayılan policy'sini değiştirir (accept / drop)."""
    with _lock:
        if policy not in ("accept", "drop"):
            return {"success": False, "error": "Geçersiz policy (accept/drop)"}
        log.info("Policy ayarlanıyor: %s/%s -> %s", table, chain, policy)
        result = _run("nft", "chain", *table.split(), chain,
                      "{", f"policy {policy};", "}")
        if result is None:
            return {"success": False, "error": "nft bulunamadı"}
        return {
            "success": result.returncode == 0,
            "stderr": result.stderr.strip(),
        }
