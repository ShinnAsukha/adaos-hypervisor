"""
AdaOS Güncelleme Sistemi
─────────────────────────
GitHub üzerinden otomatik güncelleme:
  - Uzak repo ile yerel commit karşılaştırması
  - Yeni dosyaları ve değişiklikleri listele
  - git pull ile uygula, servisi yeniden başlat
"""

import os
import json
import subprocess
import requests
import logging
import time
from datetime import datetime

log = logging.getLogger("oxware.updater")

UPDATE_CONFIG_FILE = os.environ.get("OXWARE_UPDATE_CONFIG", "/etc/oxware/update.conf")
UPDATE_LOG_FILE    = os.path.join(os.environ.get("OXWARE_LOG_DIR", "/var/log/oxware"), "updates.jsonl")

# ── Konfigürasyon ─────────────────────────────────────────────────────────────

def _load_config() -> dict:
    defaults = {
        "repo_url":   "",       # https://github.com/user/repo
        "branch":     "main",
        "auto_check": "false",
        "project_dir": _detect_project_dir(),
    }
    if not os.path.exists(UPDATE_CONFIG_FILE):
        return defaults
    try:
        cfg = {}
        for line in open(UPDATE_CONFIG_FILE):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip().lower()] = v.strip()
        return {**defaults, **cfg}
    except Exception:
        return defaults


def save_config(repo_url: str, branch: str = "main", auto_check: bool = False):
    os.makedirs(os.path.dirname(UPDATE_CONFIG_FILE), exist_ok=True)
    lines = [
        "# OXware Güncelleme Yapılandırması",
        f"REPO_URL   = {repo_url}",
        f"BRANCH     = {branch}",
        f"AUTO_CHECK = {'true' if auto_check else 'false'}",
        f"PROJECT_DIR = {_detect_project_dir()}",
    ]
    with open(UPDATE_CONFIG_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(UPDATE_CONFIG_FILE, 0o600)


def _detect_project_dir() -> str:
    """AdaOS proje kök dizinini bul."""
    this_file = os.path.abspath(__file__)
    # backend/updater.py → AdaOS/
    return os.path.dirname(os.path.dirname(os.path.dirname(this_file)))


# ── Git İşlemleri ─────────────────────────────────────────────────────────────

def _run(cmd: list, cwd: str = None) -> tuple[int, str, str]:
    """Komutu çalıştır, (returncode, stdout, stderr) döndür."""
    try:
        r = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=60
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Zaman aşımı"
    except Exception as e:
        return -1, "", str(e)


def _is_git_repo(path: str) -> bool:
    code, _, _ = _run(["git", "rev-parse", "--is-inside-work-tree"], cwd=path)
    return code == 0


def _local_commit(path: str) -> str:
    _, out, _ = _run(["git", "rev-parse", "HEAD"], cwd=path)
    return out[:40] if out else ""


def _local_branch(path: str) -> str:
    _, out, _ = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=path)
    return out or "main"


def _ensure_remote(path: str, repo_url: str):
    """Remote 'origin' yoksa ekle, varsa güncelle."""
    code, out, _ = _run(["git", "remote", "get-url", "origin"], cwd=path)
    if code != 0:
        _run(["git", "remote", "add", "origin", repo_url], cwd=path)
    elif out != repo_url:
        _run(["git", "remote", "set-url", "origin", repo_url], cwd=path)


def _init_repo_if_needed(path: str, repo_url: str, branch: str):
    """Git repo yoksa başlat ve remote bağla."""
    if not _is_git_repo(path):
        _run(["git", "init", "-b", branch], cwd=path)
        _run(["git", "remote", "add", "origin", repo_url], cwd=path)
    else:
        _ensure_remote(path, repo_url)


# ── GitHub API ────────────────────────────────────────────────────────────────

def _github_api_url(repo_url: str) -> str:
    """https://github.com/user/repo → https://api.github.com/repos/user/repo"""
    url = repo_url.rstrip("/").replace("https://github.com/", "")
    url = url.replace("http://github.com/", "")
    if url.endswith(".git"):
        url = url[:-4]
    return f"https://api.github.com/repos/{url}"


def _get_remote_commits(repo_url: str, branch: str, limit: int = 20) -> list:
    """GitHub API üzerinden son commit'leri çek."""
    api_url = _github_api_url(repo_url) + f"/commits?sha={branch}&per_page={limit}"
    try:
        r = requests.get(api_url, timeout=10, headers={"Accept": "application/vnd.github.v3+json"})
        if r.status_code == 200:
            commits = r.json()
            return [
                {
                    "sha":     c["sha"][:8],
                    "sha_full": c["sha"],
                    "message": c["commit"]["message"].split("\n")[0][:100],
                    "author":  c["commit"]["author"]["name"],
                    "date":    c["commit"]["author"]["date"],
                }
                for c in commits
            ]
        elif r.status_code == 404:
            return []
        else:
            log.warning("GitHub API yanıtı: %s", r.status_code)
            return []
    except Exception as e:
        log.error("GitHub API hatası: %s", e)
        return []


def _get_remote_head(repo_url: str, branch: str) -> str:
    """GitHub API üzerinden en son commit SHA'sını al."""
    commits = _get_remote_commits(repo_url, branch, limit=1)
    return commits[0]["sha_full"] if commits else ""


# ── Ana Fonksiyonlar ──────────────────────────────────────────────────────────

def check_updates() -> dict:
    """
    Güncelleme kontrolü yap.
    Dönüş: {up_to_date, current_sha, remote_sha, new_commits, error}
    """
    cfg = _load_config()
    repo_url = cfg.get("repo_url", "")
    branch   = cfg.get("branch", "main")
    proj_dir = cfg.get("project_dir", _detect_project_dir())

    if not repo_url:
        return {"error": "Repo URL ayarlanmamış. Ayarlar → Güncellemeler bölümünden girin."}

    # Yerel commit
    local_sha = ""
    if _is_git_repo(proj_dir):
        local_sha = _local_commit(proj_dir)

    # Uzak commit'leri çek
    remote_commits = _get_remote_commits(repo_url, branch)
    if not remote_commits:
        return {"error": "GitHub'a bağlanılamadı veya repo bulunamadı."}

    remote_sha = remote_commits[0]["sha_full"]

    # Yeni commit'leri bul
    new_commits = []
    if local_sha:
        for c in remote_commits:
            if c["sha_full"].startswith(local_sha[:8]) or local_sha.startswith(c["sha_full"][:8]):
                break
            new_commits.append(c)
    else:
        new_commits = remote_commits

    return {
        "up_to_date":     len(new_commits) == 0,
        "current_sha":    local_sha[:8] if local_sha else "bilinmiyor",
        "remote_sha":     remote_sha[:8],
        "new_commits":    new_commits,
        "new_count":      len(new_commits),
        "repo_url":       repo_url,
        "branch":         branch,
        "checked_at":     datetime.now().isoformat(),
    }


def apply_update() -> dict:
    """
    Güncellemeyi uygula: git pull çek, servisi yeniden başlat.
    """
    cfg      = _load_config()
    repo_url = cfg.get("repo_url", "")
    branch   = cfg.get("branch", "main")
    proj_dir = cfg.get("project_dir", _detect_project_dir())

    if not repo_url:
        return {"success": False, "error": "Repo URL ayarlanmamış."}

    log.info("Güncelleme başlatılıyor: %s @ %s", repo_url, branch)
    steps = []

    try:
        # 1. Git repo yoksa başlat
        _init_repo_if_needed(proj_dir, repo_url, branch)
        steps.append({"step": "repo_init", "status": "ok"})

        # 2. Fetch
        code, out, err = _run(["git", "fetch", "origin", branch], cwd=proj_dir)
        if code != 0:
            return {"success": False, "error": f"git fetch başarısız: {err}", "steps": steps}
        steps.append({"step": "fetch", "status": "ok"})

        # 3. Mevcut SHA
        old_sha = _local_commit(proj_dir)

        # 4. Reset — yerel değişiklikleri atla, uzak branch'e zorla al
        code, out, err = _run(
            ["git", "reset", "--hard", f"origin/{branch}"], cwd=proj_dir
        )
        if code != 0:
            return {"success": False, "error": f"git reset başarısız: {err}", "steps": steps}
        steps.append({"step": "reset", "status": "ok"})

        # 5. Yeni SHA
        new_sha = _local_commit(proj_dir)
        steps.append({"step": "update", "status": "ok", "old_sha": old_sha[:8], "new_sha": new_sha[:8]})

        # 6. Python bağımlılıkları güncelle
        venv_pip = "/opt/oxware/venv/bin/pip"
        req_file = os.path.join(proj_dir, "oxware", "backend", "requirements.txt")
        if os.path.exists(venv_pip) and os.path.exists(req_file):
            code, out, err = _run([venv_pip, "install", "-r", req_file, "-q"], cwd=proj_dir)
            steps.append({"step": "pip_install", "status": "ok" if code == 0 else "warning", "detail": err[:200] if err else ""})

        # 7. Güncelleme loguna kaydet
        _log_update(old_sha, new_sha, repo_url, branch, steps)

        # 8. Servisi arka planda yeniden başlat (5 sn gecikme → yanıt dönebilsin)
        def _restart():
            time.sleep(5)
            subprocess.run(["systemctl", "restart", "oxware"], timeout=30)

        import threading
        threading.Thread(target=_restart, daemon=True).start()
        steps.append({"step": "restart_scheduled", "status": "ok"})

        return {
            "success":  True,
            "old_sha":  old_sha[:8] if old_sha else "—",
            "new_sha":  new_sha[:8],
            "steps":    steps,
            "message":  "Güncelleme uygulandı. Servis 5 saniye içinde yeniden başlayacak.",
        }

    except Exception as e:
        log.error("Güncelleme hatası: %s", e)
        return {"success": False, "error": str(e), "steps": steps}


def get_update_history(limit: int = 20) -> list:
    """Geçmiş güncelleme kayıtlarını döndür."""
    if not os.path.exists(UPDATE_LOG_FILE):
        return []
    entries = []
    with open(UPDATE_LOG_FILE) as f:
        for line in f:
            try:
                entries.append(json.loads(line.strip()))
            except Exception:
                pass
    return sorted(entries, key=lambda x: x.get("timestamp", 0), reverse=True)[:limit]


def get_config() -> dict:
    cfg = _load_config()
    return {
        "repo_url":   cfg.get("repo_url", ""),
        "branch":     cfg.get("branch", "main"),
        "auto_check": cfg.get("auto_check", "false").lower() == "true",
        "project_dir": cfg.get("project_dir", ""),
        "is_git_repo": _is_git_repo(cfg.get("project_dir", _detect_project_dir())),
        "local_sha":  _local_commit(cfg.get("project_dir", _detect_project_dir()))[:8],
    }


def _log_update(old_sha: str, new_sha: str, repo_url: str, branch: str, steps: list):
    os.makedirs(os.path.dirname(UPDATE_LOG_FILE), exist_ok=True)
    entry = {
        "timestamp": time.time(),
        "datetime":  datetime.now().isoformat(),
        "old_sha":   old_sha[:8] if old_sha else "",
        "new_sha":   new_sha[:8] if new_sha else "",
        "repo_url":  repo_url,
        "branch":    branch,
        "steps":     steps,
    }
    with open(UPDATE_LOG_FILE, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
