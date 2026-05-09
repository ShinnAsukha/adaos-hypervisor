"""
OXware Anomaly Detector
────────────────────────
Z-score tabanlı anomali tespiti ve baseline yönetimi.
"""

import json
import logging
import math
import os
import statistics
import threading
import time
from datetime import datetime, timedelta

log = logging.getLogger("oxware.anomaly")

ANOMALIES_FILE = "/var/lib/oxware/anomalies.json"
BASELINE_FILE  = "/var/lib/oxware/baselines.json"
CONFIG_FILE    = "/var/lib/oxware/anomaly_config.json"

_lock = threading.Lock()

try:
    import perf_history as _perf
    PERF_AVAILABLE = True
except Exception:
    _perf = None
    PERF_AVAILABLE = False

try:
    import notifications as _notif
    NOTIF_AVAILABLE = True
except Exception:
    _notif = None
    NOTIF_AVAILABLE = False


# ── Yardımcı ──────────────────────────────────────────────────────────────────

def _ensure_dir(path: str):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass


def _z_score(value: float, mean: float, std: float) -> float:
    """Z-score hesapla."""
    if std > 0:
        return abs((value - mean) / std)
    return 0.0


def _load_baselines() -> dict:
    try:
        if os.path.exists(BASELINE_FILE):
            with open(BASELINE_FILE) as f:
                return json.load(f)
    except Exception as e:
        log.warning("Baseline yükleme hatası: %s", e)
    return {}


def _save_baselines(data: dict):
    _ensure_dir(BASELINE_FILE)
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log.error("Baseline kaydetme hatası: %s", e)


def _load_anomalies() -> list:
    try:
        if os.path.exists(ANOMALIES_FILE):
            with open(ANOMALIES_FILE) as f:
                return json.load(f)
    except Exception as e:
        log.warning("Anomali yükleme hatası: %s", e)
    return []


def _save_anomalies(data: list):
    _ensure_dir(ANOMALIES_FILE)
    try:
        with open(ANOMALIES_FILE, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log.error("Anomali kaydetme hatası: %s", e)


# ── Config ────────────────────────────────────────────────────────────────────

def get_config() -> dict:
    """Anomali dedektör yapılandırmasını döndür."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
            cfg.setdefault("sensitivity", 2.5)
            cfg.setdefault("enabled", True)
            cfg.setdefault("check_interval", 300)
            return cfg
    except Exception as e:
        log.warning("Config yükleme hatası: %s", e)
    return {"sensitivity": 2.5, "enabled": True, "check_interval": 300}


def update_config(
    sensitivity: float = None,
    enabled: bool = None,
    check_interval: int = None,
) -> dict:
    """Anomali dedektör yapılandırmasını güncelle."""
    try:
        cfg = get_config()
        if sensitivity is not None:
            cfg["sensitivity"] = float(sensitivity)
        if enabled is not None:
            cfg["enabled"] = bool(enabled)
        if check_interval is not None:
            cfg["check_interval"] = int(check_interval)
        _ensure_dir(CONFIG_FILE)
        with _lock:
            with open(CONFIG_FILE, "w") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
        return cfg
    except Exception as e:
        log.error("Config güncelleme hatası: %s", e)
        return {"error": str(e)}


# ── Baseline ─────────────────────────────────────────────────────────────────

def update_baseline(metric_key: str, values: list):
    """Metrik için mean ve std hesapla, baseline'a kaydet."""
    try:
        if not values or len(values) < 2:
            log.debug("Baseline için yetersiz veri: %s", metric_key)
            return
        mean = statistics.mean(values)
        std  = statistics.stdev(values)
        with _lock:
            baselines = _load_baselines()
            baselines[metric_key] = {
                "mean": mean,
                "std": std,
                "sample_count": len(values),
                "updated_at": datetime.now().isoformat(),
            }
            _save_baselines(baselines)
        log.debug("Baseline güncellendi: %s mean=%.2f std=%.2f", metric_key, mean, std)
    except Exception as e:
        log.error("update_baseline hatası (%s): %s", metric_key, e)


# ── Anomali Kontrolü ──────────────────────────────────────────────────────────

def check_metric(metric_key: str, current_value: float) -> dict:
    """Bir metrik için Z-score tabanlı anomali kontrolü yap."""
    try:
        baselines = _load_baselines()
        if metric_key not in baselines:
            return {
                "is_anomaly": False,
                "z_score": 0.0,
                "current": current_value,
                "mean": None,
                "std": None,
                "reason": "Baseline henüz yok.",
            }
        b = baselines[metric_key]
        mean = b["mean"]
        std  = b["std"]
        cfg  = get_config()
        sensitivity = cfg.get("sensitivity", 2.5)

        z = _z_score(current_value, mean, std)
        is_anomaly = z >= sensitivity

        return {
            "is_anomaly": is_anomaly,
            "z_score": round(z, 4),
            "current": current_value,
            "mean": round(mean, 4),
            "std": round(std, 4),
        }
    except Exception as e:
        log.error("check_metric hatası (%s): %s", metric_key, e)
        return {"is_anomaly": False, "z_score": 0.0, "current": current_value, "error": str(e)}


# ── Ana Tespit ────────────────────────────────────────────────────────────────

def run_detection():
    """Tüm metrikler için anomali tespiti çalıştır."""
    try:
        cfg = get_config()
        if not cfg.get("enabled", True):
            log.debug("Anomali dedektörü devre dışı.")
            return

        metrics = {}

        if PERF_AVAILABLE:
            try:
                metrics = _perf.get_latest_metrics()
            except Exception as e:
                log.debug("perf_history get_latest_metrics hatası: %s", e)

        if not metrics:
            try:
                import psutil
                metrics["system.cpu"] = psutil.cpu_percent(interval=0.5)
                metrics["system.mem"] = psutil.virtual_memory().percent
            except Exception:
                pass

        new_anomalies = []
        for key, value in metrics.items():
            try:
                result = check_metric(key, float(value))
                if result.get("is_anomaly"):
                    anomaly = {
                        "ts": datetime.now().isoformat(),
                        "metric_key": key,
                        "current_value": value,
                        "z_score": result["z_score"],
                        "mean": result["mean"],
                        "std": result["std"],
                    }
                    new_anomalies.append(anomaly)
                    log.warning(
                        "Anomali tespit edildi! %s=%.2f z=%.2f",
                        key, value, result["z_score"]
                    )
                    if NOTIF_AVAILABLE:
                        try:
                            _notif.send_alert(
                                message=f"Anomali: {key} = {value:.2f} (z-score: {result['z_score']:.2f})",
                                level="WARNING",
                                category="anomaly",
                                details={
                                    "metric": key,
                                    "value": value,
                                    "z_score": result["z_score"],
                                    "mean": result["mean"],
                                },
                            )
                        except Exception as ne:
                            log.debug("Bildirim gönderilemedi: %s", ne)
            except Exception as e:
                log.debug("Metrik kontrolü hatası (%s): %s", key, e)

        if new_anomalies:
            with _lock:
                existing = _load_anomalies()
                existing.extend(new_anomalies)
                _save_anomalies(existing)

        # Baseline güncelle
        for key, value in metrics.items():
            try:
                baselines = _load_baselines()
                if key in baselines:
                    # Exponential moving average benzeri: mevcut değeri listeye ekle, son 100'ü tut
                    b = baselines[key]
                    sample = b.get("_samples", [b["mean"]] * min(b.get("sample_count", 10), 100))
                    sample.append(float(value))
                    sample = sample[-100:]
                    update_baseline(key, sample)
                else:
                    update_baseline(key, [float(value)])
            except Exception:
                pass

    except Exception as e:
        log.error("run_detection hatası: %s", e)


def get_anomalies(limit: int = 50, vm_id: str = None) -> list:
    """Kaydedilmiş anomalileri döndür."""
    try:
        with _lock:
            anomalies = _load_anomalies()
        if vm_id:
            anomalies = [a for a in anomalies if vm_id in a.get("metric_key", "")]
        return list(reversed(anomalies))[:limit]
    except Exception as e:
        log.error("get_anomalies hatası: %s", e)
        return []


def get_summary() -> dict:
    """Anomali özeti döndür."""
    try:
        with _lock:
            anomalies = _load_anomalies()
        now = datetime.now()
        cutoff = (now - timedelta(hours=24)).isoformat()
        last_24h = [a for a in anomalies if a.get("ts", "") >= cutoff]

        by_metric: dict = {}
        for a in anomalies:
            key = a.get("metric_key", "unknown")
            by_metric[key] = by_metric.get(key, 0) + 1

        return {
            "total": len(anomalies),
            "last_24h": len(last_24h),
            "by_metric": by_metric,
        }
    except Exception as e:
        log.error("get_summary hatası: %s", e)
        return {"total": 0, "last_24h": 0, "by_metric": {}, "error": str(e)}


def clear_old_anomalies(days: int = 7):
    """Eski anomalileri temizle."""
    try:
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with _lock:
            anomalies = _load_anomalies()
            filtered = [a for a in anomalies if a.get("ts", "") >= cutoff]
            removed = len(anomalies) - len(filtered)
            _save_anomalies(filtered)
        log.info("%d eski anomali temizlendi.", removed)
        return {"removed": removed, "remaining": len(filtered)}
    except Exception as e:
        log.error("clear_old_anomalies hatası: %s", e)
        return {"error": str(e)}


def start_detector(interval: int = 300):
    """Anomali dedektörünü daemon thread olarak başlat."""
    def _worker():
        while True:
            try:
                run_detection()
            except Exception as e:
                log.error("Dedektör döngü hatası: %s", e)
            time.sleep(interval)

    t = threading.Thread(target=_worker, daemon=True, name="anomaly-detector")
    t.start()
    log.info("Anomali dedektörü başlatıldı. Aralık: %ds", interval)
    return t
