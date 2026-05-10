"""
session_manager.py — OXware JWT Oturum Yöneticisi
Aktif oturumları bellek içinde takip eder; iptal (revocation) ve
otomatik temizleme desteği sağlar.
"""

import threading
import logging
from datetime import datetime, timezone

logger = logging.getLogger("oxware.session_manager")

# JWT süresi 12 saat; 13 saatte kesin sona erme kabul edilir
JWT_EXPIRY_HOURS = 12
CLEANUP_THRESHOLD_HOURS = 13

# ─────────────────────────────────────────────
# Bellek içi depolama
# ─────────────────────────────────────────────

# { jti (str) → session dict }
_sessions: dict = {}

# RLock: aynı thread içinde iç içe kilitlenmeye izin verir
_lock = threading.RLock()


# ─────────────────────────────────────────────
# Yardımcı fonksiyonlar
# ─────────────────────────────────────────────

def _now_iso() -> str:
    """Şimdiki UTC zamanını ISO-8601 formatında döndür."""
    return datetime.now(timezone.utc).isoformat()


def _age_minutes(created_at_iso: str) -> float:
    """Oluşturulma zamanından bu yana geçen süreyi dakika olarak hesapla."""
    try:
        created = datetime.fromisoformat(created_at_iso)
        # Timezone-naive ise UTC kabul et
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - created
        return delta.total_seconds() / 60
    except (ValueError, OSError):
        return 0.0


def _format_session(jti: str, session: dict) -> dict:
    """
    Dahili oturum dict'ini API'ye sunulacak biçime dönüştür.
    jti'nin tamamını açıklamaz; sadece ilk 8 karakteri session_id olarak kullanır.
    """
    return {
        "session_id": jti[:8],
        "username": session["username"],
        "ip": session["ip"],
        "user_agent": session["user_agent"],
        "created_at": session["created_at"],
        "last_seen": session["last_seen"],
        "revoked": session["revoked"],
        "age_minutes": round(_age_minutes(session["created_at"]), 1),
    }


# ─────────────────────────────────────────────
# Temel API
# ─────────────────────────────────────────────

def register_session(
    jti: str,
    username: str,
    ip: str,
    user_agent: str,
) -> None:
    """
    Yeni JWT oturumunu kaydet.

    jti      : JWT "jti" talebi (benzersiz token kimliği)
    username : Oturum sahibi kullanıcı adı
    ip       : İstemci IP adresi
    user_agent: HTTP User-Agent başlığı
    """
    now = _now_iso()
    session = {
        "username": username,
        "ip": ip,
        "user_agent": user_agent,
        "created_at": now,
        "last_seen": now,
        "revoked": False,
    }
    with _lock:
        _sessions[jti] = session
    logger.info(
        "Oturum kaydedildi: jti=%s... kullanıcı=%s ip=%s",
        jti[:8], username, ip,
    )


def touch_session(jti: str) -> None:
    """last_seen alanını şimdiki zamana güncelle (her istekte çağrılır)."""
    with _lock:
        if jti in _sessions:
            _sessions[jti]["last_seen"] = _now_iso()


def revoke_session(jti: str) -> bool:
    """
    Oturumu iptal et (revoke).
    Döndürür: True (iptal edildi) | False (oturum bulunamadı).
    """
    with _lock:
        if jti not in _sessions:
            logger.warning("İptal edilecek oturum bulunamadı: jti=%s...", jti[:8])
            return False
        _sessions[jti]["revoked"] = True

    logger.info(
        "Oturum iptal edildi: jti=%s... kullanıcı=%s",
        jti[:8], _sessions[jti]["username"],
    )
    return True


def revoke_by_short_id(short_id: str) -> bool:
    """session_id (jti'nin ilk 8 karakteri) ile oturumu iptal et."""
    with _lock:
        for jti, sess in _sessions.items():
            if jti[:8] == short_id:
                sess["revoked"] = True
                logger.info("Oturum kısa ID ile iptal edildi: %s", short_id)
                return True
    return False


def is_revoked(jti: str) -> bool:
    """
    Token'ın iptal edilip edilmediğini kontrol et.
    Bilinmeyen jti → False (JWT kütüphanesi imza/süre doğrulaması yapar).
    """
    with _lock:
        session = _sessions.get(jti)
        if session is None:
            return False
        return session.get("revoked", False)


# ─────────────────────────────────────────────
# Listeleme API
# ─────────────────────────────────────────────

def get_active_sessions(username: str = None) -> list:
    """
    Aktif (iptal edilmemiş, süresi dolmamış) oturumları döndür.

    username : Belirtilirse yalnızca o kullanıcıya ait oturumlar döner.
    Döndürür: Güvenli formattaki session dict listesi (jti açıklanmaz).
    """
    result = []
    with _lock:
        for jti, session in _sessions.items():
            if session["revoked"]:
                continue
            if _age_minutes(session["created_at"]) > JWT_EXPIRY_HOURS * 60:
                continue
            if username and session["username"] != username:
                continue
            result.append(_format_session(jti, session))
    return result


def get_all_sessions() -> list:
    """
    Tüm oturumları döndür (iptal edilmiş ve süresi dolmuşlar dahil).
    Yalnızca yönetici kullanımı içindir.
    """
    with _lock:
        return [_format_session(jti, sess) for jti, sess in _sessions.items()]


# ─────────────────────────────────────────────
# Temizleme
# ─────────────────────────────────────────────

def cleanup_expired() -> int:
    """
    13 saatten eski oturumları bellekten sil.
    Döndürür: Silinen oturum sayısı.
    """
    threshold_minutes = CLEANUP_THRESHOLD_HOURS * 60
    to_delete = []

    with _lock:
        for jti, session in _sessions.items():
            if _age_minutes(session["created_at"]) > threshold_minutes:
                to_delete.append(jti)
        for jti in to_delete:
            del _sessions[jti]

    if to_delete:
        logger.info("Süresi dolmuş %d oturum temizlendi.", len(to_delete))
    else:
        logger.debug("Temizlenecek süresi dolmuş oturum yok.")

    return len(to_delete)


def _cleanup_loop() -> None:
    """Daemon thread döngüsü — her 30 dakikada bir temizleme yapar."""
    logger.info("Oturum temizleme thread'i başladı.")
    import time  # noqa: PLC0415
    while True:
        time.sleep(30 * 60)  # 30 dakika bekle
        try:
            cleanup_expired()
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Oturum temizleme sırasında hata: %s", exc)


def start_cleanup_thread() -> threading.Thread:
    """
    Oturum temizleme daemon thread'ini başlat.
    Döndürür: Başlatılan Thread nesnesi.
    """
    t = threading.Thread(
        target=_cleanup_loop,
        daemon=True,
        name="session-cleanup",
    )
    t.start()
    logger.info("Oturum temizleme thread'i başlatıldı (30 dk aralık).")
    return t
