"""
OXware MinIO Manager
─────────────────────
MinIO / S3-uyumlu depolama entegrasyonu (boto3 tabanlı).
boto3 kurulu değilse: tüm işlemler hata döndürür.
"""

import json
import logging
import os
import threading
from datetime import datetime

log = logging.getLogger("oxware.minio")

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
    log.debug("boto3 yüklendi.")
except ImportError:
    boto3 = None
    ClientError = Exception
    BOTO3_AVAILABLE = False
    log.warning("boto3 bulunamadı. MinIO işlemleri devre dışı.")

CONFIG_FILE = "/etc/oxware/minio_config.json"
_lock = threading.Lock()


# ── Yardımcı ──────────────────────────────────────────────────────────────────

def _ensure_dir(path: str):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass


def _err_no_boto() -> dict:
    return {"success": False, "error": "boto3 kurulu değil. 'pip install boto3' ile yükleyin."}


def _bytes_to_human(size_bytes: int) -> str:
    """Byte değerini okunabilir formata çevir."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"


# ── Config ────────────────────────────────────────────────────────────────────

def get_config() -> dict:
    """MinIO bağlantı yapılandırmasını döndür (secret key gizlenir)."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
            result = {
                "endpoint":   cfg.get("endpoint", ""),
                "access_key": cfg.get("access_key", ""),
                "secret_key": "***" if cfg.get("secret_key") else "",
                "bucket":     cfg.get("bucket", ""),
                "region":     cfg.get("region", "us-east-1"),
                "enabled":    cfg.get("enabled", True),
                "available":  BOTO3_AVAILABLE,
            }
            return result
    except Exception as e:
        log.warning("Config yükleme hatası: %s", e)
    return {
        "endpoint": "",
        "access_key": "",
        "secret_key": "",
        "bucket": "",
        "region": "us-east-1",
        "enabled": False,
        "available": BOTO3_AVAILABLE,
    }


def _load_full_config() -> dict:
    """Secret key dahil tam config."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                return json.load(f)
    except Exception as e:
        log.warning("Config yükleme hatası: %s", e)
    return {}


def save_config(
    endpoint: str,
    access_key: str,
    secret_key: str,
    bucket: str,
    region: str = "us-east-1",
) -> dict:
    """MinIO bağlantı yapılandırmasını kaydet."""
    try:
        cfg = {
            "endpoint":   endpoint,
            "access_key": access_key,
            "secret_key": secret_key,
            "bucket":     bucket,
            "region":     region,
            "enabled":    True,
            "updated_at": datetime.now().isoformat(),
        }
        _ensure_dir(CONFIG_FILE)
        with _lock:
            with open(CONFIG_FILE, "w") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except Exception:
            pass
        log.info("MinIO config kaydedildi. Endpoint: %s", endpoint)
        return {"success": True, "endpoint": endpoint, "bucket": bucket}
    except Exception as e:
        log.error("save_config hatası: %s", e)
        return {"success": False, "error": str(e)}


# ── Bağlantı ──────────────────────────────────────────────────────────────────

def _get_client():
    """boto3 S3 client oluştur."""
    if not BOTO3_AVAILABLE:
        raise RuntimeError("boto3 kurulu değil.")
    cfg = _load_full_config()
    if not cfg:
        raise RuntimeError("MinIO yapılandırması bulunamadı.")
    return boto3.client(
        "s3",
        endpoint_url=cfg.get("endpoint"),
        aws_access_key_id=cfg.get("access_key"),
        aws_secret_access_key=cfg.get("secret_key"),
        region_name=cfg.get("region", "us-east-1"),
    )


def test_connection() -> dict:
    """Bağlantıyı test et."""
    try:
        if not BOTO3_AVAILABLE:
            return _err_no_boto()
        client = _get_client()
        client.list_buckets()
        return {"success": True, "message": "Bağlantı başarılı."}
    except Exception as e:
        log.warning("Bağlantı testi başarısız: %s", e)
        return {"success": False, "message": str(e)}


# ── Bucket İşlemleri ─────────────────────────────────────────────────────────

def list_buckets() -> list:
    """Tüm bucket'ları listele."""
    try:
        if not BOTO3_AVAILABLE:
            return []
        client = _get_client()
        response = client.list_buckets()
        return [
            {"name": b["Name"], "creation_date": b["CreationDate"].isoformat()}
            for b in response.get("Buckets", [])
        ]
    except Exception as e:
        log.error("list_buckets hatası: %s", e)
        return []


def create_bucket(name: str) -> dict:
    """Yeni bucket oluştur."""
    try:
        if not BOTO3_AVAILABLE:
            return _err_no_boto()
        client = _get_client()
        cfg = _load_full_config()
        region = cfg.get("region", "us-east-1")
        if region == "us-east-1":
            client.create_bucket(Bucket=name)
        else:
            client.create_bucket(
                Bucket=name,
                CreateBucketConfiguration={"LocationConstraint": region}
            )
        log.info("Bucket oluşturuldu: %s", name)
        return {"success": True, "bucket": name}
    except ClientError as e:
        log.warning("create_bucket ClientError: %s", e)
        return {"success": False, "error": str(e)}
    except Exception as e:
        log.error("create_bucket hatası: %s", e)
        return {"success": False, "error": str(e)}


# ── Nesne İşlemleri ───────────────────────────────────────────────────────────

def _default_bucket() -> str:
    return _load_full_config().get("bucket", "")


def list_objects(bucket: str = None, prefix: str = "") -> list:
    """Bucket içindeki nesneleri listele."""
    try:
        if not BOTO3_AVAILABLE:
            return []
        client  = _get_client()
        bucket  = bucket or _default_bucket()
        objects = []
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                objects.append({
                    "key":           obj["Key"],
                    "size":          obj["Size"],
                    "size_human":    _bytes_to_human(obj["Size"]),
                    "last_modified": obj["LastModified"].isoformat(),
                })
        return objects
    except Exception as e:
        log.error("list_objects hatası: %s", e)
        return []


def upload_file(
    local_path: str,
    remote_key: str,
    bucket: str = None,
) -> dict:
    """Dosyayı MinIO'ya yükle."""
    try:
        if not BOTO3_AVAILABLE:
            return _err_no_boto()
        if not os.path.exists(local_path):
            return {"success": False, "error": f"Dosya bulunamadı: {local_path}"}

        client = _get_client()
        bucket = bucket or _default_bucket()
        file_size = os.path.getsize(local_path)

        uploaded_bytes = [0]

        def _progress(chunk):
            uploaded_bytes[0] += chunk
            pct = (uploaded_bytes[0] / max(file_size, 1)) * 100
            log.debug("Yükleniyor: %s %d%%", remote_key, int(pct))

        client.upload_file(local_path, bucket, remote_key, Callback=_progress)
        log.info("Yüklendi: %s → s3://%s/%s", local_path, bucket, remote_key)
        return {
            "success": True,
            "local_path": local_path,
            "remote_key": remote_key,
            "bucket": bucket,
            "size": file_size,
        }
    except ClientError as e:
        log.warning("upload_file ClientError: %s", e)
        return {"success": False, "error": str(e)}
    except Exception as e:
        log.error("upload_file hatası: %s", e)
        return {"success": False, "error": str(e)}


def download_file(
    remote_key: str,
    local_path: str,
    bucket: str = None,
) -> dict:
    """Dosyayı MinIO'dan indir."""
    try:
        if not BOTO3_AVAILABLE:
            return _err_no_boto()
        client = _get_client()
        bucket = bucket or _default_bucket()
        _ensure_dir(local_path)
        client.download_file(bucket, remote_key, local_path)
        size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
        log.info("İndirildi: s3://%s/%s → %s", bucket, remote_key, local_path)
        return {
            "success": True,
            "remote_key": remote_key,
            "local_path": local_path,
            "size": size,
        }
    except ClientError as e:
        log.warning("download_file ClientError: %s", e)
        return {"success": False, "error": str(e)}
    except Exception as e:
        log.error("download_file hatası: %s", e)
        return {"success": False, "error": str(e)}


def delete_object(remote_key: str, bucket: str = None) -> dict:
    """Nesneyi sil."""
    try:
        if not BOTO3_AVAILABLE:
            return _err_no_boto()
        client = _get_client()
        bucket = bucket or _default_bucket()
        client.delete_object(Bucket=bucket, Key=remote_key)
        log.info("Silindi: s3://%s/%s", bucket, remote_key)
        return {"success": True, "remote_key": remote_key, "bucket": bucket}
    except ClientError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        log.error("delete_object hatası: %s", e)
        return {"success": False, "error": str(e)}


def get_object_url(
    remote_key: str,
    expires: int = 3600,
    bucket: str = None,
) -> dict:
    """Geçici (presigned) URL oluştur."""
    try:
        if not BOTO3_AVAILABLE:
            return _err_no_boto()
        client = _get_client()
        bucket = bucket or _default_bucket()
        url = client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": remote_key},
            ExpiresIn=expires,
        )
        return {
            "success": True,
            "url": url,
            "remote_key": remote_key,
            "expires_in": expires,
        }
    except ClientError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        log.error("get_object_url hatası: %s", e)
        return {"success": False, "error": str(e)}


def get_storage_stats(bucket: str = None) -> dict:
    """Bucket istatistiklerini hesapla."""
    try:
        if not BOTO3_AVAILABLE:
            return _err_no_boto()
        objects = list_objects(bucket=bucket)
        total_objects = len(objects)
        total_bytes   = sum(o.get("size", 0) for o in objects)
        return {
            "total_objects":    total_objects,
            "total_size_bytes": total_bytes,
            "total_size_human": _bytes_to_human(total_bytes),
            "bucket": bucket or _default_bucket(),
        }
    except Exception as e:
        log.error("get_storage_stats hatası: %s", e)
        return {"total_objects": 0, "total_size_bytes": 0, "total_size_human": "0 B", "error": str(e)}
