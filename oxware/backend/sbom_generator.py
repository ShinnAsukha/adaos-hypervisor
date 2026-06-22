"""OXware SBOM generator (CycloneDX 1.5 JSON).

Walks `requirements.txt` and the installed Python distribution metadata
to emit a CycloneDX-formatted Software Bill of Materials. The CI job
runs this on every release tag and uploads the result as a build
artifact.

Output: /var/lib/oxware/sbom-cyclonedx.json
"""
from __future__ import annotations
import importlib.metadata as _imd
import json
import logging
import os
import platform
import time
import uuid
from pathlib import Path

log = logging.getLogger("oxware.sbom")
_OUT_PATH = Path("/var/lib/oxware/sbom-cyclonedx.json")


def _component_for(dist) -> dict:
    name = dist.metadata.get("Name", "")
    version = dist.version
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name.lower()}@{version}",
        "licenses": _licenses(dist),
        "externalReferences": _refs(dist),
    }


def _licenses(dist) -> list:
    lic = dist.metadata.get("License")
    if not lic:
        return []
    return [{"license": {"name": lic}}]


def _refs(dist) -> list:
    out = []
    home = dist.metadata.get("Home-page")
    if home:
        out.append({"type": "website", "url": home})
    for line in (dist.metadata.get_all("Project-URL") or []):
        if ", " in line:
            kind, url = line.split(", ", 1)
            out.append({"type": kind.lower(), "url": url})
    return out


def generate(out_path: str | Path = _OUT_PATH) -> dict:
    components = []
    for dist in _imd.distributions():
        try:
            components.append(_component_for(dist))
        except Exception as e:
            log.debug("sbom skip dist: %s", e)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tools": [{"vendor": "OXware", "name": "sbom_generator", "version": "1.0"}],
            "component": {
                "type": "application",
                "name": "oxware-hypervisor",
                "version": os.environ.get("OXWARE_VERSION", "2.8.1"),
                "purl": "pkg:generic/oxware-hypervisor@"
                + os.environ.get("OXWARE_VERSION", "2.8.1"),
            },
            "properties": [
                {"name": "python_version", "value": platform.python_version()},
                {"name": "platform", "value": platform.platform()},
            ],
        },
        "components": components,
    }
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    os.replace(tmp, p)
    log.info("SBOM written: %s (%d components)", p, len(components))
    return {"ok": True, "path": str(p), "components": len(components)}


def latest() -> dict:
    if not _OUT_PATH.exists():
        return {"ok": False, "error": "no SBOM generated yet"}
    try:
        return {"ok": True, "sbom": json.loads(_OUT_PATH.read_text(encoding="utf-8"))}
    except Exception as e:
        return {"ok": False, "error": str(e)}
