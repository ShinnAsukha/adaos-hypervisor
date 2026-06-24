"""Regression tests for the v2.8.1 honesty/audit fixes.

These lock in the behaviour changes made when resolving the system audit:
no fake "AI" output, no placeholder password hash, Pillow (not ImageMagick)
for thumbnails, a real /api/openapi spec, and a secret-free config.load().
If any of these regress, CI fails — that is the whole point.
"""

from __future__ import annotations

import json

import pytest


# ── ai_planner: no fake AI when there's no AI agent ──────────────────────────

def test_ai_planner_marks_heuristic_when_no_ai(tmp_path, monkeypatch):
    import ai_planner  # type: ignore

    # Force the "no AI agent" branch regardless of the host environment.
    monkeypatch.setattr(ai_planner, "AI_AVAILABLE", False)
    monkeypatch.setattr(ai_planner, "RECS_FILE", str(tmp_path / "recs.json"))

    result = ai_planner.analyze_resources()
    assert result.get("ai_available") is False
    assert result.get("source") == "heuristic"


def test_ai_planner_sizing_is_honest_without_ai(tmp_path, monkeypatch):
    import ai_planner  # type: ignore
    monkeypatch.setattr(ai_planner, "AI_AVAILABLE", False)

    out = ai_planner.suggest_vm_sizing("does-not-exist")
    assert out.get("ai_available") is False
    assert out.get("source") == "heuristic"
    # Must not invent an "optimal" size — reason states AI is absent.
    assert "AI yok" in (out.get("reason") or "")


# ── bare_metal: generated password hash, never the placeholder ───────────────

def test_bare_metal_no_placeholder_password_hash(tmp_path, monkeypatch):
    import bare_metal  # type: ignore
    monkeypatch.setattr(bare_metal, "AUTOINSTALL_DIR", tmp_path)
    monkeypatch.setattr(bare_metal, "LOG_DIR", tmp_path)
    monkeypatch.setattr(bare_metal, "AUDIT_LOG", tmp_path / "audit.jsonl")

    res = bare_metal.create_profile(
        name="testnode",
        hostname="testnode",
        disk_layout="lvm",
        network={"dhcp": True},
        ssh_keys=["ssh-ed25519 AAAA... test@host"],
        post_script="",
    )
    yaml_text = (tmp_path / "testnode.yaml").read_text(encoding="utf-8")

    assert "placeholderhashreplaceme" not in yaml_text
    # Either a real sha512-crypt hash ($6$...) or the locked-account marker.
    assert ('password: "$6$' in yaml_text) or ('password: "!"' in yaml_text)
    assert res["ok"] is True


def test_bare_metal_password_hash_is_unique_per_call(tmp_path, monkeypatch):
    import bare_metal  # type: ignore
    monkeypatch.setattr(bare_metal, "AUTOINSTALL_DIR", tmp_path)
    monkeypatch.setattr(bare_metal, "LOG_DIR", tmp_path)
    monkeypatch.setattr(bare_metal, "AUDIT_LOG", tmp_path / "audit.jsonl")

    def _hash_of(name):
        bare_metal.create_profile(name, name, "lvm", {"dhcp": True}, [], "")
        txt = (tmp_path / f"{name}.yaml").read_text(encoding="utf-8")
        for line in txt.splitlines():
            if line.strip().startswith("password:"):
                return line
        return None

    h1 = _hash_of("nodea")
    # Platforms without a working crypt module (e.g. Windows: no _crypt C ext)
    # fall back to the locked-account marker "!". Uniqueness only applies when
    # a real sha512-crypt hash is generated, as on the Linux CI runner.
    if "$6$" not in (h1 or ""):
        pytest.skip("crypt module unavailable — locked-account fallback in use")
    assert h1 != _hash_of("nodeb")


# ── vnc_thumbnail: Pillow path, never ImageMagick `convert` ──────────────────

def test_vnc_thumbnail_uses_pillow_not_convert(tmp_path, monkeypatch):
    pytest.importorskip("PIL")
    import vnc_thumbnail  # type: ignore

    calls = []

    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        # Simulate `virsh screenshot` by writing a tiny PPM where expected.
        if cmd and cmd[0] == "virsh":
            ppm_path = cmd[3]  # virsh screenshot <name> <file> --screen 0
            from PIL import Image
            Image.new("RGB", (64, 48), (10, 20, 30)).save(ppm_path, format="PPM")

            class _R:
                returncode = 0
                stderr = ""
            return _R()
        raise AssertionError(f"unexpected subprocess call: {cmd}")

    monkeypatch.setattr(vnc_thumbnail.subprocess, "run", fake_run)

    out = tmp_path / "thumb.png"
    ok = vnc_thumbnail._capture_via_virsh("vm-test", out)

    assert ok is True
    assert out.exists()
    # The only subprocess call must be virsh — never ImageMagick `convert`.
    assert all(c[0] != "convert" for c in calls)
    assert any(c[0] == "virsh" for c in calls)


# ── /api/openapi: real spec, public, paths dict ──────────────────────────────

def test_openapi_endpoint_returns_paths(app):
    resp = app.get("/api/openapi")
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert isinstance(payload, dict)
    assert payload.get("openapi", "").startswith("3.")
    assert isinstance(payload.get("paths"), dict)
    assert len(payload["paths"]) > 0


# ── config.load(): dict snapshot, no secrets ─────────────────────────────────

def test_config_load_is_dict_without_secrets(tmp_state_dir):
    import config  # type: ignore
    data = config.load()
    assert isinstance(data, dict)
    assert "SECRET_KEY" not in data
    assert "CONFIG_FILE" not in data
