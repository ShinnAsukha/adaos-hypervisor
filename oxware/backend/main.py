# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""Entry-point shim.

The Flask app + SocketIO live in app.py. Tests and some launchers import
`main` and expect a `.app` attribute, so re-export them here. Importing this
under OXWARE_TEST_MODE=1 skips background threads (guarded in app.py).
"""
from __future__ import annotations

from app import app  # noqa: F401  (Flask application object)

try:
    from app import socketio  # noqa: F401
except Exception:  # socketio optional / disabled in some modes
    socketio = None


if __name__ == "__main__":
    # Delegate to app.py's own __main__ runner.
    import runpy
    runpy.run_module("app", run_name="__main__")
