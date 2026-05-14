#!/usr/bin/env bash
# OXware Web Installer startup script
set -e

export DISPLAY=:0

# ── Start Xorg ─────────────────────────────────────────────────────────────
# Try to start Xorg on display :0, vt7
Xorg :0 -nolisten tcp -s 0 -dpms vt7 &
XORG_PID=$!

# Wait for X to be ready
for i in $(seq 1 15); do
    DISPLAY=:0 xdpyinfo >/dev/null 2>&1 && break
    sleep 0.5
done

# ── Hide cursor ────────────────────────────────────────────────────────────
DISPLAY=:0 xsetroot -solid '#0d1117' 2>/dev/null || true
DISPLAY=:0 unclutter -idle 0.1 -root 2>/dev/null &

# ── Start HTTP server ──────────────────────────────────────────────────────
cd /opt/oxware-installer/web
python3 server.py &
SERVER_PID=$!

# Give server a moment to bind
sleep 1

# ── Launch kiosk browser ───────────────────────────────────────────────────
DISPLAY=:0 python3 launcher.py

# ── Cleanup ────────────────────────────────────────────────────────────────
kill $SERVER_PID 2>/dev/null || true
kill $XORG_PID  2>/dev/null || true
