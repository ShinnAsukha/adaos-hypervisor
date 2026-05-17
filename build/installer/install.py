#!/usr/bin/env python3
"""
OXware Hypervisor Installer
Proxmox-style full-screen TUI installer using Python curses.
Requires: python3-curses (stdlib), no external pip packages.
Minimum terminal: 80x24
"""

import curses
import subprocess
import os
import sys
import re
import json
import hashlib
import shutil
import time
import textwrap
import threading
from pathlib import Path

# ── constants ──────────────────────────────────────────────────────────────────

VERSION = "1.0"
BANNER = [
    " ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ██████╗ ███████╗",
    "██╔═══██╗╚██╗██╔╝██║    ██║██╔══██╗██╔══██╗██╔════╝",
    "██║   ██║ ╚███╔╝ ██║ █╗ ██║███████║██████╔╝█████╗  ",
    "██║   ██║ ██╔██╗ ██║███╗██║██╔══██║██╔══██╗██╔══╝  ",
    "╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║██║  ██║███████╗",
    " ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝",
]

LICENSE_TEXT = """\
MIT License

Copyright (c) 2024 OXware Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

By pressing ENTER you accept the terms of this license and agree to install
OXware Hypervisor on the selected disk. All existing data on the target disk
will be permanently destroyed.
"""

TARGET_MOUNT = "/mnt/target"
OXWARE_SRC   = "/opt/oxware"
INSTALLER_SRC = "/opt/oxware-installer"

# ── color pair ids ─────────────────────────────────────────────────────────────
CP_NORMAL   = 1   # white on black
CP_HEADER   = 2   # black on cyan
CP_SELECTED = 3   # black on white
CP_PROGRESS = 4   # black on green
CP_ERROR    = 5   # white on red
CP_BORDER   = 6   # cyan on black
CP_DIM      = 7   # dark white on black
CP_INPUT    = 8   # yellow on black
CP_ACCENT   = 9   # yellow on black
CP_GREEN    = 10  # green on black

# ── installer state ────────────────────────────────────────────────────────────
class State:
    def __init__(self):
        self.disk        = ""
        self.net_mode    = "dhcp"   # "dhcp" | "static"
        self.ip          = ""
        self.netmask     = "255.255.255.0"
        self.gateway     = ""
        self.dns         = "8.8.8.8"
        self.hostname    = "oxware-node"
        self.username    = ""
        self.password    = ""
        self.confirm_pw  = ""
        self.keyboard_layout  = "tr"
        self.keyboard_variant = ""
        self.locale           = "tr_TR.UTF-8"
        self.timezone         = "Europe/Istanbul"
        self.ssh_enabled      = True
        self.ssh_port         = 22
        self.ssh_root         = False
        self.ssh_passwd_auth  = True

state = State()

# ── helper: run shell command ──────────────────────────────────────────────────

def run(cmd, check=True, capture=False, input_text=None):
    kwargs = {"shell": True, "check": check}
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
        kwargs["text"]   = True
    if input_text is not None:
        kwargs["input"] = input_text
        if not capture:
            kwargs["stdin"] = subprocess.PIPE
    return subprocess.run(cmd, **kwargs)

def run_chroot(cmd, check=True):
    return run(f"chroot {TARGET_MOUNT} /bin/bash -c {repr(cmd)}", check=check)

# ── drawing primitives ─────────────────────────────────────────────────────────

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(CP_NORMAL,   curses.COLOR_WHITE,   curses.COLOR_BLACK)
    curses.init_pair(CP_HEADER,   curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(CP_SELECTED, curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(CP_PROGRESS, curses.COLOR_BLACK,   curses.COLOR_GREEN)
    curses.init_pair(CP_ERROR,    curses.COLOR_WHITE,   curses.COLOR_RED)
    curses.init_pair(CP_BORDER,   curses.COLOR_CYAN,    curses.COLOR_BLACK)
    curses.init_pair(CP_DIM,      curses.COLOR_WHITE,   curses.COLOR_BLACK)
    curses.init_pair(CP_INPUT,    curses.COLOR_YELLOW,  curses.COLOR_BLACK)
    curses.init_pair(CP_ACCENT,   curses.COLOR_YELLOW,  curses.COLOR_BLACK)
    curses.init_pair(CP_GREEN,    curses.COLOR_GREEN,   curses.COLOR_BLACK)


def draw_frame(win):
    """Draw the outer frame with header and footer."""
    h, w = win.getmaxyx()
    win.bkgd(' ', curses.color_pair(CP_NORMAL))
    win.erase()

    # outer border
    battr = curses.color_pair(CP_BORDER)
    try:
        win.border(0)
    except curses.error:
        pass

    # header bar
    hattr = curses.color_pair(CP_HEADER) | curses.A_BOLD
    title = f"  OXware Hypervisor {VERSION}  -  Professional Installer  "
    pad   = (w - 2 - len(title)) // 2
    try:
        win.addstr(1, 1, " " * (w - 2), hattr)
        win.addstr(1, 1 + pad, title, hattr)
        # separator
        win.addch(2, 0, curses.ACS_LTEE, battr)
        win.hline(2, 1, curses.ACS_HLINE, w - 2, battr)
        win.addch(2, w - 1, curses.ACS_RTEE, battr)
    except curses.error:
        pass

    # footer separator + hints
    try:
        win.addch(h - 3, 0, curses.ACS_LTEE, battr)
        win.hline(h - 3, 1, curses.ACS_HLINE, w - 2, battr)
        win.addch(h - 3, w - 1, curses.ACS_RTEE, battr)
        hints = "  [TAB/ENTER] Next   [SHIFT+TAB] Back   [Q] Quit  "
        win.addstr(h - 2, 1, " " * (w - 2), curses.color_pair(CP_DIM))
        win.addstr(h - 2, 2, hints, curses.color_pair(CP_DIM) | curses.A_DIM)
    except curses.error:
        pass

    win.refresh()


def content_area(win):
    """Return (top_row, left_col, height, width) of usable content area."""
    h, w = win.getmaxyx()
    return 3, 1, h - 6, w - 2


def center_str(win, row, text, attr=None, col_offset=0):
    h, w = win.getmaxyx()
    col = (w - len(text)) // 2 + col_offset
    if attr is None:
        attr = curses.color_pair(CP_NORMAL)
    try:
        win.addstr(row, max(1, col), text, attr)
    except curses.error:
        pass


def draw_progress_bar(win, row, col, width, pct, label=""):
    filled = int(width * pct / 100)
    bar    = "█" * filled + "░" * (width - filled)
    pattr  = curses.color_pair(CP_PROGRESS) | curses.A_BOLD
    nattr  = curses.color_pair(CP_NORMAL)
    try:
        win.addstr(row, col, bar[:filled],          pattr)
        win.addstr(row, col + filled, bar[filled:], nattr)
        pct_str = f" {pct:3d}% "
        if label:
            pct_str = f" {label} {pct:3d}% "
        win.addstr(row + 1, col + (width - len(pct_str)) // 2, pct_str,
                   curses.color_pair(CP_NORMAL) | curses.A_BOLD)
    except curses.error:
        pass

# ── screens ────────────────────────────────────────────────────────────────────

def screen_welcome(win):
    """Screen 1: rich welcome with two-column layout."""
    while True:
        win.erase()
        win.bkgd(' ', curses.color_pair(CP_NORMAL))
        h, w = win.getmaxyx()

        # ── Top header bar ──────────────────────────────────────────────────
        hattr = curses.color_pair(CP_HEADER) | curses.A_BOLD
        try:
            win.addstr(0, 0, " " * w, hattr)
            hdr = f"  OXware Hypervisor {VERSION}  —  Professional Hypervisor Management Platform  "
            win.addstr(0, max(1, (w - len(hdr)) // 2), hdr[:w - 2], hattr)
        except curses.error:
            pass

        # ── ASCII logo centered ──────────────────────────────────────────────
        battr  = curses.color_pair(CP_BORDER) | curses.A_BOLD
        logo_w = max((len(l) for l in BANNER), default=0)
        lx     = max(1, (w - logo_w) // 2)
        row    = 2
        for line in BANNER:
            try:
                win.addstr(row, lx, line, battr)
            except curses.error:
                pass
            row += 1

        # ── Tagline + version ───────────────────────────────────────────────
        row += 1
        tagline = "Enterprise-Grade Hypervisor Yönetim Platformu"
        try:
            win.addstr(row, max(1, (w - len(tagline)) // 2), tagline,
                       curses.color_pair(CP_NORMAL) | curses.A_BOLD)
        except curses.error:
            pass
        row += 1
        sub = f"v{VERSION}  ·  Ubuntu 22.04 LTS Jammy  ·  KVM + libvirt + nginx + Flask"
        try:
            win.addstr(row, max(1, (w - len(sub)) // 2), sub,
                       curses.color_pair(CP_DIM) | curses.A_DIM)
        except curses.error:
            pass
        row += 2

        # ── Horizontal divider ──────────────────────────────────────────────
        div_attr = curses.color_pair(CP_BORDER)
        try:
            win.addch(row, 0, curses.ACS_LTEE, div_attr)
            win.hline(row, 1, curses.ACS_HLINE, w - 2, div_attr)
            win.addch(row, w - 1, curses.ACS_RTEE, div_attr)
        except curses.error:
            pass
        row += 1

        # ── Two-column layout ───────────────────────────────────────────────
        mid     = w // 2
        col1_x  = 3
        col2_x  = mid + 3
        col_w   = mid - 5

        # Column headers
        lhattr = curses.color_pair(CP_HEADER) | curses.A_BOLD
        try:
            win.addstr(row, col1_x, " OXware Nedir? ", lhattr)
            win.addstr(row, col2_x, " Bu Kurulum Neleri Yapılandırır? ", lhattr)
        except curses.error:
            pass

        # Vertical separator between columns
        sep_col = mid
        for r in range(row, min(row + 12, h - 5)):
            try:
                win.addch(r, sep_col, curses.ACS_VLINE, div_attr)
            except curses.error:
                pass

        row += 2

        left_lines = [
            "OXware; KVM sanallaştırma teknolojisi",
            "üzerine inşa edilmiş, web tabanlı",
            "profesyonel hypervisor yönetim",
            "platformudur.",
            "",
            "Sanal makine yaşam döngüsü,  ağ",
            "yönetimi, snapshot, yedekleme,",
            "CVE takibi ve AI asistan özelliklerini",
            "tek çatı altında sunar.",
        ]

        right_items = [
            ("Ubuntu 22.04 LTS", "temel işletim sistemi"),
            ("KVM + QEMU + libvirt", "sanallaştırma katmanı"),
            ("OXware web arayüzü", "Flask + nginx reverse proxy"),
            ("GRUB önyükleyici", "BIOS + UEFI desteği"),
            ("netplan", "ağ yapılandırması"),
            ("systemd servisi", "otomatik başlatma"),
            ("ufw güvenlik duvarı", "port yönetimi"),
        ]

        nattr   = curses.color_pair(CP_NORMAL)
        dimattr = curses.color_pair(CP_DIM) | curses.A_DIM
        gattr   = curses.color_pair(CP_GREEN) | curses.A_BOLD
        yattr   = curses.color_pair(CP_ACCENT) | curses.A_BOLD

        for i, line in enumerate(left_lines):
            try:
                win.addstr(row + i, col1_x, line[:col_w], nattr)
            except curses.error:
                pass

        for i, (name, desc) in enumerate(right_items):
            try:
                win.addstr(row + i, col2_x,     "✔ ", gattr)
                win.addstr(row + i, col2_x + 2, (name + " "), yattr)
                win.addstr("— " + desc, dimattr)
            except curses.error:
                pass

        row += max(len(left_lines), len(right_items)) + 1

        # ── Warning bar ─────────────────────────────────────────────────────
        try:
            win.addch(row, 0, curses.ACS_LTEE, div_attr)
            win.hline(row, 1, curses.ACS_HLINE, w - 2, div_attr)
            win.addch(row, w - 1, curses.ACS_RTEE, div_attr)
        except curses.error:
            pass
        row += 1

        warn = "⚠  DİKKAT: Kurulum sırasında seçilen diskteki TÜM VERİLER kalıcı olarak SİLİNECEKTİR.  ⚠"
        wattr = curses.color_pair(CP_ERROR) | curses.A_BOLD
        try:
            win.addstr(row, max(1, (w - len(warn)) // 2), warn[:w - 2], wattr)
        except curses.error:
            pass
        row += 2

        # ── Action prompt ────────────────────────────────────────────────────
        prompt = "[ ENTER — Kurulumu Başlat ]          [ Q — Çıkış ]"
        pattr  = curses.color_pair(CP_HEADER) | curses.A_BOLD
        try:
            win.addstr(row, max(1, (w - len(prompt)) // 2), prompt, pattr)
        except curses.error:
            pass

        win.refresh()
        key = win.getch()
        if key in (10, 13, curses.KEY_ENTER):
            return "next"
        if key in (ord('q'), ord('Q')):
            return "quit"


def screen_license(win):
    """Screen 2: license scroll."""
    lines  = LICENSE_TEXT.splitlines()
    offset = 0
    h, w   = win.getmaxyx()
    top, left, ch, cw = content_area(win)
    visible = ch - 3  # leave room for prompt

    while True:
        draw_frame(win)
        h, w = win.getmaxyx()
        top, left, ch, cw = content_area(win)
        visible = ch - 3

        title_attr = curses.color_pair(CP_HEADER) | curses.A_BOLD
        try:
            win.addstr(top, left + 2, " License Agreement ", title_attr)
        except curses.error:
            pass

        for i, ln in enumerate(lines[offset: offset + visible]):
            try:
                win.addstr(top + 1 + i, left + 1,
                           ln[:cw - 2].ljust(cw - 2),
                           curses.color_pair(CP_NORMAL))
            except curses.error:
                pass

        prompt = "Scroll: ↑↓  |  ENTER = Accept & Continue  |  SHIFT+TAB = Back"
        center_str(win, top + ch - 1, prompt, curses.color_pair(CP_DIM))
        win.refresh()

        key = win.getch()
        if key == curses.KEY_DOWN and offset < len(lines) - visible:
            offset += 1
        elif key == curses.KEY_UP and offset > 0:
            offset -= 1
        elif key in (10, 13, curses.KEY_ENTER):
            return "next"
        elif key == curses.KEY_BTAB:
            return "back"
        elif key in (ord('q'), ord('Q')):
            return "quit"


def get_disks():
    """Return list of (device, size, model) tuples."""
    try:
        r = run("lsblk -d -o NAME,SIZE,MODEL --noheadings 2>/dev/null",
                capture=True, check=False)
        disks = []
        for line in r.stdout.strip().splitlines():
            parts = line.split(None, 2)
            name  = parts[0] if len(parts) > 0 else ""
            size  = parts[1] if len(parts) > 1 else "?"
            model = parts[2].strip() if len(parts) > 2 else "Unknown"
            if name and not name.startswith("loop") and not name.startswith("sr"):
                disks.append((f"/dev/{name}", size, model))
        return disks
    except Exception:
        return []


def screen_disk(win):
    """Screen 3: target disk selection."""
    disks   = get_disks()
    sel     = 0

    while True:
        draw_frame(win)
        h, w = win.getmaxyx()
        top, left, ch, cw = content_area(win)

        try:
            win.addstr(top, left + 2,
                       " Select Installation Disk ",
                       curses.color_pair(CP_HEADER) | curses.A_BOLD)
            win.addstr(top + 1, left + 1,
                       "WARNING: All data on the selected disk will be destroyed!",
                       curses.color_pair(CP_ERROR) | curses.A_BOLD)
        except curses.error:
            pass

        if not disks:
            center_str(win, top + 4,
                       "No disks detected. Check hardware.",
                       curses.color_pair(CP_ERROR) | curses.A_BOLD)
        else:
            for i, (dev, size, model) in enumerate(disks):
                row  = top + 3 + i
                label = f"  {dev:<14}  {size:>8}   {model}"
                label = label[:cw - 2]
                attr  = (curses.color_pair(CP_SELECTED) | curses.A_BOLD
                         if i == sel
                         else curses.color_pair(CP_NORMAL))
                try:
                    win.addstr(row, left + 1, label.ljust(cw - 2), attr)
                except curses.error:
                    pass

        win.refresh()
        key = win.getch()

        if key == curses.KEY_DOWN and sel < len(disks) - 1:
            sel += 1
        elif key == curses.KEY_UP and sel > 0:
            sel -= 1
        elif key in (10, 13, curses.KEY_ENTER, ord('\t')):
            if disks:
                state.disk = disks[sel][0]
                return "next"
        elif key == curses.KEY_BTAB:
            return "back"
        elif key in (ord('q'), ord('Q')):
            return "quit"


def read_input(win, row, col, width, secret=False, initial=""):
    """Simple single-line input widget. Returns the string entered."""
    curses.echo()
    curses.curs_set(1)
    buf = list(initial)
    iattr = curses.color_pair(CP_INPUT) | curses.A_BOLD

    def redraw():
        display = ("*" * len(buf) if secret else "".join(buf))
        display = (display[-width:] if len(display) > width else display)
        try:
            win.addstr(row, col, display.ljust(width), iattr)
            win.move(row, col + min(len(display), width))
        except curses.error:
            pass
        win.refresh()

    redraw()
    while True:
        ch = win.getch()
        if ch in (10, 13, curses.KEY_ENTER, ord('\t')):
            break
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if buf:
                buf.pop()
        elif 32 <= ch <= 126:
            buf.append(chr(ch))
        redraw()

    curses.noecho()
    curses.curs_set(0)
    return "".join(buf)


def screen_network(win):
    """Screen 4: network config."""
    mode_sel = 0 if state.net_mode == "dhcp" else 1
    fields   = {
        "ip":      state.ip,
        "netmask": state.netmask,
        "gateway": state.gateway,
        "dns":     state.dns,
    }
    labels   = ["IP Address", "Netmask", "Gateway", "DNS"]
    fkeys    = ["ip", "netmask", "gateway", "dns"]
    focus    = 0  # 0=dhcp radio, 1=static radio, 2..5=fields

    while True:
        draw_frame(win)
        h, w = win.getmaxyx()
        top, left, ch, cw = content_area(win)

        try:
            win.addstr(top, left + 2,
                       " Network Configuration ",
                       curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

        dhcp_attr   = (curses.color_pair(CP_SELECTED) | curses.A_BOLD
                       if focus == 0 else curses.color_pair(CP_NORMAL))
        static_attr = (curses.color_pair(CP_SELECTED) | curses.A_BOLD
                       if focus == 1 else curses.color_pair(CP_NORMAL))

        dhcp_marker   = "(*)" if mode_sel == 0 else "( )"
        static_marker = "(*)" if mode_sel == 1 else "( )"

        try:
            win.addstr(top + 2, left + 4, f"{dhcp_marker} DHCP (automatic)",   dhcp_attr)
            win.addstr(top + 3, left + 4, f"{static_marker} Static IP",        static_attr)
        except curses.error:
            pass

        field_col = left + 20
        field_w   = min(30, cw - 22)

        for i, (lbl, fkey) in enumerate(zip(labels, fkeys)):
            row   = top + 5 + i
            fattr = (curses.color_pair(CP_SELECTED) | curses.A_BOLD
                     if focus == i + 2 else curses.color_pair(CP_NORMAL))
            dim   = curses.color_pair(CP_DIM) | curses.A_DIM if mode_sel == 0 else fattr
            try:
                win.addstr(row, left + 4, f"{lbl:>12}: ", dim)
                val = fields[fkey]
                display = val if val else f"<{lbl.lower()}>"
                win.addstr(row, field_col, display[:field_w].ljust(field_w),
                           curses.color_pair(CP_INPUT) | curses.A_BOLD
                           if focus == i + 2
                           else (curses.color_pair(CP_DIM) if mode_sel == 0
                                 else curses.color_pair(CP_NORMAL)))
            except curses.error:
                pass

        win.refresh()
        key = win.getch()

        if key == curses.KEY_DOWN or key == ord('\t'):
            max_focus = 1 if mode_sel == 0 else 5
            focus = (focus + 1) % (max_focus + 1)
        elif key == curses.KEY_UP or key == curses.KEY_BTAB:
            if focus == 0:
                state.net_mode = "dhcp" if mode_sel == 0 else "static"
                for fk in fkeys:
                    fields[fk] = fields[fk]
                return "back"
            max_focus = 1 if mode_sel == 0 else 5
            focus = (focus - 1) % (max_focus + 1)
        elif key in (10, 13, curses.KEY_ENTER):
            if focus == 0:
                mode_sel = 0
            elif focus == 1:
                mode_sel = 1
            elif focus >= 2 and mode_sel == 1:
                fkey = fkeys[focus - 2]
                row  = top + 5 + (focus - 2)
                val  = read_input(win, row, field_col, field_w,
                                  initial=fields[fkey])
                fields[fkey] = val

            if focus == 5 or (focus == 1 and mode_sel == 0):
                # advance on last field
                state.net_mode = "dhcp" if mode_sel == 0 else "static"
                state.ip       = fields["ip"]
                state.netmask  = fields["netmask"]
                state.gateway  = fields["gateway"]
                state.dns      = fields["dns"]
                return "next"
        elif key in (ord('q'), ord('Q')):
            return "quit"

        # pressing enter on DHCP radio and it's already selected → advance
        if key in (10, 13) and focus == 0 and mode_sel == 0:
            state.net_mode = "dhcp"
            return "next"


def screen_hostname(win):
    """Screen 5: hostname input."""
    hostname = state.hostname

    while True:
        draw_frame(win)
        h, w = win.getmaxyx()
        top, left, ch, cw = content_area(win)

        try:
            win.addstr(top, left + 2,
                       " Hostname ",
                       curses.color_pair(CP_HEADER) | curses.A_BOLD)
            win.addstr(top + 2, left + 4,
                       "Enter the hostname for this OXware node:",
                       curses.color_pair(CP_NORMAL))
            win.addstr(top + 4, left + 4, "Hostname: ",
                       curses.color_pair(CP_NORMAL) | curses.A_BOLD)
        except curses.error:
            pass

        win.refresh()
        hostname = read_input(win, top + 4, left + 14, 40, initial=hostname)
        if hostname.strip():
            state.hostname = hostname.strip()
            return "next"
        # empty — stay on screen


def screen_password(win):
    """Screen 6: admin username + password."""
    uname = state.username or ""
    pw1   = ""
    pw2   = ""
    msg   = ""

    while True:
        draw_frame(win)
        h, w = win.getmaxyx()
        top, left, ch, cw = content_area(win)

        try:
            win.addstr(top, left + 2,
                       " Admin Account ",
                       curses.color_pair(CP_HEADER) | curses.A_BOLD)
            win.addstr(top + 2, left + 4,
                       "Create the administrator account for OXware web UI:",
                       curses.color_pair(CP_NORMAL))
            win.addstr(top + 4, left + 4, "Username:        ",
                       curses.color_pair(CP_NORMAL) | curses.A_BOLD)
            win.addstr(top + 6, left + 4, "Password:        ",
                       curses.color_pair(CP_NORMAL) | curses.A_BOLD)
            win.addstr(top + 8, left + 4, "Confirm Password:",
                       curses.color_pair(CP_NORMAL) | curses.A_BOLD)
        except curses.error:
            pass

        if msg:
            try:
                win.addstr(top + 11, left + 4, msg,
                           curses.color_pair(CP_ERROR) | curses.A_BOLD)
            except curses.error:
                pass

        win.refresh()

        uname = read_input(win, top + 4, left + 22, 30, initial=uname)
        if not uname.strip():
            msg = "Username cannot be empty."
            continue
        if len(uname.strip()) < 3:
            msg = "Username must be at least 3 characters."
            continue
        if not uname.strip().replace("-", "").replace("_", "").isalnum():
            msg = "Username: only letters, numbers, - and _ allowed."
            uname = ""
            continue

        pw1 = read_input(win, top + 6, left + 22, 30, secret=True)
        pw2 = read_input(win, top + 8, left + 22, 30, secret=True)

        if not pw1:
            msg = "Password cannot be empty."
            continue
        if len(pw1) < 6:
            msg = "Password must be at least 6 characters."
            continue
        if pw1 != pw2:
            msg = "Passwords do not match. Try again."
            pw1 = ""
            pw2 = ""
            continue

        state.username    = uname.strip()
        state.password    = pw1
        state.confirm_pw  = pw2
        return "next"


def screen_summary(win):
    """Screen 7: summary + confirm."""
    while True:
        draw_frame(win)
        h, w = win.getmaxyx()
        top, left, ch, cw = content_area(win)

        try:
            win.addstr(top, left + 2,
                       " Installation Summary ",
                       curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

        rows = [
            ("Target Disk",  state.disk    or "(none)"),
            ("Network",      state.net_mode.upper()),
        ]
        if state.net_mode == "static":
            rows += [
                ("IP Address",  state.ip),
                ("Netmask",     state.netmask),
                ("Gateway",     state.gateway),
                ("DNS",         state.dns),
            ]
        rows += [
            ("Hostname",    state.hostname),
            ("Admin User",  state.username  or "(not set)"),
            ("Admin Pass",  "*" * len(state.password) if state.password else "(not set)"),
        ]

        for i, (lbl, val) in enumerate(rows):
            row = top + 2 + i
            try:
                win.addstr(row, left + 4,
                           f"{lbl:>14}:  ",
                           curses.color_pair(CP_NORMAL) | curses.A_BOLD)
                win.addstr(row, left + 20,
                           val,
                           curses.color_pair(CP_INPUT) | curses.A_BOLD)
            except curses.error:
                pass

        try:
            warn_row = top + 2 + len(rows) + 2
            win.addstr(warn_row, left + 4,
                       "WARNING: All data on the target disk will be erased!",
                       curses.color_pair(CP_ERROR) | curses.A_BOLD)
            win.addstr(warn_row + 2, left + 4,
                       "[ ENTER = Begin Installation ]   [ SHIFT+TAB = Go Back ]",
                       curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

        win.refresh()
        key = win.getch()

        if key in (10, 13, curses.KEY_ENTER):
            return "next"
        elif key == curses.KEY_BTAB:
            return "back"
        elif key in (ord('q'), ord('Q')):
            return "quit"


# ── actual installation ────────────────────────────────────────────────────────

def do_install(progress_cb):
    """
    Run the real installation. Calls progress_cb(pct, message) periodically.
    Raises on failure.
    """
    disk = state.disk

    def blk(n):
        """Return /dev/sdXn style partition path."""
        # nvme uses 'p' separator: /dev/nvme0n1p1
        if re.search(r'\d$', disk):
            return f"{disk}p{n}"
        return f"{disk}{n}"

    progress_cb(2, "Partitioning disk …")
    run(f"wipefs -a {disk}")
    run(f"parted -s {disk} mklabel gpt")
    run(f"parted -s {disk} mkpart primary 1MiB 2MiB")      # BIOS boot
    run(f"parted -s {disk} set 1 bios_grub on")
    run(f"parted -s {disk} mkpart primary fat32 2MiB 514MiB")  # EFI
    run(f"parted -s {disk} set 2 esp on")
    run(f"parted -s {disk} mkpart primary ext4 514MiB 100%")  # root

    progress_cb(10, "Formatting partitions …")
    run(f"mkfs.vfat -F32 {blk(2)}")
    run(f"mkfs.ext4 -F {blk(3)}")

    progress_cb(14, "Mounting target …")
    Path(TARGET_MOUNT).mkdir(parents=True, exist_ok=True)
    run(f"mount {blk(3)} {TARGET_MOUNT}")
    Path(f"{TARGET_MOUNT}/boot/efi").mkdir(parents=True, exist_ok=True)
    run(f"mount {blk(2)} {TARGET_MOUNT}/boot/efi")

    progress_cb(15, "Ağ yapılandırılıyor …")
    import time as _time

    # 1. Already connected? (live env may have auto-configured)
    _already = subprocess.run(
        "curl -sf --max-time 4 http://archive.ubuntu.com/ubuntu/dists/jammy/Release -o /dev/null",
        shell=True, capture_output=True)

    if _already.returncode != 0:
        # 2. Find ALL physical ethernet interfaces (exclude lo, wl*, vir*, docker*, br*)
        _ifaces_raw = subprocess.run(
            "ip -o link show | awk -F': ' '{print $2}' | grep -Ev '^(lo|wl|vir|docker|br|veth|dummy)'",
            shell=True, capture_output=True, text=True)
        _ifaces = [i.strip() for i in _ifaces_raw.stdout.splitlines() if i.strip()]

        for _iface in _ifaces:
            subprocess.run(f"ip link set {_iface} up", shell=True, check=False)
            subprocess.run(f"dhclient -v {_iface}", shell=True, check=False, timeout=30)
            # Quick check after each iface
            _chk = subprocess.run(
                "curl -sf --max-time 4 http://archive.ubuntu.com/ubuntu/dists/jammy/Release -o /dev/null",
                shell=True, capture_output=True)
            if _chk.returncode == 0:
                break

    # 3. Final connectivity check — wait up to 30 s
    _net_ready = False
    for _i in range(30):
        _ping = subprocess.run(
            "curl -sf --max-time 3 http://archive.ubuntu.com/ubuntu/dists/jammy/Release -o /dev/null",
            shell=True, capture_output=True)
        if _ping.returncode == 0:
            _net_ready = True
            break
        _time.sleep(1)

    if not _net_ready:
        raise RuntimeError(
            "İnternet bağlantısı kurulamadı.\n"
            "VM ağ bağdaştırıcısını NAT veya Bridged moduna alıp\n"
            "yeniden deneyin. (VMware: VM → Settings → Network Adapter → NAT)"
        )

    progress_cb(16, "Running debootstrap (this may take several minutes) …")
    run(
        f"debootstrap --no-check-gpg --arch=amd64 "
        f"--components=main,restricted,universe "
        f"jammy {TARGET_MOUNT} http://archive.ubuntu.com/ubuntu/"
    )

    progress_cb(45, "Mounting virtual filesystems …")
    for fs in ("proc", "sys", "dev", "dev/pts"):
        Path(f"{TARGET_MOUNT}/{fs}").mkdir(parents=True, exist_ok=True)
        if fs == "dev":
            run(f"mount --bind /dev {TARGET_MOUNT}/dev", check=False)
        elif fs == "dev/pts":
            run(f"mount --bind /dev/pts {TARGET_MOUNT}/dev/pts", check=False)
        else:
            run(f"mount -t {fs} {fs} {TARGET_MOUNT}/{fs}", check=False)

    # Copy resolv.conf so apt/pip can reach internet from chroot
    _resolv = Path(f"{TARGET_MOUNT}/etc/resolv.conf")
    _resolv.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy("/etc/resolv.conf", str(_resolv))
    except Exception:
        _resolv.write_text("nameserver 8.8.8.8\nnameserver 1.1.1.1\n")

    progress_cb(46, "Writing Ubuntu apt sources …")
    sources = (
        "deb http://archive.ubuntu.com/ubuntu/ jammy main restricted universe multiverse\n"
        "deb http://archive.ubuntu.com/ubuntu/ jammy-updates main restricted universe multiverse\n"
        "deb http://archive.ubuntu.com/ubuntu/ jammy-security main restricted universe multiverse\n"
        "deb http://archive.ubuntu.com/ubuntu/ jammy-backports main restricted universe multiverse\n"
    )
    Path(f"{TARGET_MOUNT}/etc/apt/sources.list").write_text(sources)

    progress_cb(48, "Installing system packages …")
    run_chroot("apt-get update -qq")
    run_chroot(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
        "linux-image-generic linux-headers-generic "
        "grub-pc grub-efi-amd64 grub-common shim-signed "
        "python3 python3-pip python3-flask python3-flask-socketio "
        "qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virtinst "
        "nginx parted dosfstools e2fsprogs "
        "curl wget git systemd openssh-server "
        "iproute2 iputils-ping net-tools sudo "
        "netplan.io cloud-utils"
    )

    progress_cb(65, "Installing Python dependencies …")
    # requirements.txt repoyla gelir — önce oradan kur
    _req_path = f"{TARGET_MOUNT}/opt/oxware/oxware/backend/requirements.txt"
    if Path(_req_path).exists():
        run_chroot(
            "pip3 install --no-cache-dir --break-system-packages "
            f"-r /opt/oxware/oxware/backend/requirements.txt",
            check=False
        )
    else:
        # Fallback: temel paketleri elle kur
        run_chroot(
            "pip3 install --no-cache-dir --break-system-packages "
            "flask==3.0.3 flask-socketio==5.3.6 flask-jwt-extended==4.6.0 flask-cors==4.0.1 "
            "eventlet==0.35.2 cryptography>=43.0.0 requests>=2.32.3 psutil==5.9.8 "
            "libvirt-python==10.3.0 paramiko==3.4.0 pyOpenSSL==24.2.1 "
            "urllib3>=2.3.0 Jinja2>=3.1.6 python-dotenv==1.0.1 "
            "pyotp==2.9.0 qrcode[pil]==8.0 anthropic==0.32.0",
            check=False
        )

    progress_cb(70, "Installing OXware from GitHub …")
    target_oxware = Path(f"{TARGET_MOUNT}/opt/oxware")
    if target_oxware.exists():
        shutil.rmtree(str(target_oxware))

    # Clone from GitHub so future updates work via git pull (no reinstall needed)
    GITHUB_REPO = "https://github.com/ShinnAsukha/oxware-hypervisor.git"
    clone_result = subprocess.run(
        ["git", "clone", "--depth=1", GITHUB_REPO, str(target_oxware)],
        capture_output=True, text=True, timeout=300
    )
    if clone_result.returncode != 0:
        # Fallback: copy from ISO if no internet
        if Path(OXWARE_SRC).exists():
            shutil.copytree(OXWARE_SRC, str(target_oxware))
            # Write a marker so user knows git pull won't work
            Path(f"{TARGET_MOUNT}/opt/oxware/.no-git-remote").write_text(
                "Installed from ISO without internet. Run:\n"
                "  cd /opt/oxware && git init && git remote add origin "
                "https://github.com/ShinnAsukha/oxware-hypervisor.git\n"
                "  git fetch && git reset --hard origin/main\n"
            )
        else:
            target_oxware.mkdir(parents=True, exist_ok=True)

    progress_cb(73, "Writing system configuration …")
    # hostname
    Path(f"{TARGET_MOUNT}/etc/hostname").write_text(state.hostname + "\n")

    # /etc/hosts
    hosts = (
        f"127.0.0.1   localhost\n"
        f"127.0.1.1   {state.hostname}\n"
        f"::1         localhost ip6-localhost ip6-loopback\n"
    )
    Path(f"{TARGET_MOUNT}/etc/hosts").write_text(hosts)

    # Network — use netplan (Ubuntu 22.04 standard).
    # net.ifnames=0 in GRUB cmdline forces eth0 naming so match works reliably.
    netplan_dir = Path(f"{TARGET_MOUNT}/etc/netplan")
    netplan_dir.mkdir(parents=True, exist_ok=True)
    if state.net_mode == "dhcp":
        netplan_cfg = (
            "network:\n"
            "  version: 2\n"
            "  ethernets:\n"
            "    eth0:\n"
            "      dhcp4: true\n"
            "      dhcp6: false\n"
        )
    else:
        # Convert netmask to CIDR
        def _mask_to_prefix(mask):
            try:
                mask = str(mask).strip()
                # Pure CIDR integer string e.g. "24"
                if mask.isdigit():
                    return int(mask)
                # Dotted notation e.g. "255.255.255.0"
                return sum(bin(int(o)).count('1') for o in mask.split('.'))
            except Exception:
                return 24
        prefix = _mask_to_prefix(state.netmask)
        netplan_cfg = (
            "network:\n"
            "  version: 2\n"
            "  ethernets:\n"
            "    eth0:\n"
            "      dhcp4: false\n"
            f"      addresses: [{state.ip}/{prefix}]\n"
            f"      routes:\n"
            f"        - to: default\n"
            f"          via: {state.gateway}\n"
            f"      nameservers:\n"
            f"        addresses: [{state.dns}]\n"
        )
    netplan_file = netplan_dir / "01-oxware.yaml"
    netplan_file.write_text(netplan_cfg)
    os.chmod(str(netplan_file), 0o600)

    # OXware credentials — write .passwd_reset so backend calls first_setup() on boot.
    # Backend reads /etc/oxware/.auth (PBKDF2-encrypted), NOT admin.json.
    # apply_reset_if_exists() is called at app.py startup and will populate .auth.
    oxware_cfg_dir = Path(f"{TARGET_MOUNT}/etc/oxware")
    oxware_cfg_dir.mkdir(parents=True, exist_ok=True)
    passwd_reset = oxware_cfg_dir / ".passwd_reset"
    passwd_reset.write_text(f"USERNAME={state.username}\nPASSWORD={state.password}\n")
    os.chmod(str(passwd_reset), 0o600)
    # Pre-create .setup_done so the web UI shows dashboard (not setup wizard).
    # Backend deletes .passwd_reset and populates .auth on first start.
    setup_done = oxware_cfg_dir / ".setup_done"
    setup_done.write_text(f"setup_completed={time.time()}\n")
    os.chmod(str(setup_done), 0o600)

    # root password in chroot — pass via stdin to avoid shell injection with special chars
    subprocess.run(
        ["chroot", TARGET_MOUNT, "/bin/bash", "-c", "chpasswd"],
        input=f"root:{state.password}\n",
        text=True, check=True
    )

    progress_cb(78, "Installing GRUB bootloader …")

    # Force traditional eth0 interface naming (predictable names break netplan match)
    grub_default_file = Path(f"{TARGET_MOUNT}/etc/default/grub")
    grub_default_content = (
        'GRUB_DEFAULT=0\n'
        'GRUB_TIMEOUT=5\n'
        'GRUB_DISTRIBUTOR="OXware"\n'
        'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash=0 loglevel=3 '
        'net.ifnames=0 biosdevname=0 apparmor=0 plymouth.enable=0"\n'
        'GRUB_CMDLINE_LINUX=""\n'
        'GRUB_TERMINAL=console\n'
    )
    grub_default_file.parent.mkdir(parents=True, exist_ok=True)
    grub_default_file.write_text(grub_default_content)

    # Set locale/timezone
    _locale = getattr(state, 'locale',   'tr_TR.UTF-8')
    _tz     = getattr(state, 'timezone', 'Europe/Istanbul')
    run_chroot(f"locale-gen {_locale}", check=False)
    if _locale != 'en_US.UTF-8':
        run_chroot("locale-gen en_US.UTF-8", check=False)
    run_chroot(f"update-locale LANG={_locale}", check=False)
    run_chroot(f"ln -sf /usr/share/zoneinfo/{_tz} /etc/localtime", check=False)
    run_chroot(f"bash -c \"echo '{_tz}' > /etc/timezone\"", check=False)

    # Keyboard layout
    progress_cb(74, "Klavye düzeni yapılandırılıyor...")
    _kbd_layout  = getattr(state, 'keyboard_layout',  'tr')
    _kbd_variant = getattr(state, 'keyboard_variant', '')
    Path(f"{TARGET_MOUNT}/etc/default/keyboard").write_text(
        f'XKBMODEL="pc105"\n'
        f'XKBLAYOUT="{_kbd_layout}"\n'
        f'XKBVARIANT="{_kbd_variant}"\n'
        f'XKBOPTIONS=""\n'
        f'BACKSPACE="guess"\n'
    )

    run_chroot(f"grub-install --target=i386-pc --recheck {disk}")
    run_chroot(
        f"grub-install --target=x86_64-efi --efi-directory=/boot/efi "
        f"--bootloader-id=OXware --removable --recheck",
        check=False
    )
    run_chroot("update-grub")

    progress_cb(83, "Writing oxware systemd service …")
    # Repo yapısı: git clone → /opt/oxware/  içinde oxware/backend/app.py var
    # Yani gerçek yol: /opt/oxware/oxware/backend/app.py
    svc = """\
[Unit]
Description=OXware Hypervisor Backend
After=network.target libvirtd.service
Wants=libvirtd.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/oxware/oxware/backend
ExecStartPre=/bin/bash -c 'mkdir -p /var/log/oxware /etc/oxware /var/lib/oxware'
ExecStartPre=/bin/bash -c 'pip3 install --quiet --no-cache-dir --break-system-packages urllib3 Jinja2 cryptography >> /var/log/oxware/pip.log 2>&1 || true'
ExecStart=/usr/bin/python3 /opt/oxware/oxware/backend/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=OXWARE_CONFIG=/etc/oxware/oxware.conf
StandardOutput=append:/var/log/oxware/oxware.log
StandardError=append:/var/log/oxware/oxware-error.log

[Install]
WantedBy=multi-user.target
"""
    svc_dir = Path(f"{TARGET_MOUNT}/etc/systemd/system")
    svc_dir.mkdir(parents=True, exist_ok=True)
    (svc_dir / "oxware.service").write_text(svc)

    # nginx proxy config
    nginx_cfg = """\
server {
    listen 80 default_server;
    location / {
        proxy_pass https://127.0.0.1:8006;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
"""
    nginx_sites = Path(f"{TARGET_MOUNT}/etc/nginx/sites-available")
    nginx_sites.mkdir(parents=True, exist_ok=True)
    (nginx_sites / "oxware").write_text(nginx_cfg)

    progress_cb(85, "Creating system user …")
    safe_user = re.sub(r'[^a-z0-9_-]', '', state.username.lower()) or "oxadmin"
    run_chroot(
        f"id -u {safe_user} &>/dev/null || "
        f"useradd -m -s /bin/bash -G sudo,libvirt,kvm {safe_user}",
        check=False
    )
    subprocess.run(
        ["chroot", TARGET_MOUNT, "/bin/bash", "-c", "chpasswd"],
        input=f"{safe_user}:{state.password}\n",
        text=True, check=False
    )

    # SSH configuration
    progress_cb(86, "SSH yapılandırılıyor...")
    _ssh_en     = getattr(state, 'ssh_enabled',    True)
    _ssh_port   = getattr(state, 'ssh_port',       22)
    _ssh_root   = getattr(state, 'ssh_root',       False)
    _ssh_passwd = getattr(state, 'ssh_passwd_auth', True)
    sshd_extra = (
        "\n# OXware installer configuration\n"
        f"Port {_ssh_port}\n"
        f"PermitRootLogin {'yes' if _ssh_root else 'prohibit-password'}\n"
        f"PasswordAuthentication {'yes' if _ssh_passwd else 'no'}\n"
        "PubkeyAuthentication yes\n"
        "ChallengeResponseAuthentication no\n"
        "PrintMotd no\n"
    )
    sshd_cfg_path = Path(f"{TARGET_MOUNT}/etc/ssh/sshd_config")
    if sshd_cfg_path.exists():
        sshd_cfg_path.write_text(sshd_cfg_path.read_text() + sshd_extra)
    else:
        sshd_cfg_path.parent.mkdir(parents=True, exist_ok=True)
        sshd_cfg_path.write_text(sshd_extra)

    # Static DNS — break systemd-resolved symlink, write permanent resolv.conf
    progress_cb(87, "DNS kalıcı yapılandırılıyor...")
    resolv_path = Path(f"{TARGET_MOUNT}/etc/resolv.conf")
    if resolv_path.is_symlink():
        resolv_path.unlink()
    resolv_path.write_text(
        "# OXware static DNS — set by installer\n"
        "nameserver 8.8.8.8\n"
        "nameserver 1.1.1.1\n"
        "nameserver 8.8.4.4\n"
    )

    # DNS watchdog script
    watchdog_script = """\
#!/bin/bash
# OXware DNS watchdog — runs every 5 min via systemd timer
# If DNS fails, restores resolv.conf and triggers git pull + service restart

LOGFILE="/var/log/oxware/dns-watchdog.log"
RESOLV="/etc/resolv.conf"
STATIC_DNS="nameserver 8.8.8.8\\nnameserver 1.1.1.1\\nnameserver 8.8.4.4"
OXWARE_DIR="/opt/oxware"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"; }

# Check DNS
if ! getent hosts github.com > /dev/null 2>&1; then
    log "DNS failed — restoring resolv.conf"
    # Break symlink if present, write static
    [ -L "$RESOLV" ] && rm -f "$RESOLV"
    printf "$STATIC_DNS\\n" > "$RESOLV"
    log "resolv.conf restored"

    # Wait and recheck
    sleep 3
    if getent hosts github.com > /dev/null 2>&1; then
        log "DNS recovered — running git pull"
        cd "$OXWARE_DIR" && git pull --ff-only >> "$LOGFILE" 2>&1 && \\
            systemctl restart oxware >> "$LOGFILE" 2>&1
        log "oxware restarted after update"
    else
        log "DNS still failed after fix — check network"
    fi
else
    # DNS OK — check if update available (silent)
    cd "$OXWARE_DIR" && git fetch --quiet 2>/dev/null
    LOCAL=$(git rev-parse HEAD 2>/dev/null)
    REMOTE=$(git rev-parse '@{u}' 2>/dev/null)
    if [ "$LOCAL" != "$REMOTE" ] && [ -n "$REMOTE" ]; then
        log "Update available — pulling"
        git pull --ff-only >> "$LOGFILE" 2>&1 && \\
            systemctl restart oxware >> "$LOGFILE" 2>&1
        log "oxware updated and restarted"
    fi
fi
"""
    scripts_dir = Path(f"{TARGET_MOUNT}/opt/oxware-scripts")
    scripts_dir.mkdir(parents=True, exist_ok=True)
    watchdog_path = scripts_dir / "dns-watchdog.sh"
    watchdog_path.write_text(watchdog_script)
    os.chmod(str(watchdog_path), 0o755)

    # systemd service for watchdog
    watchdog_svc = """\
[Unit]
Description=OXware DNS Watchdog & Auto-Update
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/oxware-scripts/dns-watchdog.sh
StandardOutput=append:/var/log/oxware/dns-watchdog.log
StandardError=append:/var/log/oxware/dns-watchdog.log
"""
    watchdog_timer = """\
[Unit]
Description=OXware DNS Watchdog Timer
Requires=oxware-dns-watchdog.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
"""
    (svc_dir / "oxware-dns-watchdog.service").write_text(watchdog_svc)
    (svc_dir / "oxware-dns-watchdog.timer").write_text(watchdog_timer)

    progress_cb(88, "Enabling services …")
    run_chroot("systemctl enable libvirtd",               check=False)
    run_chroot("systemctl enable nginx",                  check=False)
    run_chroot("systemctl enable oxware",                 check=False)
    run_chroot("systemctl enable oxware-dns-watchdog.timer", check=False)
    if _ssh_en:
        run_chroot("systemctl enable ssh",    check=False)
    else:
        run_chroot("systemctl disable ssh",   check=False)
    run_chroot("systemctl enable netplan-wpa-supplicant", check=False)
    run_chroot(
        "cd /etc/nginx/sites-enabled && "
        "ln -sf ../sites-available/oxware oxware && "
        "rm -f default",
        check=False
    )

    # fstab
    progress_cb(90, "Writing fstab …")
    efi_uuid_r = run(f"blkid -s UUID -o value {blk(2)}", capture=True, check=False)
    root_uuid_r = run(f"blkid -s UUID -o value {blk(3)}", capture=True, check=False)
    efi_uuid  = efi_uuid_r.stdout.strip()
    root_uuid = root_uuid_r.stdout.strip()
    fstab = (
        f"UUID={root_uuid} /         ext4 errors=remount-ro 0 1\n"
        f"UUID={efi_uuid}  /boot/efi vfat umask=0077       0 1\n"
    )
    Path(f"{TARGET_MOUNT}/etc/fstab").write_text(fstab)

    progress_cb(94, "Unmounting filesystems …")
    for mp in [f"{TARGET_MOUNT}/dev/pts",
               f"{TARGET_MOUNT}/dev",
               f"{TARGET_MOUNT}/sys",
               f"{TARGET_MOUNT}/proc",
               f"{TARGET_MOUNT}/boot/efi",
               TARGET_MOUNT]:
        run(f"umount -lf {mp}", check=False)

    progress_cb(98, "Syncing disks …")
    run("sync")

    progress_cb(100, "Installation complete!")


def screen_progress(win):
    """Screen 8: clean full-screen progress bar — install runs in background thread."""
    h, w = win.getmaxyx()

    # Shared state between thread and UI
    pct_state  = [0]
    step_state = ["Hazırlanıyor…"]
    error_msg  = [None]
    done_flag  = [False]
    lock       = threading.Lock()

    def progress_cb(pct, msg):
        with lock:
            pct_state[0]  = pct
            step_state[0] = msg

    def install_thread():
        try:
            do_install(progress_cb)
        except Exception as e:
            with lock:
                error_msg[0] = str(e)
        finally:
            with lock:
                done_flag[0] = True

    t = threading.Thread(target=install_thread, daemon=True)
    t.start()

    win.nodelay(True)
    spinner = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    spin_i  = 0

    while True:
        with lock:
            pct  = pct_state[0]
            step = step_state[0]
            done = done_flag[0]
            err  = error_msg[0]

        # ── draw ──────────────────────────────────────────────────────────
        try:
            win.erase()
            # Title bar
            win.attron(curses.color_pair(CP_HEADER) | curses.A_BOLD)
            win.addstr(0, 0, " OXware Hypervisor ".center(w - 1))
            win.attroff(curses.color_pair(CP_HEADER) | curses.A_BOLD)

            # Big ASCII logo (mini)
            logo = "OXWARE"
            logo_col = max(0, (w - len(logo)) // 2)
            try:
                win.addstr(2, logo_col, logo,
                           curses.color_pair(CP_BORDER) | curses.A_BOLD)
            except curses.error:
                pass

            # Status line
            spin = spinner[spin_i % len(spinner)] if not done else "✓"
            status = f" {spin}  Kuruluyor…  —  %{pct}" if not done else " ✓  Kurulum tamamlandı!"
            try:
                win.addstr(4, (w - len(status)) // 2, status,
                           curses.color_pair(CP_NORMAL) | curses.A_BOLD)
            except curses.error:
                pass

            # Big progress bar (full width - 8 margin)
            bar_col = 4
            bar_w   = max(10, w - 8)
            bar_row = 6
            filled  = int(bar_w * pct / 100)
            bar_str = "█" * filled + "░" * (bar_w - filled)
            try:
                win.addstr(bar_row, bar_col, bar_str,
                           curses.color_pair(CP_PROGRESS) | curses.A_BOLD)
            except curses.error:
                pass

            # Percentage centered below bar
            pct_str = f"{pct}%"
            try:
                win.addstr(bar_row + 1, (w - len(pct_str)) // 2, pct_str,
                           curses.color_pair(CP_INPUT) | curses.A_BOLD)
            except curses.error:
                pass

            # Current step
            step_short = step[:w - 6]
            try:
                win.addstr(bar_row + 3, (w - len(step_short)) // 2, step_short,
                           curses.color_pair(CP_DIM))
            except curses.error:
                pass

            # Estimated steps hint
            steps_hint = "Disk bölümleniyor → Debian kuruluyor → Paketler → OXware → GRUB"
            if len(steps_hint) < w - 4:
                try:
                    win.addstr(bar_row + 5, (w - len(steps_hint)) // 2, steps_hint,
                               curses.color_pair(CP_DIM))
                except curses.error:
                    pass

            # Done / error prompt
            if done and not err:
                msg = "[ ENTER — Devam ]"
                try:
                    win.addstr(h - 3, (w - len(msg)) // 2, msg,
                               curses.color_pair(CP_HEADER) | curses.A_BOLD)
                except curses.error:
                    pass
            elif err:
                errl = f"HATA: {err}"[:w - 4]
                try:
                    win.addstr(h - 5, (w - len(errl)) // 2, errl,
                               curses.color_pair(CP_ERROR) | curses.A_BOLD)
                    hint = "[ Q — Çık ]   [ R — Disk Seçimine Dön ]"
                    win.addstr(h - 3, (w - len(hint)) // 2, hint,
                               curses.color_pair(CP_NORMAL))
                except curses.error:
                    pass

            win.refresh()
        except curses.error:
            pass

        spin_i += 1
        time.sleep(0.12)

        # ── key handling ──────────────────────────────────────────────────
        try:
            key = win.getch()
        except curses.error:
            key = -1

        if done and not err and key in (10, 13, curses.KEY_ENTER):
            win.nodelay(False)
            return ("next", None)
        if err:
            if key in (ord('q'), ord('Q')):
                win.nodelay(False)
                return ("error", err)
            if key in (ord('r'), ord('R')):
                win.nodelay(False)
                return ("restart", err)


def screen_done(win):
    """Screen 9: done."""
    while True:
        draw_frame(win)
        h, w = win.getmaxyx()
        top, left, ch, cw = content_area(win)

        center_str(win, top + 3,
                   "Installation Complete!",
                   curses.color_pair(CP_PROGRESS) | curses.A_BOLD)
        center_str(win, top + 5,
                   "OXware Hypervisor has been installed successfully.",
                   curses.color_pair(CP_NORMAL))
        center_str(win, top + 7,
                   "After reboot, the web interface will be available at:",
                   curses.color_pair(CP_NORMAL))
        center_str(win, top + 8,
                   f"  https://<server-ip>:8006  ",
                   curses.color_pair(CP_INPUT) | curses.A_BOLD)
        center_str(win, top + 10,
                   f"Credentials: {state.username} / (password you set)",
                   curses.color_pair(CP_DIM))
        center_str(win, top + 13,
                   "[ Press ENTER to reboot ]",
                   curses.color_pair(CP_HEADER) | curses.A_BOLD)

        win.refresh()
        key = win.getch()
        if key in (10, 13, curses.KEY_ENTER):
            return "reboot"
        if key in (ord('q'), ord('Q')):
            return "quit"


def screen_error(win, message):
    """Error screen."""
    while True:
        draw_frame(win)
        h, w = win.getmaxyx()
        top, left, ch, cw = content_area(win)

        try:
            win.addstr(top, left + 2,
                       " Installation Error ",
                       curses.color_pair(CP_ERROR) | curses.A_BOLD)
            center_str(win, top + 3,
                       "An error occurred during installation:",
                       curses.color_pair(CP_ERROR) | curses.A_BOLD)
        except curses.error:
            pass

        wrapped = textwrap.wrap(message, cw - 4)
        for i, line in enumerate(wrapped[:10]):
            try:
                win.addstr(top + 5 + i, left + 2, line,
                           curses.color_pair(CP_NORMAL))
            except curses.error:
                pass

        center_str(win, top + ch - 2,
                   "[ Q = Quit ]  [ R = Retry from disk selection ]",
                   curses.color_pair(CP_DIM))

        win.refresh()
        key = win.getch()
        if key in (ord('q'), ord('Q')):
            return "quit"
        if key in (ord('r'), ord('R')):
            return "retry"


# ── main flow ──────────────────────────────────────────────────────────────────

def confirm_quit(win):
    h, w = win.getmaxyx()
    qwin = curses.newwin(7, 40, h // 2 - 3, (w - 40) // 2)
    qwin.bkgd(' ', curses.color_pair(CP_ERROR))
    qwin.border(0)
    try:
        qwin.addstr(1, 2, "  Quit the installer?  ",
                    curses.color_pair(CP_ERROR) | curses.A_BOLD)
        qwin.addstr(3, 2, "  [Y] Yes, quit   [N] No, continue  ",
                    curses.color_pair(CP_ERROR))
    except curses.error:
        pass
    qwin.refresh()
    while True:
        key = qwin.getch()
        if key in (ord('y'), ord('Y')):
            return True
        if key in (ord('n'), ord('N'), 27):
            return False


def main(stdscr):
    curses.curs_set(0)
    init_colors()
    stdscr.keypad(True)
    curses.noecho()

    SCREENS = [
        screen_welcome,
        screen_license,
        screen_disk,
        screen_network,
        screen_hostname,
        screen_password,
        screen_summary,
    ]

    idx = 0
    while True:
        if idx < 0:
            idx = 0
        if idx < len(SCREENS):
            result = SCREENS[idx](stdscr)
            if result == "next":
                idx += 1
            elif result == "back":
                idx = max(0, idx - 1)
            elif result == "quit":
                if confirm_quit(stdscr):
                    return
        else:
            # Installation screen
            result, err = screen_progress(stdscr)
            if result == "error":
                action = screen_error(stdscr, err or "Unknown error")
                if action == "retry":
                    idx = 2  # back to disk selection
                else:
                    return
            else:
                action = screen_done(stdscr)
                if action == "reboot":
                    try:
                        run("reboot", check=False)
                    except Exception:
                        pass
                return


# ── Headless mode (called from web installer via --headless config.json) ──
def _headless_main(config_file: str):
    """Run installation headless, output JSON progress lines to stdout."""
    import json as _json
    with open(config_file) as f:
        cfg = _json.load(f)

    state.disk     = cfg.get('disk', '')
    state.hostname = cfg.get('hostname', 'oxware')
    state.username = cfg.get('username', 'oxadmin')
    state.password = cfg.get('password', 'oxware123')
    state.net_mode = cfg.get('net_mode', 'dhcp')
    # Attribute names must match what do_install() reads from state.*
    state.ip       = cfg.get('net_ip', '')
    state.netmask  = cfg.get('net_mask', '255.255.255.0')
    state.gateway  = cfg.get('net_gw', '')
    state.dns      = cfg.get('net_dns', '8.8.8.8')
    state.keyboard_layout  = cfg.get('keyboard_layout',  'tr')
    state.keyboard_variant = cfg.get('keyboard_variant', '')
    state.locale           = cfg.get('locale',        'tr_TR.UTF-8')
    state.timezone         = cfg.get('timezone',       'Europe/Istanbul')
    state.ssh_enabled      = cfg.get('ssh_enabled',   True)
    state.ssh_port         = int(cfg.get('ssh_port',  22))
    state.ssh_root         = cfg.get('ssh_root',      False)
    state.ssh_passwd_auth  = cfg.get('ssh_passwd_auth', True)

    def progress_cb(pct, msg):
        print(_json.dumps({'pct': pct, 'msg': msg}), flush=True)

    try:
        do_install(progress_cb)
        print(_json.dumps({'pct': 100, 'msg': 'Kurulum tamamlandı!', 'done': True}), flush=True)
    except Exception as e:
        print(_json.dumps({'error': str(e), 'done': True}), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == '--headless':
        _headless_main(sys.argv[2])
        sys.exit(0)
    if os.geteuid() != 0:
        print("ERROR: This installer must be run as root.", file=sys.stderr)
        sys.exit(1)
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        print("\nInstallation cancelled.")
        sys.exit(1)
    except Exception as exc:
        print(f"\nFatal error: {exc}", file=sys.stderr)
        sys.exit(1)
