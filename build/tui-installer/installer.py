#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OXware Hypervisor — Curses TUI Installer
Proxmox-style, stdlib only, 80x24 minimum terminal.
"""

import curses
import json
import os
import subprocess
import sys
import threading
import textwrap
import time

# ──────────────────────────────────────────────────────────
#  ASCII LOGO
# ──────────────────────────────────────────────────────────
LOGO = [
    "  ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ██████╗ ███████╗",
    " ██╔═══██╗╚██╗██╔╝██║    ██║██╔══██╗██╔══██╗██╔════╝",
    " ██║   ██║ ╚███╔╝ ██║ █╗ ██║███████║██████╔╝█████╗  ",
    " ██║   ██║ ██╔██╗ ██║███╗██║██╔══██║██╔══██╗██╔══╝  ",
    " ╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║██║  ██║███████╗",
    "  ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝",
]

SUBTITLE = "Hypervisor Kurulum Sihirbazı  v1.0"

STEPS = [
    "1.Lisans",
    "2.Disk",
    "3.Ağ",
    "4.Yönetici",
    "5.Özet",
    "6.Kurulum",
]

LICENSE_TEXT = """\
OXware Hypervisor Lisans Sözleşmesi

Bu yazılım, açık kaynak bileşenler içermektedir:

  • KVM/QEMU — GNU Genel Kamu Lisansı (GPL v2)
  • libvirt   — GNU Kısıtlı Genel Kamu Lisansı (LGPL v2.1)
  • Python    — Python Yazılım Vakfı Lisansı (PSF)
  • QEMU-img — GPL v2

Bu yazılım "OLDUĞU GİBİ" sunulmaktadır; açık ya da zımni hiçbir
garanti verilmemektedir. Üretici, bu yazılımın kullanımından
doğabilecek herhangi bir hasardan sorumlu tutulamaz.

Kurulum yalnızca yetkili donanım üzerinde gerçekleştirilmelidir.
Lisanssız çoğaltma ve dağıtım yasaktır.

Bu sözleşmeyi kabul etmek için → veya PgDn tuşuna basın.
"""

# ──────────────────────────────────────────────────────────
#  COLOR PAIR IDs
# ──────────────────────────────────────────────────────────
CP_LOGO      = 1
CP_TITLE     = 2
CP_BORDER    = 3
CP_STEP_ACTIVE = 4
CP_STEP_DONE = 5
CP_STEP_IDLE = 6
CP_INPUT     = 7
CP_SEL       = 8
CP_FOOTER    = 9
CP_ERR       = 10
CP_OK        = 11
CP_WARN      = 12
CP_PROG      = 13
CP_PROGBG    = 14
CP_LABEL     = 15

# ──────────────────────────────────────────────────────────
#  STATE
# ──────────────────────────────────────────────────────────
class S:
    step      = 0
    disk      = ""
    disk_size = ""
    disk_model= ""
    fs_type   = "ext4"
    swap      = True
    iface     = ""
    net_mode  = "dhcp"
    net_ip    = ""
    net_mask  = "24"
    net_gw    = ""
    net_dns   = "8.8.8.8"
    hostname  = "oxware"
    username  = "oxware"
    password  = ""
    password2 = ""
    # runtime
    disks     = []
    ifaces    = []
    pct       = 0
    msg       = ""
    log_lines = []
    done      = False
    error     = ""

st = S()

# Module-level selection indices
_disk_sel  = 0
_iface_sel = 0

# ──────────────────────────────────────────────────────────
#  LAYOUT
# ──────────────────────────────────────────────────────────
HEADER_H = len(LOGO) + 4   # logo lines + subtitle + hline + steps + hline
FOOTER_H = 2               # hline + keys line

def content_bounds(scr):
    h, w = scr.getmaxyx()
    ty = HEADER_H
    by = h - FOOTER_H - 1
    # returns: top_y, left_x, bottom_y, right_x, content_height, content_width
    return ty, 2, by, w - 2, by - ty, w - 4

# ──────────────────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────────────────
def safeadd(win, y, x, s, attr=0):
    """addstr wrapper that never raises on edge hits."""
    h, w = win.getmaxyx()
    if not (0 <= y < h):
        return
    x = max(0, x)
    avail = w - x
    if avail <= 0:
        return
    s = s[:avail]
    try:
        win.addstr(y, x, s, attr)
    except curses.error:
        pass


def hline(scr, y, attr=0):
    h, w = scr.getmaxyx()
    if 0 <= y < h:
        try:
            scr.hline(y, 0, curses.ACS_HLINE, w, attr)
        except curses.error:
            pass


def center_str(text, width):
    pad = max(0, (width - len(text)) // 2)
    return " " * pad + text


# ──────────────────────────────────────────────────────────
#  COLOR INIT
# ──────────────────────────────────────────────────────────
def init_colors():
    curses.start_color()
    curses.use_default_colors()

    curses.init_pair(CP_LOGO,         curses.COLOR_YELLOW,  curses.COLOR_BLACK)
    curses.init_pair(CP_TITLE,        curses.COLOR_WHITE,   curses.COLOR_BLACK)
    curses.init_pair(CP_BORDER,       curses.COLOR_CYAN,    curses.COLOR_BLACK)
    curses.init_pair(CP_STEP_ACTIVE,  curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(CP_STEP_DONE,    curses.COLOR_GREEN,   curses.COLOR_BLACK)
    curses.init_pair(CP_STEP_IDLE,    curses.COLOR_WHITE,   curses.COLOR_BLACK)
    curses.init_pair(CP_INPUT,        curses.COLOR_WHITE,   curses.COLOR_BLUE)
    curses.init_pair(CP_SEL,          curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(CP_FOOTER,       curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(CP_ERR,          curses.COLOR_RED,     curses.COLOR_BLACK)
    curses.init_pair(CP_OK,           curses.COLOR_GREEN,   curses.COLOR_BLACK)
    curses.init_pair(CP_WARN,         curses.COLOR_YELLOW,  curses.COLOR_BLACK)
    curses.init_pair(CP_PROG,         curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(CP_PROGBG,       curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(CP_LABEL,        curses.COLOR_CYAN,    curses.COLOR_BLACK)

# ──────────────────────────────────────────────────────────
#  HARDWARE PROBING
# ──────────────────────────────────────────────────────────
def get_disks():
    """Return list of dicts: {path, size_gb, model}"""
    disks = []
    try:
        raw = subprocess.check_output(
            ["lsblk", "-J", "-b", "-o", "NAME,SIZE,TYPE,MODEL"],
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        data = json.loads(raw)
        for dev in data.get("blockdevices", []):
            if dev.get("type") == "disk":
                name  = dev.get("name", "")
                size  = dev.get("size") or 0
                model = (dev.get("model") or "").strip()
                try:
                    size_gb = f"{int(size) // (1024**3)} GB"
                except (ValueError, TypeError):
                    size_gb = "? GB"
                disks.append({
                    "path":  f"/dev/{name}",
                    "size":  size_gb,
                    "model": model or "—",
                })
    except Exception:
        # Fallback for testing / non-Linux environments
        disks.append({"path": "/dev/sda", "size": "120 GB", "model": "Simüle Disk"})
    return disks


def get_ifaces():
    """Return list of non-loopback/virtual interface names."""
    ifaces = []
    try:
        raw = subprocess.check_output(
            "ip -o link show | awk -F': ' '{print $2}' | grep -Ev '^(lo|wl|vir|docker|br|veth|dummy|tun)'",
            shell=True,
            stderr=subprocess.DEVNULL,
            timeout=10,
        ).decode()
        for line in raw.splitlines():
            name = line.strip().split("@")[0]
            if name:
                ifaces.append(name)
    except Exception:
        ifaces.append("eth0")
    return ifaces

# ──────────────────────────────────────────────────────────
#  INPUT EDITOR
# ──────────────────────────────────────────────────────────
def read_input(scr, y, x, width, initial="", password=False):
    """Edit a field in place. Returns new value (or original on Esc)."""
    curses.curs_set(1)
    val = list(initial)
    while True:
        display = ("*" * len(val)) if password else "".join(val)
        field   = (display + " " * width)[:width]
        safeadd(scr, y, x, field, curses.color_pair(CP_SEL))
        cx = min(x + len(display), x + width - 1)
        try:
            scr.move(y, cx)
        except curses.error:
            pass
        scr.refresh()
        ch = scr.getch()
        if ch in (10, 13):
            break
        elif ch == 27:
            val = list(initial)
            break
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if val:
                val.pop()
        elif 32 <= ch <= 126:
            if len(val) < width - 1:
                val.append(chr(ch))
    curses.curs_set(0)
    return "".join(val)

# ──────────────────────────────────────────────────────────
#  HEADER / FOOTER DRAWING
# ──────────────────────────────────────────────────────────
def draw_header(scr):
    h, w = scr.getmaxyx()
    logo_attr = curses.color_pair(CP_TITLE) | curses.A_BOLD

    # Draw logo lines centered
    for i, line in enumerate(LOGO):
        cx = max(0, (w - len(line)) // 2)
        safeadd(scr, i, cx, line, logo_attr)

    # Subtitle
    sub_y = len(LOGO)
    safeadd(scr, sub_y, max(0, (w - len(SUBTITLE)) // 2), SUBTITLE,
            curses.color_pair(CP_LABEL) | curses.A_BOLD)

    # Separator after logo
    hline(scr, len(LOGO) + 1, curses.color_pair(CP_BORDER))

    # Step tabs
    tab_y   = len(LOGO) + 2
    tab_x   = 1
    for i, name in enumerate(STEPS):
        label = f" {name} "
        if i == st.step:
            attr = curses.color_pair(CP_STEP_ACTIVE) | curses.A_BOLD
        elif i < st.step:
            attr = curses.color_pair(CP_STEP_DONE)
        else:
            attr = curses.color_pair(CP_STEP_IDLE) | curses.A_DIM
        safeadd(scr, tab_y, tab_x, label, attr)
        tab_x += len(label) + 1

    # Separator after steps
    hline(scr, len(LOGO) + 3, curses.color_pair(CP_BORDER))


def draw_footer(scr, keys_hint):
    h, w = scr.getmaxyx()
    footer_y = h - 2
    hline(scr, footer_y, curses.color_pair(CP_BORDER))
    hint_y   = h - 1
    # Fill footer background
    bg = " " * w
    safeadd(scr, hint_y, 0, bg, curses.color_pair(CP_FOOTER))
    safeadd(scr, hint_y, 1, keys_hint, curses.color_pair(CP_FOOTER))

# ──────────────────────────────────────────────────────────
#  STEP 0 — LİSANS
# ──────────────────────────────────────────────────────────
def draw_step0(scr):
    draw_header(scr)
    ty, lx, by, rx, ch, cw = content_bounds(scr)

    title = "OXware Hypervisor Lisans Sözleşmesi"
    safeadd(scr, ty + 1, lx, title,
            curses.color_pair(CP_TITLE) | curses.A_BOLD)

    lines = LICENSE_TEXT.strip().splitlines()
    row   = ty + 3
    for line in lines:
        if row >= by - 2:
            break
        safeadd(scr, row, lx, line, curses.color_pair(CP_TITLE))
        row += 1

    accept = "[ ✓ Devam etmek için → tuşuna basın ]"
    safeadd(scr, by - 1,
            max(lx, (scr.getmaxyx()[1] - len(accept)) // 2),
            accept,
            curses.color_pair(CP_OK) | curses.A_BOLD)

    draw_footer(scr, "[→ / PgDn] Kabul Et ve İleri  [F10] Çıkış")


def handle_step0(scr, ch):
    if ch in (curses.KEY_RIGHT, curses.KEY_NPAGE, ord('\n'), ord('\r')):
        st.step = 1
    elif ch == curses.KEY_F10:
        return False
    return True

# ──────────────────────────────────────────────────────────
#  STEP 1 — DİSK
# ──────────────────────────────────────────────────────────
FS_TYPES = ["ext4", "xfs", "btrfs"]

def draw_step1(scr):
    global _disk_sel
    draw_header(scr)
    ty, lx, by, rx, ch_h, cw = content_bounds(scr)

    safeadd(scr, ty + 1, lx, "Kurulum Diski Seçin",
            curses.color_pair(CP_TITLE) | curses.A_BOLD)

    # Column header
    hdr = f"{'AYGIT':<14}{'BOYUT':<12}{'MODEL'}"
    safeadd(scr, ty + 3, lx, hdr, curses.color_pair(CP_LABEL) | curses.A_BOLD)
    hline(scr, ty + 4, curses.color_pair(CP_BORDER))

    disks = st.disks if st.disks else [{"path": "—", "size": "—", "model": "—"}]
    for i, d in enumerate(disks):
        row = ty + 5 + i
        if row >= by - 5:
            break
        line = f"{d['path']:<14}{d['size']:<12}{d['model']}"
        if i == _disk_sel:
            prefix_attr = curses.color_pair(CP_SEL) | curses.A_BOLD
            safeadd(scr, row, lx, "▶ " + line, prefix_attr)
        else:
            safeadd(scr, row, lx + 2, line, curses.color_pair(CP_TITLE))

    # FS type
    fs_y = by - 5
    safeadd(scr, fs_y, lx, "Dosya Sistemi: ", curses.color_pair(CP_LABEL))
    fx = lx + 16
    for fst in FS_TYPES:
        bracket = f"[{fst}]"
        if fst == st.fs_type:
            safeadd(scr, fs_y, fx, bracket, curses.color_pair(CP_SEL) | curses.A_BOLD)
        else:
            safeadd(scr, fs_y, fx, bracket, curses.color_pair(CP_STEP_IDLE))
        fx += len(bracket) + 1
    safeadd(scr, fs_y, fx + 2, "(f: değiştir)", curses.color_pair(CP_LABEL))

    # Swap toggle
    swap_y = by - 4
    swap_str = "[x] 4GB swap oluştur" if st.swap else "[ ] 4GB swap oluştur"
    safeadd(scr, swap_y, lx, swap_str,
            curses.color_pair(CP_OK) if st.swap else curses.color_pair(CP_STEP_IDLE))
    safeadd(scr, swap_y, lx + 22, "(s: değiştir)", curses.color_pair(CP_LABEL))

    # Warning
    warn = "⚠  Seçili disk tamamen silinecek!"
    safeadd(scr, by - 2, lx, warn, curses.color_pair(CP_WARN) | curses.A_BOLD)

    draw_footer(scr, "[↑/↓] Disk  [f] FS  [s] Swap  [←] Geri  [→/Enter] İleri  [F10] Çıkış")


def handle_step1(scr, ch):
    global _disk_sel
    ndisks = len(st.disks) if st.disks else 1
    if ch == curses.KEY_UP:
        _disk_sel = max(0, _disk_sel - 1)
    elif ch == curses.KEY_DOWN:
        _disk_sel = min(ndisks - 1, _disk_sel + 1)
    elif ch in (ord('f'), ord('F')):
        idx = FS_TYPES.index(st.fs_type)
        st.fs_type = FS_TYPES[(idx + 1) % len(FS_TYPES)]
    elif ch in (ord('s'), ord('S')):
        st.swap = not st.swap
    elif ch in (curses.KEY_RIGHT, ord('\n'), ord('\r')):
        if st.disks:
            d          = st.disks[_disk_sel]
            st.disk    = d["path"]
            st.disk_size  = d["size"]
            st.disk_model = d["model"]
        st.step = 2
    elif ch == curses.KEY_LEFT:
        st.step = 0
    elif ch == curses.KEY_F10:
        return False
    return True

# ──────────────────────────────────────────────────────────
#  STEP 2 — AĞ
# ──────────────────────────────────────────────────────────
_net_field = 0   # active static field index

def draw_step2(scr):
    global _iface_sel
    draw_header(scr)
    ty, lx, by, rx, ch_h, cw = content_bounds(scr)

    safeadd(scr, ty + 1, lx, "Ağ Yapılandırması",
            curses.color_pair(CP_TITLE) | curses.A_BOLD)

    # Interface tabs
    safeadd(scr, ty + 3, lx, "Arayüz: ", curses.color_pair(CP_LABEL))
    ix = lx + 9
    ifaces = st.ifaces if st.ifaces else ["eth0"]
    for i, iface in enumerate(ifaces):
        label = f" {iface} "
        if i == _iface_sel:
            safeadd(scr, ty + 3, ix, label, curses.color_pair(CP_SEL) | curses.A_BOLD)
        else:
            safeadd(scr, ty + 3, ix, label, curses.color_pair(CP_STEP_IDLE))
        ix += len(label) + 1

    # Mode toggle
    safeadd(scr, ty + 5, lx, "Mod: ", curses.color_pair(CP_LABEL))
    mx = lx + 6
    for mode in ["dhcp", "static"]:
        label = f"[{mode.upper()}]"
        if mode == st.net_mode:
            safeadd(scr, ty + 5, mx, label, curses.color_pair(CP_SEL) | curses.A_BOLD)
        else:
            safeadd(scr, ty + 5, mx, label, curses.color_pair(CP_STEP_IDLE))
        mx += len(label) + 2
    safeadd(scr, ty + 5, mx + 2, "(d: DHCP  s: Statik)", curses.color_pair(CP_LABEL))

    if st.net_mode == "dhcp":
        safeadd(scr, ty + 7, lx, "IP adresi otomatik atanacak.",
                curses.color_pair(CP_OK))
    else:
        fields = [
            ("IP Adresi  :", st.net_ip,   20),
            ("Alt Ağ Mask:", st.net_mask, 4),
            ("Ağ Geçidi  :", st.net_gw,   20),
            ("DNS        :", st.net_dns,  20),
        ]
        safeadd(scr, ty + 7, lx, "Statik IP yapılandırması:",
                curses.color_pair(CP_LABEL))
        field_y = ty + 9
        for i, (label, val, fw) in enumerate(fields):
            safeadd(scr, field_y + i, lx, label, curses.color_pair(CP_LABEL))
            display = (val + " " * fw)[:fw]
            if i == _net_field:
                attr = curses.color_pair(CP_SEL) | curses.A_BOLD
            else:
                attr = curses.color_pair(CP_INPUT)
            safeadd(scr, field_y + i, lx + 14, display, attr)

        safeadd(scr, field_y + len(fields) + 1, lx,
                "[Enter] alanları düzenle",
                curses.color_pair(CP_LABEL))

    draw_footer(scr, "[←/→] Arayüz  [d] DHCP  [s] Statik  [Enter] Düzenle  [←] Geri  [TAB/→] İleri")


def handle_step2(scr, ch):
    global _iface_sel, _net_field
    nifaces = len(st.ifaces) if st.ifaces else 1

    ty, lx, by, rx, ch_h, cw = content_bounds(scr)

    if st.net_mode == "static":
        fields_data = [
            ("net_ip",   "IP Adresi",   st.net_ip,   20),
            ("net_mask", "Alt Ağ Mask", st.net_mask, 4),
            ("net_gw",   "Ağ Geçidi",   st.net_gw,   20),
            ("net_dns",  "DNS",         st.net_dns,  20),
        ]
        field_y = ty + 9

        if ch in (ord('\n'), ord('\r')):
            # Edit current static field
            key, lbl, val, fw = fields_data[_net_field]
            new_val = read_input(scr, field_y + _net_field, lx + 14, fw + 1, val)
            setattr(st, key, new_val)
            _net_field = (_net_field + 1) % len(fields_data)
            return True
        elif ch == curses.KEY_UP:
            _net_field = max(0, _net_field - 1)
            return True
        elif ch == curses.KEY_DOWN:
            _net_field = min(len(fields_data) - 1, _net_field + 1)
            return True

    if ch in (ord('d'), ord('D')):
        st.net_mode = "dhcp"
    elif ch in (ord('s'), ord('S')):
        if st.net_mode != "static":
            st.net_mode = "static"
    elif ch == curses.KEY_LEFT:
        if st.ifaces and _iface_sel > 0:
            _iface_sel -= 1
            st.iface = st.ifaces[_iface_sel]
        elif st.step > 0:
            st.step = 1
    elif ch in (curses.KEY_RIGHT, ord('\t')):
        if st.ifaces and _iface_sel < nifaces - 1:
            _iface_sel += 1
            st.iface = st.ifaces[_iface_sel]
        else:
            if st.ifaces:
                st.iface = st.ifaces[_iface_sel]
            st.step = 3
    elif ch == curses.KEY_F10:
        return False
    return True

# ──────────────────────────────────────────────────────────
#  STEP 3 — YÖNETİCİ
# ──────────────────────────────────────────────────────────
_admin_field = 0
_admin_err   = ""

def draw_step3(scr):
    draw_header(scr)
    ty, lx, by, rx, ch_h, cw = content_bounds(scr)

    safeadd(scr, ty + 1, lx, "Yönetici Hesabı",
            curses.color_pair(CP_TITLE) | curses.A_BOLD)

    fields = [
        ("Sunucu Adı (hostname)  :", st.hostname,  30, False),
        ("Kullanıcı Adı          :", st.username,  30, False),
        ("Parola                 :", st.password,  30, True),
        ("Parola (tekrar)        :", st.password2, 30, True),
    ]

    field_y = ty + 3
    for i, (label, val, fw, pwd) in enumerate(fields):
        safeadd(scr, field_y + i * 2, lx, label, curses.color_pair(CP_LABEL))
        display = ("*" * len(val)) if pwd else val
        display = (display + " " * fw)[:fw]
        if i == _admin_field:
            attr = curses.color_pair(CP_SEL) | curses.A_BOLD
        else:
            attr = curses.color_pair(CP_INPUT)
        safeadd(scr, field_y + i * 2, lx + 25, display, attr)

    # Password match indicator
    indicator_y = field_y + len(fields) * 2
    if st.password and st.password2:
        if st.password == st.password2:
            safeadd(scr, indicator_y, lx, "✓ Parolalar eşleşiyor",
                    curses.color_pair(CP_OK) | curses.A_BOLD)
        else:
            safeadd(scr, indicator_y, lx, "✗ Parolalar eşleşmiyor",
                    curses.color_pair(CP_ERR) | curses.A_BOLD)

    if _admin_err:
        safeadd(scr, indicator_y + 1, lx, _admin_err,
                curses.color_pair(CP_ERR) | curses.A_BOLD)

    safeadd(scr, by - 2, lx, "[Enter] Düzenle   [←] Geri   [→] İleri",
            curses.color_pair(CP_LABEL))

    draw_footer(scr, "[Enter] Düzenle  [←] Geri  [→] İleri  [F10] Çıkış")


def handle_step3(scr, ch):
    global _admin_field, _admin_err
    ty, lx, by, rx, ch_h, cw = content_bounds(scr)

    fields_spec = [
        ("hostname",  30, False),
        ("username",  30, False),
        ("password",  30, True),
        ("password2", 30, True),
    ]
    field_y = ty + 3

    if ch in (ord('\n'), ord('\r')):
        key, fw, pwd = fields_spec[_admin_field]
        old = getattr(st, key)
        new = read_input(scr, field_y + _admin_field * 2, lx + 25, fw + 1, old, pwd)
        setattr(st, key, new)
        _admin_field = (_admin_field + 1) % len(fields_spec)
        _admin_err = ""
        return True
    elif ch == curses.KEY_UP:
        _admin_field = max(0, _admin_field - 1)
    elif ch == curses.KEY_DOWN:
        _admin_field = min(len(fields_spec) - 1, _admin_field + 1)
    elif ch == curses.KEY_LEFT:
        st.step = 2
    elif ch == curses.KEY_RIGHT:
        # Validate
        if not st.hostname.strip():
            _admin_err = "Hata: Sunucu adı boş olamaz."
        elif not st.username.strip():
            _admin_err = "Hata: Kullanıcı adı boş olamaz."
        elif not st.password:
            _admin_err = "Hata: Parola boş olamaz."
        elif st.password != st.password2:
            _admin_err = "Hata: Parolalar eşleşmiyor."
        else:
            _admin_err = ""
            st.step = 4
    elif ch == curses.KEY_F10:
        return False
    return True

# ──────────────────────────────────────────────────────────
#  STEP 4 — ÖZET
# ──────────────────────────────────────────────────────────
def draw_step4(scr):
    draw_header(scr)
    ty, lx, by, rx, ch_h, cw = content_bounds(scr)

    safeadd(scr, ty + 1, lx, "Kurulum Özeti — Lütfen kontrol edin",
            curses.color_pair(CP_TITLE) | curses.A_BOLD)

    rows = [
        ("Disk",            st.disk),
        ("Disk Boyutu",     st.disk_size),
        ("Disk Modeli",     st.disk_model),
        ("Dosya Sistemi",   st.fs_type),
        ("Swap",            "4GB" if st.swap else "Yok"),
        ("Ağ Arayüzü",     st.iface),
        ("Ağ Modu",         "DHCP" if st.net_mode == "dhcp" else "Statik"),
        ("IP",              st.net_ip if st.net_mode == "static" else "Otomatik"),
        ("Alt Ağ",          st.net_mask if st.net_mode == "static" else "—"),
        ("Ağ Geçidi",       st.net_gw  if st.net_mode == "static" else "—"),
        ("DNS",             st.net_dns),
        ("Sunucu Adı",      st.hostname),
        ("Kullanıcı",       st.username),
    ]

    table_y = ty + 3
    for i, (label, val) in enumerate(rows):
        r = table_y + i
        if r >= by - 4:
            break
        safeadd(scr, r, lx,       f"{label:<22}", curses.color_pair(CP_LABEL))
        safeadd(scr, r, lx + 22,  ":",            curses.color_pair(CP_BORDER))
        safeadd(scr, r, lx + 24,  val,            curses.color_pair(CP_TITLE))

    warn = "⚠  DİKKAT: Kurulum başlayınca disk kalıcı olarak silinir!"
    safeadd(scr, by - 3, lx, warn, curses.color_pair(CP_WARN) | curses.A_BOLD)

    confirm = "Başlamak için [Enter] veya [→] tuşuna basın"
    safeadd(scr, by - 2, lx, confirm, curses.color_pair(CP_OK))

    draw_footer(scr, "[←] Geri  [Enter/→] Kurulumu Başlat  [F10] Çıkış")


def handle_step4(scr, ch):
    if ch in (ord('\n'), ord('\r'), curses.KEY_RIGHT):
        st.step = 5
        st.pct = 0
        st.msg = "Kurulum başlatılıyor..."
        st.done  = False
        st.error = ""
        t = threading.Thread(target=_run_install, daemon=True)
        t.start()
    elif ch == curses.KEY_LEFT:
        st.step = 3
    elif ch == curses.KEY_F10:
        return False
    return True

# ──────────────────────────────────────────────────────────
#  BACKGROUND INSTALL
# ──────────────────────────────────────────────────────────
def _run_install():
    # Write JSON config
    config = {
        "disk":       st.disk,
        "fs_type":    st.fs_type,
        "swap":       st.swap,
        "iface":      st.iface,
        "net_mode":   st.net_mode,
        "net_ip":     st.net_ip,
        "net_mask":   st.net_mask,
        "net_gw":     st.net_gw,
        "net_dns":    st.net_dns,
        "hostname":   st.hostname,
        "username":   st.username,
        "password":   st.password,
    }
    config_path = "/tmp/oxware-config.json"
    try:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        st.error = f"Config yazılamadı: {e}"
        st.done  = True
        return

    installer = "/opt/oxware-installer/install.py"
    cmd = ["python3", installer, "--headless", config_path]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            # Try to parse JSON progress
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    if "pct" in data:
                        st.pct = int(data["pct"])
                    if "msg" in data:
                        st.msg = data["msg"]
                    if data.get("done"):
                        st.done = True
                    if "error" in data and data["error"]:
                        st.error = data["error"]
                        st.done  = True
                    continue
                except json.JSONDecodeError:
                    pass
            # Plain log line
            st.log_lines.append(line)
            if len(st.log_lines) > 200:
                st.log_lines = st.log_lines[-200:]

        proc.wait()
        if proc.returncode != 0 and not st.done:
            st.error = f"Installer çıkış kodu: {proc.returncode}"
            st.done  = True
        elif not st.done:
            st.pct  = 100
            st.msg  = "Kurulum tamamlandı."
            st.done = True
    except FileNotFoundError:
        st.error = f"Installer bulunamadı: {installer}"
        st.done  = True
    except Exception as e:
        st.error = str(e)
        st.done  = True

# ──────────────────────────────────────────────────────────
#  STEP 5 — KURULUM
# ──────────────────────────────────────────────────────────
def draw_step5(scr):
    draw_header(scr)
    ty, lx, by, rx, ch_h, cw = content_bounds(scr)

    if st.error:
        title = "Kurulum Başarısız!"
        title_attr = curses.color_pair(CP_ERR) | curses.A_BOLD
    elif st.done:
        title = "Kurulum Tamamlandı!"
        title_attr = curses.color_pair(CP_OK) | curses.A_BOLD
    else:
        title = "Kurulum Devam Ediyor..."
        title_attr = curses.color_pair(CP_TITLE) | curses.A_BOLD

    safeadd(scr, ty + 1, lx, title, title_attr)

    # Progress bar
    bar_y = ty + 3
    bar_w = cw
    filled = max(0, min(bar_w, int(bar_w * st.pct / 100)))
    empty  = bar_w - filled
    safeadd(scr, bar_y, lx,
            "█" * filled,
            curses.color_pair(CP_PROG))
    safeadd(scr, bar_y, lx + filled,
            "░" * empty,
            curses.color_pair(CP_PROGBG))

    pct_str = f"  {st.pct}%"
    safeadd(scr, bar_y, lx + bar_w - len(pct_str),
            pct_str, curses.color_pair(CP_TITLE) | curses.A_BOLD)

    # Current message
    safeadd(scr, bar_y + 2, lx,
            (st.msg + " " * cw)[:cw],
            curses.color_pair(CP_TITLE))

    # Log area
    log_top    = bar_y + 4
    log_bottom = by - 3
    log_h      = log_bottom - log_top
    if log_h > 0:
        visible = st.log_lines[-log_h:]
        for i, line in enumerate(visible):
            safeadd(scr, log_top + i, lx,
                    (line + " " * cw)[:cw],
                    curses.color_pair(CP_STEP_IDLE) | curses.A_DIM)

    # Status line
    if st.error:
        err_msg = f"✗ HATA: {st.error}"
        safeadd(scr, by - 2, lx, err_msg[:cw],
                curses.color_pair(CP_ERR) | curses.A_BOLD)
        safeadd(scr, by - 1, lx, "[q] Çıkış",
                curses.color_pair(CP_FOOTER))
        draw_footer(scr, "[q] Çıkış")
    elif st.done:
        ok_msg = "✓ Kurulum Tamamlandı!"
        safeadd(scr, by - 2, lx, ok_msg,
                curses.color_pair(CP_OK) | curses.A_BOLD)
        draw_footer(scr, "[Enter] Yeniden Başlat  [q] Çıkış")
    else:
        draw_footer(scr, "Lütfen bekleyin...  [F10] İptal")


def handle_step5(scr, ch):
    if st.done and not st.error:
        if ch in (ord('\n'), ord('\r')):
            try:
                subprocess.run(["reboot"], check=False)
            except Exception:
                pass
            return False
    if ch in (ord('q'), ord('Q'), curses.KEY_F10):
        return False
    return True

# ──────────────────────────────────────────────────────────
#  DISPATCH
# ──────────────────────────────────────────────────────────
DRAWERS = [
    draw_step0,
    draw_step1,
    draw_step2,
    draw_step3,
    draw_step4,
    draw_step5,
]

HANDLERS = [
    handle_step0,
    handle_step1,
    handle_step2,
    handle_step3,
    handle_step4,
    handle_step5,
]


def dispatch(scr):
    """
    Get input and dispatch to the current step handler.
    Returns False when the loop should exit.
    """
    if st.step == 5:
        scr.timeout(300)
    else:
        scr.timeout(-1)

    ch = scr.getch()
    if ch == -1:
        return True  # timeout (auto-refresh for install step)

    return HANDLERS[st.step](scr, ch)


# ──────────────────────────────────────────────────────────
#  CONFIRM QUIT OVERLAY
# ──────────────────────────────────────────────────────────
def confirm_quit(scr):
    h, w = scr.getmaxyx()
    box_h, box_w = 5, 40
    by2 = (h - box_h) // 2
    bx  = (w - box_w) // 2
    # Draw box
    for r in range(box_h):
        safeadd(scr, by2 + r, bx, " " * box_w,
                curses.color_pair(CP_FOOTER))
    safeadd(scr, by2 + 1, bx + 2, "Kurulumdan çıkmak istiyor musunuz?",
            curses.color_pair(CP_FOOTER) | curses.A_BOLD)
    safeadd(scr, by2 + 3, bx + 5,
            "[E] Evet — Çıkış     [H] Hayır — Devam",
            curses.color_pair(CP_FOOTER))
    scr.refresh()
    while True:
        ch = scr.getch()
        if ch in (ord('e'), ord('E'), ord('y'), ord('Y')):
            return True
        elif ch in (ord('h'), ord('H'), ord('n'), ord('N'), 27):
            return False

# ──────────────────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────────────────
def main(scr):
    init_colors()
    curses.curs_set(0)
    scr.nodelay(False)

    # Probe hardware
    st.disks  = get_disks()
    st.ifaces = get_ifaces()
    if st.ifaces:
        st.iface = st.ifaces[0]
    if st.disks:
        d           = st.disks[0]
        st.disk     = d["path"]
        st.disk_size  = d["size"]
        st.disk_model = d["model"]

    while True:
        h, w = scr.getmaxyx()
        if h < 24 or w < 80:
            scr.clear()
            msg = f"Terminal çok küçük! Min 80x24, şu an {w}x{h}. Boyutu artırın."
            safeadd(scr, h // 2,
                    max(0, (w - len(msg)) // 2),
                    msg,
                    curses.color_pair(CP_ERR) | curses.A_BOLD)
            scr.refresh()
            scr.getch()
            continue

        scr.clear()
        DRAWERS[st.step](scr)
        scr.refresh()

        if not dispatch(scr):
            if st.step == 5 and st.done and not st.error:
                # Already handled by handle_step5
                break
            elif confirm_quit(scr):
                break


if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
    finally:
        # Ensure clean terminal state
        sys.stdout.write("\033[?25h")  # show cursor
        sys.stdout.flush()
