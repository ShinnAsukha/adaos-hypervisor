#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OXware Hypervisor — Curses TUI Installer
Proxmox-style, stdlib only, 80×24 minimum.
"""

import curses
import json
import os
import re
import subprocess
import sys
import threading
import time

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
VERSION  = "2.0"
APP_NAME = "OXware Hypervisor"

LOGO = [
    " ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ██████╗ ███████╗",
    "██╔═══██╗╚██╗██╔╝██║    ██║██╔══██╗██╔══██╗██╔════╝",
    "██║   ██║ ╚███╔╝ ██║ █╗ ██║███████║██████╔╝█████╗  ",
    "██║   ██║ ██╔██╗ ██║███╗██║██╔══██║██╔══██╗██╔══╝  ",
    "╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║██║  ██║███████╗",
    " ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝",
]

LICENSE_TEXT = """\
OXware Hypervisor Lisans Sözleşmesi

Bu yazılım açık kaynak bileşenler içermektedir:
  • KVM/QEMU  — GNU GPL v2
  • libvirt   — LGPL v2.1
  • Python    — PSF License

Yazılım "OLDUĞU GİBİ" sunulmaktadır; herhangi bir garanti verilmemektedir.
Üretici, kullanımdan doğabilecek zararlardan sorumlu tutulamaz.

Kurulum yalnızca yetkili donanım üzerinde gerçekleştirilmelidir.
Lisanssız çoğaltma ve dağıtım yasaktır.

Devam etmek sözleşmeyi kabul etmek anlamına gelir.
"""

STEPS = [
    ("1",  "Lisans"),
    ("2",  "Disk"),
    ("3",  "Ağ"),
    ("4",  "Yönetici"),
    ("5",  "Klavye"),
    ("6",  "Dil"),
    ("7",  "Saat"),
    ("8",  "SSH"),
    ("9",  "Özet"),
    ("10", "Kurulum"),
]

FS_TYPES = ["ext4", "xfs", "btrfs"]

# (id, display_name, xkb_layout, xkb_variant)
KEYBOARD_LAYOUTS = [
    ("tr",  "Türkçe Q",     "tr", ""),
    ("trf", "Türkçe F",     "tr", "f"),
    ("us",  "English US",   "us", ""),
    ("gb",  "English UK",   "gb", ""),
    ("de",  "Deutsch",      "de", ""),
    ("fr",  "Français",     "fr", ""),
    ("es",  "Español",      "es", ""),
    ("it",  "Italiano",     "it", ""),
    ("ru",  "Русский",      "ru", ""),
    ("pt",  "Português",    "pt", ""),
    ("pl",  "Polski",       "pl", ""),
    ("nl",  "Nederlands",   "nl", ""),
    ("ar",  "العربية",      "ar", ""),
]
_kb_sel = 0

# (locale_id, display_name)
LOCALE_LIST = [
    ("tr_TR.UTF-8", "Türkçe (Türkiye)"),
    ("en_US.UTF-8", "English (United States)"),
    ("en_GB.UTF-8", "English (United Kingdom)"),
    ("de_DE.UTF-8", "Deutsch (Deutschland)"),
    ("fr_FR.UTF-8", "Français (France)"),
    ("es_ES.UTF-8", "Español (España)"),
    ("it_IT.UTF-8", "Italiano (Italia)"),
    ("ru_RU.UTF-8", "Русский (Россия)"),
    ("pt_BR.UTF-8", "Português (Brasil)"),
    ("pl_PL.UTF-8", "Polski (Polska)"),
    ("nl_NL.UTF-8", "Nederlands (Nederland)"),
    ("ar_SA.UTF-8", "العربية (السعودية)"),
    ("zh_CN.UTF-8", "中文 (中国)"),
    ("ja_JP.UTF-8", "日本語 (日本)"),
]
_locale_sel = 0

TIMEZONE_LIST = [
    "Africa/Cairo", "Africa/Johannesburg", "Africa/Lagos",
    "America/Anchorage", "America/Argentina/Buenos_Aires",
    "America/Chicago", "America/Denver", "America/Los_Angeles",
    "America/Mexico_City", "America/New_York", "America/Sao_Paulo",
    "America/Toronto", "America/Vancouver",
    "Asia/Baghdad", "Asia/Bangkok", "Asia/Dubai",
    "Asia/Hong_Kong", "Asia/Jakarta", "Asia/Karachi", "Asia/Kolkata",
    "Asia/Kuala_Lumpur", "Asia/Manila", "Asia/Riyadh", "Asia/Seoul",
    "Asia/Shanghai", "Asia/Singapore", "Asia/Tehran", "Asia/Tokyo",
    "Australia/Adelaide", "Australia/Melbourne",
    "Australia/Perth", "Australia/Sydney",
    "Europe/Amsterdam", "Europe/Athens", "Europe/Belgrade",
    "Europe/Berlin", "Europe/Brussels", "Europe/Budapest",
    "Europe/Copenhagen", "Europe/Dublin", "Europe/Helsinki",
    "Europe/Istanbul", "Europe/Kiev", "Europe/Lisbon",
    "Europe/London", "Europe/Madrid", "Europe/Moscow",
    "Europe/Oslo", "Europe/Paris", "Europe/Prague",
    "Europe/Rome", "Europe/Sofia", "Europe/Stockholm",
    "Europe/Warsaw", "Europe/Zurich",
    "Pacific/Auckland", "Pacific/Honolulu",
    "UTC",
]
_tz_filter = ""
_tz_sel    = 0
_ssh_field = 0

# ─────────────────────────────────────────────────────────────────────────────
#  COLOR PAIRS
# ─────────────────────────────────────────────────────────────────────────────
C_LOGO     = 1
C_HEADER   = 2
C_BORDER   = 3
C_STEP_ACT = 4   # active step tab
C_STEP_DON = 5   # done step
C_STEP_IDL = 6   # future step
C_FIELD    = 7   # inactive input field
C_FIELD_ON = 8   # active input field
C_FOOTER   = 9
C_ERR      = 10
C_OK       = 11
C_WARN     = 12
C_PROG     = 13
C_PROG_BG  = 14
C_LABEL    = 15
C_SEL      = 16  # list selection highlight
C_DIM      = 17
C_TITLE    = 18

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_LOGO,     curses.COLOR_CYAN,    -1)
    curses.init_pair(C_HEADER,   curses.COLOR_WHITE,   curses.COLOR_BLUE)
    curses.init_pair(C_BORDER,   curses.COLOR_CYAN,    -1)
    curses.init_pair(C_STEP_ACT, curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(C_STEP_DON, curses.COLOR_GREEN,   -1)
    curses.init_pair(C_STEP_IDL, curses.COLOR_WHITE,   -1)
    curses.init_pair(C_FIELD,    curses.COLOR_WHITE,   curses.COLOR_BLUE)
    curses.init_pair(C_FIELD_ON, curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(C_FOOTER,   curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(C_ERR,      curses.COLOR_RED,     -1)
    curses.init_pair(C_OK,       curses.COLOR_GREEN,   -1)
    curses.init_pair(C_WARN,     curses.COLOR_YELLOW,  -1)
    curses.init_pair(C_PROG,     curses.COLOR_BLACK,   curses.COLOR_GREEN)
    curses.init_pair(C_PROG_BG,  curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(C_LABEL,    curses.COLOR_CYAN,    -1)
    curses.init_pair(C_SEL,      curses.COLOR_BLACK,   curses.COLOR_YELLOW)
    curses.init_pair(C_DIM,      curses.COLOR_BLACK,   -1)
    curses.init_pair(C_TITLE,    curses.COLOR_WHITE,   -1)

# ─────────────────────────────────────────────────────────────────────────────
#  STATE
# ─────────────────────────────────────────────────────────────────────────────
class State:
    step       = 0
    # disk
    disk       = ""
    disk_size  = ""
    disk_model = ""
    fs_type    = "ext4"
    swap       = True
    # network
    iface      = ""
    net_mode   = "dhcp"
    net_ip     = ""
    net_mask   = "24"
    net_gw     = ""
    net_dns    = "8.8.8.8"
    # admin
    hostname   = "oxware"
    username   = "oxadmin"
    password   = ""
    password2  = ""
    keyboard   = "tr"   # keyboard layout id
    # locale & timezone
    locale    = "tr_TR.UTF-8"
    timezone  = "Europe/Istanbul"
    # SSH
    ssh_enabled    = True
    ssh_port       = 22
    ssh_root       = False
    ssh_passwd_auth = True
    # runtime
    disks      = []
    ifaces     = []
    pct        = 0
    msg        = "Hazırlanıyor..."
    log_lines  = []
    done       = False
    error      = ""
    # ui helpers
    err_msg    = ""  # inline validation error

st = State()

_disk_sel  = 0
_iface_sel = 0

# ─────────────────────────────────────────────────────────────────────────────
#  HARDWARE PROBING
# ─────────────────────────────────────────────────────────────────────────────
def get_disks():
    disks = []
    try:
        raw = subprocess.check_output(
            ["lsblk", "-J", "-b", "-o", "NAME,SIZE,TYPE,MODEL,ROTA"],
            stderr=subprocess.DEVNULL, timeout=10)
        data = json.loads(raw)
        for dev in data.get("blockdevices", []):
            if dev.get("type") != "disk":
                continue
            name  = dev.get("name", "")
            size  = dev.get("size") or 0
            model = (dev.get("model") or "").strip()
            rota  = dev.get("rota", "1")
            dtype = "SSD" if str(rota) in ("0", False, "false") else "HDD"
            try:
                gb = int(size) // (1024 ** 3)
                size_str = f"{gb} GB"
            except Exception:
                size_str = "? GB"
            disks.append({
                "path":  f"/dev/{name}",
                "size":  size_str,
                "model": model or "Unknown",
                "type":  dtype,
            })
    except Exception:
        disks.append({"path": "/dev/sda", "size": "120 GB", "model": "Simulated Disk", "type": "HDD"})
    return disks


def get_ifaces():
    ifaces = []
    try:
        raw = subprocess.check_output(
            "ip -o link show | awk -F': ' '{print $2}' | "
            "grep -Ev '^(lo|wl|vir|docker|br|veth|dummy|tun)'",
            shell=True, stderr=subprocess.DEVNULL, timeout=10).decode()
        for line in raw.splitlines():
            name = line.strip().split("@")[0]
            if name:
                ifaces.append(name)
    except Exception:
        ifaces.append("eth0")
    return ifaces or ["eth0"]

# ─────────────────────────────────────────────────────────────────────────────
#  LAYOUT HELPERS
# ─────────────────────────────────────────────────────────────────────────────
HEADER_H = 3   # title bar + hline + step tabs + hline
FOOTER_H = 2   # hline + key hints

def content_area(scr):
    """Return (top_y, left_x, bot_y, right_x, height, width)."""
    h, w = scr.getmaxyx()
    ty = HEADER_H
    by = h - FOOTER_H - 1
    return ty, 1, by, w - 1, by - ty, w - 2


def safeadd(win, y, x, s, attr=0):
    h, w = win.getmaxyx()
    if not (0 <= y < h):
        return
    x = max(0, x)
    avail = w - x - 1
    if avail <= 0:
        return
    try:
        win.addstr(y, x, s[:avail], attr)
    except curses.error:
        pass


def hline(scr, y, attr=0):
    h, w = scr.getmaxyx()
    if 0 <= y < h:
        try:
            scr.hline(y, 0, curses.ACS_HLINE, w, attr)
        except curses.error:
            pass


def fill_row(scr, y, attr):
    h, w = scr.getmaxyx()
    if 0 <= y < h:
        try:
            scr.addstr(y, 0, " " * (w - 1), attr)
        except curses.error:
            pass

# ─────────────────────────────────────────────────────────────────────────────
#  HEADER / FOOTER
# ─────────────────────────────────────────────────────────────────────────────
def draw_header(scr):
    h, w = scr.getmaxyx()

    # Title bar row 0
    fill_row(scr, 0, curses.color_pair(C_HEADER))
    title = f" {APP_NAME} Installer v{VERSION}"
    safeadd(scr, 0, 0, title, curses.color_pair(C_HEADER) | curses.A_BOLD)
    right = "OXware.io "
    safeadd(scr, 0, max(0, w - len(right) - 1), right, curses.color_pair(C_HEADER))

    # Separator row 1
    hline(scr, 1, curses.color_pair(C_BORDER))

    # Step tabs row 2 — sliding window (handles many steps on narrow terminals)
    _h2, _w2 = scr.getmaxyx()
    all_tabs  = []
    for i, (num, name) in enumerate(STEPS):
        if i < st.step:
            all_tabs.append((f" ✓{num}.{name} ", curses.color_pair(C_STEP_DON) | curses.A_BOLD))
        elif i == st.step:
            all_tabs.append((f" ►{num}.{name} ", curses.color_pair(C_STEP_ACT) | curses.A_BOLD))
        else:
            all_tabs.append((f"  {num}.{name} ", curses.color_pair(C_STEP_IDL) | curses.A_DIM))

    total_w = sum(len(t[0]) + 1 for t in all_tabs)
    avail_w = max(10, _w2 - 2)
    tab_x   = 1

    if total_w <= avail_w:
        vis = list(range(len(all_tabs)))
    else:
        vis  = [st.step]
        used = len(all_tabs[st.step][0]) + 1
        left, right = st.step - 1, st.step + 1
        while left >= 0 or right < len(all_tabs):
            if left >= 0:
                need = len(all_tabs[left][0]) + 1
                if used + need + 3 <= avail_w:
                    vis.append(left); used += need; left -= 1
                else:
                    left = -1
            if right < len(all_tabs):
                need = len(all_tabs[right][0]) + 1
                if used + need + 3 <= avail_w:
                    vis.append(right); used += need; right += 1
                else:
                    right = len(all_tabs)
        vis = sorted(vis)

    if vis and vis[0] > 0:
        safeadd(scr, 2, tab_x, "‹ ", curses.color_pair(C_STEP_IDL) | curses.A_DIM)
        tab_x += 2
    for i in vis:
        label, attr = all_tabs[i]
        safeadd(scr, 2, tab_x, label, attr)
        tab_x += len(label) + 1
    if vis and vis[-1] < len(all_tabs) - 1:
        safeadd(scr, 2, tab_x, " ›", curses.color_pair(C_STEP_IDL) | curses.A_DIM)

    hline(scr, 3, curses.color_pair(C_BORDER))


def draw_footer(scr, hints):
    h, w = scr.getmaxyx()
    hline(scr, h - 2, curses.color_pair(C_BORDER))
    fill_row(scr, h - 1, curses.color_pair(C_FOOTER))
    safeadd(scr, h - 1, 1, hints, curses.color_pair(C_FOOTER))
    # Right side: F10 quit
    q = " F10:Çıkış "
    safeadd(scr, h - 1, max(1, w - len(q) - 1), q,
            curses.color_pair(C_ERR) | curses.A_BOLD)

# ─────────────────────────────────────────────────────────────────────────────
#  INLINE INPUT EDITOR
# ─────────────────────────────────────────────────────────────────────────────
def read_field(scr, y, x, width, initial="", password=False):
    """Edit a text field in-place. Returns (new_value, confirmed: bool)."""
    curses.curs_set(1)
    val = list(initial)
    while True:
        shown = ("*" * len(val)) if password else "".join(val)
        field = (shown + " " * width)[:width]
        safeadd(scr, y, x, field, curses.color_pair(C_FIELD_ON))
        cx = min(x + len(shown), x + width - 1)
        try:
            scr.move(y, cx)
        except curses.error:
            pass
        scr.refresh()
        ch = scr.getch()
        if ch in (10, 13):      # Enter → confirm
            curses.curs_set(0)
            return "".join(val), True
        elif ch == 27:          # Esc → cancel
            curses.curs_set(0)
            return initial, False
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if val:
                val.pop()
        elif 32 <= ch <= 126:
            if len(val) < width - 1:
                val.append(chr(ch))

# ─────────────────────────────────────────────────────────────────────────────
#  VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
def _valid_ip(s):
    parts = s.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _valid_hostname(s):
    return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$', s))


def _pw_strength(pw):
    """Return (label, color_pair) for password strength."""
    if len(pw) < 6:
        return "Çok Kısa", C_ERR
    score = 0
    if len(pw) >= 10: score += 1
    if re.search(r'[A-Z]', pw): score += 1
    if re.search(r'[0-9]', pw): score += 1
    if re.search(r'[^A-Za-z0-9]', pw): score += 1
    if score <= 1:
        return "Zayıf", C_WARN
    if score == 2:
        return "Orta", C_WARN
    if score == 3:
        return "İyi", C_OK
    return "Güçlü ✓", C_OK

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 0 — LİSANS
# ─────────────────────────────────────────────────────────────────────────────
_lic_offset = 0

def draw_step0(scr):
    global _lic_offset
    draw_header(scr)
    ty, lx, by, rx, cth, ctw = content_area(scr)

    # Logo (only on welcome/license step)
    logo_y = ty + 1
    h, w   = scr.getmaxyx()
    for i, line in enumerate(LOGO):
        cx = max(lx, (w - len(line)) // 2)
        safeadd(scr, logo_y + i, cx, line,
                curses.color_pair(C_LOGO) | curses.A_BOLD)

    text_y = logo_y + len(LOGO) + 1
    lines  = LICENSE_TEXT.strip().splitlines()
    avail  = by - text_y - 2
    _lic_offset = max(0, min(_lic_offset, len(lines) - avail))
    for i, line in enumerate(lines[_lic_offset: _lic_offset + avail]):
        safeadd(scr, text_y + i, lx + 2, line, curses.color_pair(C_TITLE))

    accept = "[ Kabul ediyorum — devam etmek için → tuşuna basın ]"
    safeadd(scr, by - 1, max(lx, (w - len(accept)) // 2),
            accept, curses.color_pair(C_OK) | curses.A_BOLD)

    draw_footer(scr, "[↑/↓ veya PgDn] Kaydır   [→ / Enter] Kabul Et ve İleri")


def handle_step0(scr, ch):
    global _lic_offset
    if ch in (curses.KEY_DOWN, ord(' ')):
        _lic_offset += 1
    elif ch == curses.KEY_UP:
        _lic_offset = max(0, _lic_offset - 1)
    elif ch == curses.KEY_NPAGE:
        _lic_offset += 5
    elif ch in (curses.KEY_RIGHT, ord('\n'), ord('\r')):
        st.step = 1
    elif ch == curses.KEY_F10:
        return False
    return True

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 1 — DİSK SEÇİMİ
# ─────────────────────────────────────────────────────────────────────────────
def draw_step1(scr):
    global _disk_sel
    draw_header(scr)
    ty, lx, by, rx, cth, ctw = content_area(scr)

    safeadd(scr, ty + 1, lx, "Kurulum Diski",
            curses.color_pair(C_TITLE) | curses.A_BOLD)
    safeadd(scr, ty + 2, lx,
            "Seçili disk tamamen silinecek. Dikkatli olun!",
            curses.color_pair(C_WARN))

    # Column headers
    hdr = f"  {'AYGIT':<12}{'TİP':<6}{'BOYUT':<10}MODEL"
    safeadd(scr, ty + 4, lx, hdr,
            curses.color_pair(C_LABEL) | curses.A_BOLD | curses.A_UNDERLINE)

    disks = st.disks or [{"path": "?", "size": "?", "model": "?", "type": "?"}]
    list_top = ty + 5
    list_bot = by - 6
    for i, d in enumerate(disks):
        row = list_top + i
        if row > list_bot:
            break
        line = f"  {d['path']:<12}{d['type']:<6}{d['size']:<10}{d['model']}"
        if i == _disk_sel:
            fill_row(scr, row, curses.color_pair(C_SEL))
            safeadd(scr, row, lx, "▶", curses.color_pair(C_SEL) | curses.A_BOLD)
            safeadd(scr, row, lx + 1, line[1:], curses.color_pair(C_SEL) | curses.A_BOLD)
        else:
            safeadd(scr, row, lx, line, curses.color_pair(C_TITLE))

    # Separator
    hline(scr, by - 5, curses.color_pair(C_BORDER))

    # Options: FS type + swap
    fs_y = by - 4
    safeadd(scr, fs_y, lx, "Dosya Sistemi: ", curses.color_pair(C_LABEL))
    fx = lx + 15
    for fst in FS_TYPES:
        label = f"[{fst}]"
        if fst == st.fs_type:
            safeadd(scr, fs_y, fx, label, curses.color_pair(C_STEP_ACT) | curses.A_BOLD)
        else:
            safeadd(scr, fs_y, fx, label, curses.color_pair(C_STEP_IDL))
        fx += len(label) + 2
    safeadd(scr, fs_y, fx, "← f: değiştir", curses.color_pair(C_DIM))

    sw_y = by - 3
    sw_icon = "[✓]" if st.swap else "[ ]"
    sw_attr = curses.color_pair(C_OK) if st.swap else curses.color_pair(C_STEP_IDL)
    safeadd(scr, sw_y, lx, f"{sw_icon} 4 GB swap bölümü oluştur", sw_attr)
    safeadd(scr, sw_y, lx + 32, "← s: değiştir", curses.color_pair(C_DIM))

    # Warning box
    if st.disks and _disk_sel < len(st.disks):
        d = st.disks[_disk_sel]
        warn = f"⚠  {d['path']} ({d['size']}) — TÜM VERİLER SİLİNECEK!"
        safeadd(scr, by - 1, lx, warn,
                curses.color_pair(C_ERR) | curses.A_BOLD)

    draw_footer(scr, "[↑/↓] Disk Seç   [f] Dosya Sistemi   [s] Swap   [←] Geri   [→/Enter] İleri")


def handle_step1(scr, ch):
    global _disk_sel
    n = len(st.disks) if st.disks else 1
    if ch == curses.KEY_UP:
        _disk_sel = max(0, _disk_sel - 1)
    elif ch == curses.KEY_DOWN:
        _disk_sel = min(n - 1, _disk_sel + 1)
    elif ch in (ord('f'), ord('F')):
        idx = FS_TYPES.index(st.fs_type)
        st.fs_type = FS_TYPES[(idx + 1) % len(FS_TYPES)]
    elif ch in (ord('s'), ord('S')):
        st.swap = not st.swap
    elif ch in (curses.KEY_RIGHT, ord('\n'), ord('\r')):
        if st.disks:
            d = st.disks[_disk_sel]
            st.disk       = d["path"]
            st.disk_size  = d["size"]
            st.disk_model = d["model"]
        st.err_msg = ""
        st.step = 2
    elif ch == curses.KEY_LEFT:
        st.step = 0
    elif ch == curses.KEY_F10:
        return False
    return True

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 2 — AĞ YAPILANDIRMASI
# ─────────────────────────────────────────────────────────────────────────────
_net_field   = 0    # 0=IP, 1=Mask, 2=GW, 3=DNS
_NET_FIELDS  = [
    ("IP Adresi  ", "net_ip",   20),
    ("Alt Ağ /   ", "net_mask",  4),
    ("Ağ Geçidi  ", "net_gw",   20),
    ("DNS Sunucu ", "net_dns",  20),
]

def draw_step2(scr):
    global _iface_sel
    draw_header(scr)
    ty, lx, by, rx, cth, ctw = content_area(scr)

    safeadd(scr, ty + 1, lx, "Ağ Yapılandırması",
            curses.color_pair(C_TITLE) | curses.A_BOLD)

    # Interface list
    ifaces = st.ifaces or ["eth0"]
    safeadd(scr, ty + 3, lx, "Ağ Arayüzü: ", curses.color_pair(C_LABEL))
    ix = lx + 12
    for i, iface in enumerate(ifaces):
        label = f" {iface} "
        if i == _iface_sel:
            safeadd(scr, ty + 3, ix, label,
                    curses.color_pair(C_STEP_ACT) | curses.A_BOLD)
        else:
            safeadd(scr, ty + 3, ix, label, curses.color_pair(C_STEP_IDL))
        ix += len(label) + 1
    safeadd(scr, ty + 3, ix + 1, "← Tab: değiştir", curses.color_pair(C_DIM))

    # Mode toggle
    safeadd(scr, ty + 5, lx, "Mod: ", curses.color_pair(C_LABEL))
    mx = lx + 5
    for mode in ["dhcp", "static"]:
        label = f"  {mode.upper()}  "
        if mode == st.net_mode:
            safeadd(scr, ty + 5, mx, label,
                    curses.color_pair(C_STEP_ACT) | curses.A_BOLD)
        else:
            safeadd(scr, ty + 5, mx, label, curses.color_pair(C_STEP_IDL))
        mx += len(label) + 1
    safeadd(scr, ty + 5, mx + 1, "← d/s: değiştir", curses.color_pair(C_DIM))

    if st.net_mode == "dhcp":
        safeadd(scr, ty + 8, lx, "✓  IP adresi otomatik alınacak (DHCP)",
                curses.color_pair(C_OK) | curses.A_BOLD)
        safeadd(scr, ty + 9, lx,
                "   Kurulum sonrası ağ yapılandırmasını değiştirebilirsiniz.",
                curses.color_pair(C_DIM))
    else:
        # Static fields
        field_y = ty + 8
        for i, (label, attr, width) in enumerate(_NET_FIELDS):
            fy = field_y + i * 2
            safeadd(scr, fy, lx, label, curses.color_pair(C_LABEL))
            val  = getattr(st, attr, "")
            disp = (val + " " * width)[:width]
            if i == _net_field:
                safeadd(scr, fy, lx + 12, disp,
                        curses.color_pair(C_FIELD_ON) | curses.A_BOLD)
                safeadd(scr, fy, lx + 12 + width + 1, "← Enter: düzenle",
                        curses.color_pair(C_DIM))
            else:
                safeadd(scr, fy, lx + 12, disp, curses.color_pair(C_FIELD))

    # Error / info
    if st.err_msg:
        safeadd(scr, by - 2, lx, f"✗  {st.err_msg}",
                curses.color_pair(C_ERR) | curses.A_BOLD)

    draw_footer(scr, "[d/s] Mod   [Tab] Arayüz   [↑/↓] Alan   [Enter] Düzenle   [←] Geri   [→] İleri")


def handle_step2(scr, ch):
    global _iface_sel, _net_field
    nifaces = len(st.ifaces) if st.ifaces else 1
    nfields = len(_NET_FIELDS)

    if ch == ord('\t'):
        _iface_sel = (_iface_sel + 1) % nifaces
        st.iface   = st.ifaces[_iface_sel] if st.ifaces else "eth0"
    elif ch in (ord('d'), ord('D')):
        st.net_mode = "dhcp"
        st.err_msg  = ""
    elif ch in (ord('s'), ord('S')):
        st.net_mode = "static"
    elif ch == curses.KEY_UP and st.net_mode == "static":
        _net_field = max(0, _net_field - 1)
    elif ch == curses.KEY_DOWN and st.net_mode == "static":
        _net_field = min(nfields - 1, _net_field + 1)
    elif ch in (ord('\n'), ord('\r')) and st.net_mode == "static":
        _, attr, width = _NET_FIELDS[_net_field]
        fy = content_area(scr)[0] + 8 + _net_field * 2
        val, ok = read_field(scr, fy, 2 + 12, width, getattr(st, attr, ""))
        if ok:
            setattr(st, attr, val)
    elif ch == curses.KEY_RIGHT or ch == ord('\n') or ch == ord('\r'):
        # Validate
        st.err_msg = ""
        if st.net_mode == "static":
            if not _valid_ip(st.net_ip):
                st.err_msg = "Geçersiz IP adresi"
                return True
            if not st.net_mask.isdigit() or not (0 <= int(st.net_mask) <= 32):
                if not _valid_ip(st.net_mask):
                    st.err_msg = "Geçersiz alt ağ maskesi (CIDR veya 255.x.x.x)"
                    return True
            if not _valid_ip(st.net_gw):
                st.err_msg = "Geçersiz ağ geçidi"
                return True
            if not _valid_ip(st.net_dns):
                st.err_msg = "Geçersiz DNS"
                return True
        st.step = 3
    elif ch == curses.KEY_LEFT:
        st.err_msg = ""
        st.step = 1
    elif ch == curses.KEY_F10:
        return False
    return True

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 3 — YÖNETİCİ BİLGİLERİ
# ─────────────────────────────────────────────────────────────────────────────
_adm_field = 0   # 0=hostname, 1=username, 2=pass, 3=pass2

def draw_step3(scr):
    draw_header(scr)
    ty, lx, by, rx, cth, ctw = content_area(scr)

    safeadd(scr, ty + 1, lx, "Yönetici Hesabı",
            curses.color_pair(C_TITLE) | curses.A_BOLD)
    safeadd(scr, ty + 2, lx,
            "Bu bilgiler web arayüzü ve SSH girişi için kullanılacak.",
            curses.color_pair(C_DIM))

    # Her field tek satırda — extra info aynı satırda sağda göster
    # Böylece 4 field = 4 satır, sığar
    ADM_FIELDS = [
        ("Sunucu Adı  ", "hostname",  20, False),
        ("Kullanıcı   ", "username",  20, False),
        ("Şifre       ", "password",  24, True),
        ("Şifre Tekrar", "password2", 24, True),
    ]
    FW      = 24
    field_y = ty + 4

    for i, (label, attr, width, is_pw) in enumerate(ADM_FIELDS):
        fy     = field_y + i * 2
        val    = getattr(st, attr, "")
        disp   = ("*" * len(val) if is_pw else val + " " * FW)[:FW]
        active = (i == _adm_field)

        safeadd(scr, fy, lx, label, curses.color_pair(C_LABEL))
        fattr = (curses.color_pair(C_FIELD_ON) | curses.A_BOLD) if active else curses.color_pair(C_FIELD)
        safeadd(scr, fy, lx + 13, disp, fattr)

        # Extra info on next line
        extra_y = fy + 1
        if attr == "hostname" and val and not _valid_hostname(val):
            safeadd(scr, extra_y, lx + 13, "⚠ harf, rakam, tire kullanın",
                    curses.color_pair(C_WARN))
        elif attr == "password" and val:
            strength, sc = _pw_strength(val)
            safeadd(scr, extra_y, lx + 13, f"Güç: {strength}",
                    curses.color_pair(sc))
        elif attr == "password2" and val:
            ok_str = "✓ Eşleşiyor" if val == st.password else "✗ Eşleşmiyor"
            mc     = C_OK if val == st.password else C_ERR
            safeadd(scr, extra_y, lx + 13, ok_str, curses.color_pair(mc))

    # Hint
    safeadd(scr, field_y + len(ADM_FIELDS) * 2 + 1, lx,
            "Enter: alanı düzenle   →: devam et",
            curses.color_pair(C_DIM))

    if st.err_msg:
        safeadd(scr, by - 1, lx, f"✗  {st.err_msg}",
                curses.color_pair(C_ERR) | curses.A_BOLD)

    draw_footer(scr, "[↑/↓] Alan   [Enter] Düzenle   [←] Geri   [→] İleri (doğrulama)")


_ADM_FIELDS_META = [
    ("hostname",  20, False),
    ("username",  20, False),
    ("password",  24, True),
    ("password2", 24, True),
]

def handle_step3(scr, ch):
    global _adm_field
    nf = len(_ADM_FIELDS_META)

    if ch == curses.KEY_UP:
        _adm_field = max(0, _adm_field - 1)
        st.err_msg = ""
    elif ch == curses.KEY_DOWN:
        _adm_field = min(nf - 1, _adm_field + 1)
        st.err_msg = ""
    elif ch in (ord('\n'), ord('\r')):
        # Enter ALWAYS edits current field (including last)
        attr, width, is_pw = _ADM_FIELDS_META[_adm_field]
        ty = content_area(scr)[0]
        fy = ty + 4 + _adm_field * 2
        val, ok = read_field(scr, fy, 1 + 13, width,
                             getattr(st, attr, ""), password=is_pw)
        if ok:
            setattr(st, attr, val)
            # Auto-advance to next field after confirming
            _adm_field = min(nf - 1, _adm_field + 1)
        st.err_msg = ""
    elif ch == curses.KEY_RIGHT:
        # RIGHT validates and advances step
        st.err_msg = ""
        if not st.hostname or not _valid_hostname(st.hostname):
            st.err_msg = "Geçersiz sunucu adı (harf/rakam/tire)"
            _adm_field = 0
            return True
        if not st.username or len(st.username) < 2:
            st.err_msg = "Kullanıcı adı en az 2 karakter"
            _adm_field = 1
            return True
        if len(st.password) < 6:
            st.err_msg = "Şifre en az 6 karakter"
            _adm_field = 2
            return True
        if st.password != st.password2:
            st.err_msg = "Şifreler eşleşmiyor"
            _adm_field = 3
            return True
        st.step = 4
    elif ch == curses.KEY_LEFT:
        st.err_msg = ""
        st.step = 2
    elif ch == curses.KEY_F10:
        return False
    return True

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 4 — KLAVYE DÜZENİ
# ─────────────────────────────────────────────────────────────────────────────
def draw_step4(scr):
    global _kb_sel
    draw_header(scr)
    ty, lx, by, rx, cth, ctw = content_area(scr)

    safeadd(scr, ty + 1, lx, "Klavye Düzeni",
            curses.color_pair(C_TITLE) | curses.A_BOLD)
    safeadd(scr, ty + 2, lx,
            "Kurulacak sistemin klavye düzenini seçin.",
            curses.color_pair(C_DIM))

    safeadd(scr, ty + 3, lx,
            f"  {'#':<4} {'DÜZEN':<22} XKB",
            curses.color_pair(C_LABEL) | curses.A_BOLD | curses.A_UNDERLINE)

    list_top = ty + 4
    list_bot = by - 3
    n_vis    = list_bot - list_top
    start    = max(0, _kb_sel - n_vis // 2)
    start    = min(start, max(0, len(KEYBOARD_LAYOUTS) - n_vis))

    for i, (kid, kname, xkbl, xkbv) in enumerate(KEYBOARD_LAYOUTS[start:start + n_vis]):
        abs_i   = start + i
        row     = list_top + i
        marker  = "▶" if abs_i == _kb_sel else " "
        vstr    = f"/{xkbv}" if xkbv else ""
        line    = f"{marker} {abs_i+1:<3} {kname:<22}{xkbl}{vstr}"
        if abs_i == _kb_sel:
            fill_row(scr, row, curses.color_pair(C_SEL))
            safeadd(scr, row, lx, line, curses.color_pair(C_SEL) | curses.A_BOLD)
        else:
            attr = curses.color_pair(C_OK) if kid == st.keyboard else curses.color_pair(C_TITLE)
            safeadd(scr, row, lx, line, attr)

    kid, kname, xkbl, xkbv = KEYBOARD_LAYOUTS[_kb_sel]
    vstr = f" / variant={xkbv}" if xkbv else ""
    safeadd(scr, by - 1, lx,
            f"Seçili: {kname}  (layout={xkbl}{vstr})",
            curses.color_pair(C_OK) | curses.A_BOLD)

    draw_footer(scr, "[↑/↓] Seç   [Enter/→] Onayla   [←] Geri")


def handle_step4(scr, ch):
    global _kb_sel
    n = len(KEYBOARD_LAYOUTS)
    if ch == curses.KEY_UP:
        _kb_sel = max(0, _kb_sel - 1)
    elif ch == curses.KEY_DOWN:
        _kb_sel = min(n - 1, _kb_sel + 1)
    elif ch in (curses.KEY_RIGHT, ord('\n'), ord('\r')):
        st.keyboard = KEYBOARD_LAYOUTS[_kb_sel][0]
        st.step = 5
    elif ch == curses.KEY_LEFT:
        st.step = 3
    elif ch == curses.KEY_F10:
        return False
    return True

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 5 — DİL (LOCALE)
# ─────────────────────────────────────────────────────────────────────────────
def draw_step5(scr):
    global _locale_sel
    draw_header(scr)
    ty, lx, by, rx, cth, ctw = content_area(scr)

    safeadd(scr, ty + 1, lx, "Sistem Dili",
            curses.color_pair(C_TITLE) | curses.A_BOLD)
    safeadd(scr, ty + 2, lx,
            "Kurulacak sistemin dil ve yerel ayarını seçin.",
            curses.color_pair(C_DIM))
    safeadd(scr, ty + 3, lx,
            f"  {'#':<4} {'DİL':<32} YEREL",
            curses.color_pair(C_LABEL) | curses.A_BOLD | curses.A_UNDERLINE)

    list_top = ty + 4
    list_bot = by - 2
    n_vis    = max(1, list_bot - list_top)
    start    = max(0, _locale_sel - n_vis // 2)
    start    = min(start, max(0, len(LOCALE_LIST) - n_vis))

    for i, (lid, lname) in enumerate(LOCALE_LIST[start:start + n_vis]):
        abs_i  = start + i
        row    = list_top + i
        marker = "▶" if abs_i == _locale_sel else " "
        line   = f"{marker} {abs_i+1:<3} {lname:<32}{lid}"
        if abs_i == _locale_sel:
            fill_row(scr, row, curses.color_pair(C_SEL))
            safeadd(scr, row, lx, line, curses.color_pair(C_SEL) | curses.A_BOLD)
        else:
            attr = curses.color_pair(C_OK) if lid == st.locale else curses.color_pair(C_TITLE)
            safeadd(scr, row, lx, line, attr)

    draw_footer(scr, "[↑/↓] Seç   [Enter/→] Onayla   [←] Geri")


def handle_step5(scr, ch):
    global _locale_sel
    n = len(LOCALE_LIST)
    if ch == curses.KEY_UP:
        _locale_sel = max(0, _locale_sel - 1)
    elif ch == curses.KEY_DOWN:
        _locale_sel = min(n - 1, _locale_sel + 1)
    elif ch in (curses.KEY_RIGHT, ord('\n'), ord('\r')):
        st.locale = LOCALE_LIST[_locale_sel][0]
        st.step = 6
    elif ch == curses.KEY_LEFT:
        st.step = 4
    elif ch == curses.KEY_F10:
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 6 — SAAT DİLİMİ (TIMEZONE)
# ─────────────────────────────────────────────────────────────────────────────
def _tz_filtered():
    if not _tz_filter:
        return TIMEZONE_LIST
    fl = _tz_filter.lower()
    return [tz for tz in TIMEZONE_LIST if fl in tz.lower()]


def draw_step6(scr):
    global _tz_filter, _tz_sel
    draw_header(scr)
    ty, lx, by, rx, cth, ctw = content_area(scr)

    safeadd(scr, ty + 1, lx, "Zaman Dilimi",
            curses.color_pair(C_TITLE) | curses.A_BOLD)
    safeadd(scr, ty + 2, lx,
            "Aramak için yazın. Ok tuşları ile seçin.",
            curses.color_pair(C_DIM))

    filter_label = "Ara: "
    safeadd(scr, ty + 3, lx, filter_label, curses.color_pair(C_LABEL))
    filter_display = (_tz_filter + " " * 30)[:30]
    safeadd(scr, ty + 3, lx + len(filter_label), filter_display,
            curses.color_pair(C_FIELD_ON) | curses.A_BOLD)

    filtered = _tz_filtered()
    if filtered and _tz_sel >= len(filtered):
        _tz_sel = max(0, len(filtered) - 1)

    safeadd(scr, ty + 4, lx,
            f"  {'#':<4} ZAMAN DİLİMİ  ({len(filtered)} sonuç)",
            curses.color_pair(C_LABEL) | curses.A_BOLD | curses.A_UNDERLINE)

    list_top = ty + 5
    list_bot = by - 2
    n_vis    = max(1, list_bot - list_top)
    start    = max(0, _tz_sel - n_vis // 2)
    start    = min(start, max(0, len(filtered) - n_vis))

    for i, tz in enumerate(filtered[start:start + n_vis]):
        abs_i  = start + i
        row    = list_top + i
        marker = "▶" if abs_i == _tz_sel else " "
        line   = f"{marker} {abs_i+1:<3} {tz}"
        if abs_i == _tz_sel:
            fill_row(scr, row, curses.color_pair(C_SEL))
            safeadd(scr, row, lx, line, curses.color_pair(C_SEL) | curses.A_BOLD)
        else:
            attr = curses.color_pair(C_OK) if tz == st.timezone else curses.color_pair(C_TITLE)
            safeadd(scr, row, lx, line, attr)

    if filtered and _tz_sel < len(filtered):
        safeadd(scr, by - 1, lx,
                f"Seçili: {filtered[_tz_sel]}",
                curses.color_pair(C_OK) | curses.A_BOLD)

    draw_footer(scr, "[Yaz] Filtrele   [↑/↓] Seç   [→/Enter] Onayla   [Esc] Temizle   [←] Geri")


def handle_step6(scr, ch):
    global _tz_filter, _tz_sel
    filtered = _tz_filtered()

    if ch == curses.KEY_UP:
        _tz_sel = max(0, _tz_sel - 1)
    elif ch == curses.KEY_DOWN:
        _tz_sel = min(max(0, len(filtered) - 1), _tz_sel + 1)
    elif ch == 27:
        _tz_filter = ""
        _tz_sel    = 0
    elif ch in (curses.KEY_BACKSPACE, 127, 8):
        _tz_filter = _tz_filter[:-1]
        _tz_sel    = 0
    elif ch in (curses.KEY_RIGHT, ord('\n'), ord('\r')):
        if filtered and _tz_sel < len(filtered):
            st.timezone = filtered[_tz_sel]
        st.step = 7
    elif ch == curses.KEY_LEFT:
        st.step = 5
    elif ch == curses.KEY_F10:
        return False
    elif 32 <= ch <= 126:
        _tz_filter += chr(ch)
        _tz_sel = 0
        new_filtered = _tz_filtered()
        for idx, tz in enumerate(new_filtered):
            if tz == st.timezone:
                _tz_sel = idx
                break
    return True


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 7 — SSH YAPILANDIRMASI
# ─────────────────────────────────────────────────────────────────────────────
_SSH_ITEMS = [
    ("SSH Sunucusu   ", "toggle", "ssh_enabled",    "OpenSSH sunucusu kurulum sonrası etkin olsun mu?"),
    ("SSH Port       ", "int",    "ssh_port",        "Varsayılan: 22  (önerilir: 22 veya 2222-65535)"),
    ("Root Girişi    ", "toggle", "ssh_root",        "SSH ile doğrudan root girişine izin ver"),
    ("Şifre Girişi   ", "toggle", "ssh_passwd_auth", "Şifre ile kimlik doğrulamaya izin ver (önerilir: Etkin)"),
]


def draw_step7(scr):
    global _ssh_field
    draw_header(scr)
    ty, lx, by, rx, cth, ctw = content_area(scr)

    safeadd(scr, ty + 1, lx, "SSH Yapılandırması",
            curses.color_pair(C_TITLE) | curses.A_BOLD)
    safeadd(scr, ty + 2, lx,
            "Güvenli kabuk erişim ayarları. Ok tuşları ile gezin.",
            curses.color_pair(C_DIM))

    field_y = ty + 4
    for i, (label, ftype, attr, hint) in enumerate(_SSH_ITEMS):
        fy     = field_y + i * 3
        active = (i == _ssh_field)
        safeadd(scr, fy, lx, label, curses.color_pair(C_LABEL))

        val = getattr(st, attr)
        if ftype == "toggle":
            icon  = "[✓] Etkin" if val else "[ ] Devre Dışı"
            color = C_OK if val else C_STEP_IDL
            fattr = (curses.color_pair(C_SEL) | curses.A_BOLD) if active else curses.color_pair(color)
            safeadd(scr, fy, lx + 16, icon, fattr)
            if active:
                safeadd(scr, fy, lx + 30, "← Space/Enter: değiştir", curses.color_pair(C_DIM))
        elif ftype == "int":
            disp  = str(val)
            field = (disp + " " * 10)[:10]
            fattr = (curses.color_pair(C_FIELD_ON) | curses.A_BOLD) if active else curses.color_pair(C_FIELD)
            safeadd(scr, fy, lx + 16, field, fattr)
            if active:
                safeadd(scr, fy, lx + 28, "← Enter: düzenle", curses.color_pair(C_DIM))

        if active:
            safeadd(scr, fy + 1, lx + 2, hint, curses.color_pair(C_DIM))

    if st.err_msg:
        safeadd(scr, by - 1, lx, f"✗  {st.err_msg}",
                curses.color_pair(C_ERR) | curses.A_BOLD)

    draw_footer(scr, "[↑/↓] Alan   [Space/Enter] Değiştir/Düzenle   [←] Geri   [→] İleri")


def handle_step7(scr, ch):
    global _ssh_field
    n = len(_SSH_ITEMS)
    if ch == curses.KEY_UP:
        _ssh_field = max(0, _ssh_field - 1)
        st.err_msg = ""
    elif ch == curses.KEY_DOWN:
        _ssh_field = min(n - 1, _ssh_field + 1)
        st.err_msg = ""
    elif ch in (ord(' '), ord('\n'), ord('\r')):
        label, ftype, attr, hint = _SSH_ITEMS[_ssh_field]
        if ftype == "toggle":
            setattr(st, attr, not getattr(st, attr))
            st.err_msg = ""
        elif ftype == "int":
            _ty, _lx = content_area(scr)[:2]
            fy = _ty + 4 + _ssh_field * 3
            val, ok = read_field(scr, fy, _lx + 16, 10, str(getattr(st, attr)))
            if ok:
                try:
                    p = int(val)
                    if not (1 <= p <= 65535):
                        raise ValueError
                    setattr(st, attr, p)
                    st.err_msg = ""
                except ValueError:
                    st.err_msg = "Port 1-65535 arasında olmalı"
    elif ch == curses.KEY_RIGHT:
        st.err_msg = ""
        st.step = 8
    elif ch == curses.KEY_LEFT:
        st.err_msg = ""
        st.step = 6
    elif ch == curses.KEY_F10:
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 9 — ÖZET
# ─────────────────────────────────────────────────────────────────────────────
def draw_step8(scr):
    draw_header(scr)
    ty, lx, by, rx, cth, ctw = content_area(scr)
    h, w = scr.getmaxyx()

    safeadd(scr, ty + 1, lx, "Kurulum Özeti",
            curses.color_pair(C_TITLE) | curses.A_BOLD)
    safeadd(scr, ty + 2, lx,
            "Aşağıdaki yapılandırma ile kurulum başlayacak.",
            curses.color_pair(C_DIM))

    _kb_name = next((kn for ki, kn, _, _ in KEYBOARD_LAYOUTS if ki == st.keyboard), st.keyboard)
    _locale_name = next((ln for li, ln in LOCALE_LIST if li == st.locale), st.locale)
    _ssh_status = "Etkin" if st.ssh_enabled else "Devre Dışı"
    _ssh_root_str = "Evet" if st.ssh_root else "Hayır"
    _ssh_pass_str = "Evet" if st.ssh_passwd_auth else "Hayır"
    rows = [
        ("Disk",          f"{st.disk}  ({st.disk_size})"),
        ("Dosya Sistemi", f"{st.fs_type}" + ("  +swap 4GB" if st.swap else "")),
        ("Ağ Arayüzü",   st.iface or "—"),
        ("Ağ Modu",      st.net_mode.upper()),
        ("IP / Maske",   f"{st.net_ip}/{st.net_mask}" if st.net_mode == "static" else "DHCP (otomatik)"),
        ("Ağ Geçidi",    st.net_gw  or "—" if st.net_mode == "static" else "—"),
        ("DNS",          st.net_dns if st.net_mode == "static" else "DHCP"),
        ("Sunucu Adı",   st.hostname),
        ("Kullanıcı",    st.username),
        ("Şifre",        "*" * len(st.password)),
        ("Klavye",       _kb_name),
        ("Dil",          _locale_name),
        ("Zaman Dilimi", st.timezone),
        ("SSH",          f"{_ssh_status}  port={st.ssh_port}  root={_ssh_root_str}  şifre={_ssh_pass_str}"),
    ]

    box_y = ty + 4
    safeadd(scr, box_y, lx, "┌" + "─" * (ctw - 2) + "┐", curses.color_pair(C_BORDER))
    for i, (k, v) in enumerate(rows):
        row = box_y + 1 + i
        if row >= by - 4:
            break
        line = f"│  {k:<16}{v}"
        line = (line + " " * ctw)[:ctw - 1] + "│"
        safeadd(scr, row, lx, line, curses.color_pair(C_TITLE))
    bot = box_y + 1 + min(len(rows), by - box_y - 6)
    safeadd(scr, bot, lx, "└" + "─" * (ctw - 2) + "┘", curses.color_pair(C_BORDER))

    warn = "⚠  UYARI: Disk tamamen silinecek. Devam etmek için → veya Enter tuşuna basın."
    safeadd(scr, by - 1, lx, warn, curses.color_pair(C_ERR) | curses.A_BOLD)

    draw_footer(scr, "[←] Geri   [→ / Enter] Kurulumu BAŞLAT")


def handle_step8(scr, ch):
    if ch in (curses.KEY_RIGHT, ord('\n'), ord('\r')):
        st.step  = 9
        st.pct   = 0
        st.msg   = "Başlatılıyor..."
        st.done  = False
        st.error = ""
        st.log_lines = []
        threading.Thread(target=_run_install, daemon=True).start()
    elif ch == curses.KEY_LEFT:
        st.step = 7
    elif ch == curses.KEY_F10:
        return False
    return True

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 10 — KURULUM İLERLEMESİ
# ─────────────────────────────────────────────────────────────────────────────
_SPIN = ["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"]
_spin_i = 0
_reboot_countdown = None

def draw_step9(scr):
    global _spin_i, _reboot_countdown
    draw_header(scr)
    ty, lx, by, rx, cth, ctw = content_area(scr)
    h, w = scr.getmaxyx()

    if st.done and st.error:
        # ERROR SCREEN
        safeadd(scr, ty + 2, lx, "✗  Kurulum Başarısız!",
                curses.color_pair(C_ERR) | curses.A_BOLD)
        hline(scr, ty + 3, curses.color_pair(C_ERR))
        err_lines = st.error.split("\n")
        for i, line in enumerate(err_lines[:8]):
            safeadd(scr, ty + 5 + i, lx + 2, line, curses.color_pair(C_ERR))
        safeadd(scr, by - 2, lx, "Son log satırları:",
                curses.color_pair(C_LABEL))
        log_visible = st.log_lines[-6:] if st.log_lines else []
        for i, line in enumerate(log_visible):
            safeadd(scr, by - 1 + i - len(log_visible), lx + 2,
                    line[:ctw - 4], curses.color_pair(C_DIM))
        draw_footer(scr, "[q] Çıkış")
        return

    if st.done:
        # SUCCESS SCREEN
        safeadd(scr, ty + 2, lx,
                "✓  Kurulum Başarıyla Tamamlandı!",
                curses.color_pair(C_OK) | curses.A_BOLD)
        hline(scr, ty + 3, curses.color_pair(C_OK))

        infos = [
            f"Sunucu adı : {st.hostname}",
            f"Kullanıcı  : {st.username}",
            f"Web arayüzü: https://<ip>:8006",
            f"SSH        : ssh {st.username}@<ip>",
        ]
        for i, line in enumerate(infos):
            safeadd(scr, ty + 5 + i, lx + 4, line,
                    curses.color_pair(C_OK) | curses.A_BOLD)

        if _reboot_countdown is not None:
            safeadd(scr, ty + 11, lx + 4,
                    f"Otomatik yeniden başlatma: {_reboot_countdown} saniye",
                    curses.color_pair(C_WARN) | curses.A_BOLD)
        safeadd(scr, ty + 12, lx + 4,
                "Enter: hemen yeniden başlat",
                curses.color_pair(C_TITLE))
        draw_footer(scr, "[Enter] Yeniden Başlat")
        return

    # INSTALL IN PROGRESS
    spin = _SPIN[_spin_i % len(_SPIN)]
    _spin_i += 1

    # Status line
    safeadd(scr, ty + 1, lx, f"{spin}  {st.msg}",
            curses.color_pair(C_LABEL) | curses.A_BOLD)

    # Progress bar
    bar_y   = ty + 3
    bar_w   = ctw - 10
    filled  = int(bar_w * st.pct / 100)
    empty   = bar_w - filled
    pct_str = f" {st.pct:3d}% "
    safeadd(scr, bar_y, lx, pct_str, curses.color_pair(C_LABEL) | curses.A_BOLD)
    safeadd(scr, bar_y, lx + len(pct_str),
            "█" * filled, curses.color_pair(C_PROG))
    safeadd(scr, bar_y, lx + len(pct_str) + filled,
            "░" * empty, curses.color_pair(C_PROG_BG))

    # Log viewer
    log_top = ty + 5
    log_bot = by - 1
    n_log   = max(0, log_bot - log_top)
    safeadd(scr, log_top - 1, lx, "─── Kurulum Günlüğü " + "─" * max(0, ctw - 21),
            curses.color_pair(C_BORDER))
    visible = st.log_lines[-n_log:] if st.log_lines else ["Bekleniyor..."]
    for i, line in enumerate(visible):
        row = log_top + i
        if row >= log_bot:
            break
        safeadd(scr, row, lx + 1, line[:ctw - 2], curses.color_pair(C_DIM))

    draw_footer(scr, "Kurulum devam ediyor, lütfen bekleyin...")


def handle_step9(scr, ch):
    global _reboot_countdown
    if st.done and st.error:
        if ch in (ord('q'), ord('Q'), curses.KEY_F10):
            return False
    elif st.done:
        if ch in (ord('\n'), ord('\r'), ord('r'), ord('R')):
            try:
                subprocess.run(["reboot"], check=False)
            except Exception:
                pass
            return False
    elif ch == curses.KEY_F10:
        return False
    return True

# ─────────────────────────────────────────────────────────────────────────────
#  BACKGROUND INSTALL THREAD
# ─────────────────────────────────────────────────────────────────────────────
def _run_install():
    global _reboot_countdown

    _kb_entry = next((k for k in KEYBOARD_LAYOUTS if k[0] == st.keyboard), KEYBOARD_LAYOUTS[0])
    config = {
        "disk":             st.disk,
        "fs_type":          st.fs_type,
        "swap":             st.swap,
        "iface":            st.iface or (st.ifaces[0] if st.ifaces else "eth0"),
        "net_mode":         st.net_mode,
        "net_ip":           st.net_ip,
        "net_mask":         st.net_mask,
        "net_gw":           st.net_gw,
        "net_dns":          st.net_dns,
        "hostname":         st.hostname,
        "username":         st.username,
        "password":         st.password,
        "keyboard":         st.keyboard,
        "keyboard_layout":  _kb_entry[2],
        "keyboard_variant": _kb_entry[3],
        "locale":           st.locale,
        "timezone":         st.timezone,
        "ssh_enabled":      st.ssh_enabled,
        "ssh_port":         st.ssh_port,
        "ssh_root":         st.ssh_root,
        "ssh_passwd_auth":  st.ssh_passwd_auth,
    }

    cfg_path = "/tmp/oxware-install.json"
    try:
        with open(cfg_path, "w") as f:
            json.dump(config, f)
    except Exception as e:
        st.error = f"Yapılandırma yazılamadı: {e}"
        st.done  = True
        return

    installer = "/opt/oxware-installer/install.py"
    if not os.path.exists(installer):
        st.error = f"Installer bulunamadı: {installer}"
        st.done  = True
        return

    try:
        proc = subprocess.Popen(
            ["python3", installer, "--headless", cfg_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    d = json.loads(line)
                    if "pct" in d:
                        st.pct = int(d["pct"])
                    if "msg" in d:
                        st.msg = d["msg"]
                        st.log_lines.append(f"[{st.pct:3d}%] {d['msg']}")
                    if d.get("done"):
                        st.done = True
                    if "error" in d and d["error"]:
                        st.error = d["error"]
                        st.done  = True
                    continue
                except json.JSONDecodeError:
                    pass
            st.log_lines.append(line)
            if len(st.log_lines) > 500:
                st.log_lines = st.log_lines[-500:]

        proc.wait()
        if proc.returncode != 0 and not st.done:
            st.error = f"Installer hata kodu: {proc.returncode}"
            st.done  = True
        elif not st.done:
            st.pct  = 100
            st.msg  = "Kurulum tamamlandı!"
            st.done = True

    except FileNotFoundError:
        st.error = f"python3 bulunamadı"
        st.done  = True
    except Exception as e:
        st.error = str(e)
        st.done  = True

    # Start reboot countdown if successful
    if st.done and not st.error:
        for i in range(15, 0, -1):
            _reboot_countdown = i
            time.sleep(1)
        _reboot_countdown = 0
        try:
            subprocess.run(["reboot"], check=False)
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
#  DISPATCH TABLE
# ─────────────────────────────────────────────────────────────────────────────
DRAWERS  = [draw_step0, draw_step1, draw_step2, draw_step3, draw_step4,
            draw_step5, draw_step6, draw_step7, draw_step8, draw_step9]
HANDLERS = [handle_step0, handle_step1, handle_step2, handle_step3, handle_step4,
            handle_step5, handle_step6, handle_step7, handle_step8, handle_step9]

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIRM QUIT OVERLAY
# ─────────────────────────────────────────────────────────────────────────────
def confirm_quit(scr):
    h, w   = scr.getmaxyx()
    bh, bw = 7, 48
    by2    = (h - bh) // 2
    bx     = (w - bw) // 2

    # Draw box
    safeadd(scr, by2,     bx, "╔" + "═" * (bw - 2) + "╗", curses.color_pair(C_BORDER) | curses.A_BOLD)
    for r in range(1, bh - 1):
        safeadd(scr, by2 + r, bx, "║" + " " * (bw - 2) + "║", curses.color_pair(C_BORDER))
    safeadd(scr, by2 + bh - 1, bx, "╚" + "═" * (bw - 2) + "╝", curses.color_pair(C_BORDER) | curses.A_BOLD)

    title = "Kurulumdan Çıkılsın Mı?"
    safeadd(scr, by2 + 2, bx + (bw - len(title)) // 2, title,
            curses.color_pair(C_WARN) | curses.A_BOLD)
    safeadd(scr, by2 + 4, bx + 8,
            "[E] Evet — Çıkış     [H] Hayır — Devam",
            curses.color_pair(C_TITLE))
    scr.refresh()

    while True:
        ch = scr.getch()
        if ch in (ord('e'), ord('E'), ord('y'), ord('Y')):
            return True
        if ch in (ord('h'), ord('H'), ord('n'), ord('N'), 27):
            return False

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────
def main(scr):
    init_colors()
    curses.curs_set(0)

    # Probe hardware once at startup
    st.disks  = get_disks()
    st.ifaces = get_ifaces()
    if st.disks:
        d = st.disks[0]
        st.disk       = d["path"]
        st.disk_size  = d["size"]
        st.disk_model = d["model"]
    if st.ifaces:
        st.iface = st.ifaces[0]

    while True:
        h, w = scr.getmaxyx()
        if h < 24 or w < 80:
            scr.clear()
            msg = f"Terminal çok küçük! Min 80×24, şu an {w}×{h}. Boyutu artırın."
            try:
                scr.addstr(h // 2, max(0, (w - len(msg)) // 2), msg[:w - 1],
                           curses.color_pair(C_ERR) | curses.A_BOLD)
            except curses.error:
                pass
            scr.refresh()
            scr.getch()
            continue

        scr.clear()
        DRAWERS[st.step](scr)
        scr.refresh()

        # Timeout for spinner refresh on install step
        if st.step == 9:
            scr.timeout(250)
        else:
            scr.timeout(-1)

        ch = scr.getch()
        if ch == -1:
            continue   # timeout (refresh for spinner)

        keep_going = HANDLERS[st.step](scr, ch)
        if not keep_going:
            if st.step == 9 and st.done:
                break
            elif confirm_quit(scr):
                break


if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write("\033[?25h\033[0m")
        sys.stdout.flush()
