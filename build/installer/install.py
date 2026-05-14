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
    """Screen 1: welcome + ASCII logo."""
    while True:
        draw_frame(win)
        h, w = win.getmaxyx()
        top, left, ch, cw = content_area(win)

        row = top + 1
        battr = curses.color_pair(CP_BORDER) | curses.A_BOLD
        for line in BANNER:
            center_str(win, row, line, battr)
            row += 1

        row += 1
        center_str(win, row,
                   f"Hypervisor Installation — Version {VERSION}",
                   curses.color_pair(CP_NORMAL) | curses.A_BOLD)
        row += 2
        center_str(win, row,
                   "This wizard will guide you through installing OXware",
                   curses.color_pair(CP_DIM))
        row += 1
        center_str(win, row,
                   "on your server. All data on the selected disk will be erased.",
                   curses.color_pair(CP_DIM))
        row += 3
        center_str(win, row,
                   "[ Press ENTER to start installation ]",
                   curses.color_pair(CP_HEADER) | curses.A_BOLD)

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

    progress_cb(16, "Running debootstrap (this may take several minutes) …")
    run(f"debootstrap bookworm {TARGET_MOUNT} http://deb.debian.org/debian")

    progress_cb(45, "Mounting virtual filesystems …")
    for fs in ("proc", "sys", "dev", "dev/pts"):
        Path(f"{TARGET_MOUNT}/{fs}").mkdir(parents=True, exist_ok=True)
        if fs == "dev":
            run(f"mount --bind /dev {TARGET_MOUNT}/dev", check=False)
        elif fs == "dev/pts":
            run(f"mount --bind /dev/pts {TARGET_MOUNT}/dev/pts", check=False)
        else:
            run(f"mount -t {fs} {fs} {TARGET_MOUNT}/{fs}", check=False)

    progress_cb(48, "Installing system packages …")
    run_chroot("apt-get update -qq")
    run_chroot(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
        "linux-image-amd64 grub-pc grub-efi-amd64 grub2-common os-prober "
        "python3 python3-pip python3-flask python3-flask-jwt-extended "
        "qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils "
        "nginx parted dosfstools e2fsprogs "
        "curl wget git systemd openssh-server "
        "iproute2 iputils-ping net-tools sudo"
    )

    progress_cb(70, "Installing OXware from GitHub …")
    target_oxware = Path(f"{TARGET_MOUNT}/opt/oxware")
    if target_oxware.exists():
        shutil.rmtree(str(target_oxware))

    # Clone from GitHub so future updates work via git pull (no reinstall needed)
    GITHUB_REPO = "https://github.com/ShinnAsukha/oxware-hypervisor.git"
    clone_result = subprocess.run(
        ["git", "clone", "--depth=1", GITHUB_REPO, str(target_oxware)],
        capture_output=True, text=True, timeout=120
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

    # network interfaces
    if state.net_mode == "dhcp":
        net_cfg = (
            "auto lo\niface lo inet loopback\n\n"
            "auto eth0\niface eth0 inet dhcp\n"
        )
    else:
        net_cfg = (
            "auto lo\niface lo inet loopback\n\n"
            f"auto eth0\n"
            f"iface eth0 inet static\n"
            f"    address {state.ip}\n"
            f"    netmask {state.netmask}\n"
            f"    gateway {state.gateway}\n"
            f"    dns-nameservers {state.dns}\n"
        )
    Path(f"{TARGET_MOUNT}/etc/network/interfaces").write_text(net_cfg)

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

    # root password in chroot
    run_chroot(f"echo 'root:{state.password}' | chpasswd")

    progress_cb(78, "Installing GRUB bootloader …")

    # Force traditional eth0 interface naming (predictable names break /etc/network/interfaces)
    grub_default_file = Path(f"{TARGET_MOUNT}/etc/default/grub")
    grub_default_content = (
        'GRUB_DEFAULT=0\n'
        'GRUB_TIMEOUT=5\n'
        'GRUB_DISTRIBUTOR="OXware"\n'
        'GRUB_CMDLINE_LINUX_DEFAULT="quiet net.ifnames=0 biosdevname=0"\n'
        'GRUB_CMDLINE_LINUX=""\n'
    )
    grub_default_file.parent.mkdir(parents=True, exist_ok=True)
    grub_default_file.write_text(grub_default_content)

    run_chroot(f"grub-install --target=i386-pc {disk}")
    run_chroot(f"grub-install --target=x86_64-efi --efi-directory=/boot/efi "
               f"--bootloader-id=OXware --removable", check=False)
    run_chroot("update-grub")

    progress_cb(83, "Writing oxware systemd service …")
    svc = """\
[Unit]
Description=OXware Hypervisor Backend
After=network.target libvirtd.service
Wants=libvirtd.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/oxware/backend
ExecStart=/usr/bin/python3 /opt/oxware/backend/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

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

    progress_cb(87, "Enabling services …")
    run_chroot("systemctl enable libvirtd", check=False)
    run_chroot("systemctl enable nginx",    check=False)
    run_chroot("systemctl enable oxware",   check=False)
    run_chroot("systemctl enable ssh",      check=False)
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
    """Screen 8: progress bar + live log."""
    h, w  = win.getmaxyx()
    top, left, ch, cw = content_area(win)
    log_lines = []
    pct_state = [0]
    error_msg = [None]

    draw_frame(win)
    try:
        win.addstr(top, left + 2,
                   " Installing OXware … ",
                   curses.color_pair(CP_HEADER) | curses.A_BOLD)
    except curses.error:
        pass
    win.refresh()

    bar_row  = top + 2
    bar_col  = left + 2
    bar_w    = cw - 4
    log_top  = bar_row + 3
    log_rows = ch - log_top - 1
    max_log  = max(1, log_rows)

    def progress_cb(pct, msg):
        pct_state[0] = pct
        log_lines.append(msg)
        if len(log_lines) > max_log * 3:
            log_lines.pop(0)

        # Redraw progress portion only (no full frame redraw to avoid flicker)
        try:
            draw_progress_bar(win, bar_row, bar_col, bar_w, pct)
            visible = log_lines[-max_log:]
            for i in range(max_log):
                attr = curses.color_pair(CP_NORMAL)
                text = visible[i] if i < len(visible) else ""
                win.addstr(log_top + i, left + 1,
                           ("  " + text)[:cw - 2].ljust(cw - 2), attr)
        except curses.error:
            pass
        win.refresh()

    win.nodelay(False)

    try:
        do_install(progress_cb)
    except Exception as e:
        error_msg[0] = str(e)

    if error_msg[0]:
        return ("error", error_msg[0])

    # wait for keypress
    while True:
        try:
            win.addstr(top + ch - 2, left + 2,
                       "Installation finished! Press ENTER to continue.",
                       curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except curses.error:
            pass
        win.refresh()
        key = win.getch()
        if key in (10, 13, curses.KEY_ENTER):
            return ("next", None)


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


if __name__ == "__main__":
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
