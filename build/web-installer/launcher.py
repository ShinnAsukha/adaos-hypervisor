#!/usr/bin/env python3
"""GTK WebKit2 kiosk launcher for OXware Web Installer."""
import sys
import time

try:
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('WebKit2', '4.0')
    from gi.repository import Gtk, WebKit2, GLib

    def _retry(wv):
        wv.load_uri('http://127.0.0.1:8888')
        return False

    def on_load_failed(wv, evt, uri, err):
        GLib.timeout_add(1500, lambda: _retry(wv))

    win = Gtk.Window()
    win.fullscreen()
    win.set_decorated(False)
    win.set_title('OXware Hypervisor Installer')

    ctx = WebKit2.WebContext.get_default()
    ctx.set_cache_model(WebKit2.CacheModel.DOCUMENT_VIEWER)

    settings = WebKit2.Settings()
    settings.set_enable_javascript(True)
    settings.set_enable_developer_extras(False)
    settings.set_enable_write_console_messages_to_stdout(True)
    settings.set_hardware_acceleration_policy(
        WebKit2.HardwareAccelerationPolicy.NEVER)

    wv = WebKit2.WebView.new_with_context(ctx)
    wv.set_settings(settings)
    wv.connect('load-failed', on_load_failed)
    wv.load_uri('http://127.0.0.1:8888')

    win.add(wv)
    win.show_all()
    win.connect('destroy', Gtk.main_quit)
    Gtk.main()

except Exception as e:
    print(f"[launcher] GTK/WebKit unavailable: {e}", file=sys.stderr)
    # Fallback: open in any available browser
    import subprocess
    for browser in ('epiphany', 'midori', 'surf', 'chromium-browser', 'firefox'):
        try:
            subprocess.run([browser, '--kiosk', 'http://127.0.0.1:8888'], check=False)
            break
        except FileNotFoundError:
            continue
