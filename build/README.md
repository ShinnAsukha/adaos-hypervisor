# OXware ISO Build

## Requirements

- Ubuntu 22.04+ or Debian 12 host
- 10 GB free disk space
- Root / sudo access
- Internet connection (packages are downloaded during build)

## Build

```bash
sudo bash build/build-iso.sh
```

The script installs all required build tools automatically, then produces:

```
oxware-YYYYMMDD.iso   (~800 MB)
```

## Write to USB / Disk

**Linux:**
```bash
dd if=oxware-YYYYMMDD.iso of=/dev/sdX bs=4M status=progress
```

**Windows:** Use [Rufus](https://rufus.ie) or [Ventoy](https://ventoy.net).

## Boot & Install

1. Boot the server from the ISO / USB.
2. The TUI installer launches automatically on tty1.
3. Follow the wizard (disk selection, network, hostname, password).
4. After reboot the OXware web UI is available at `https://<server-ip>:8006`.

## Automated Build via GitHub Actions

Push a git tag to trigger a full build and upload the ISO to GitHub Releases:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

The workflow (`.github/workflows/build-iso.yml`) runs on `ubuntu-22.04`,
builds the ISO, and attaches it as a release asset automatically.

For non-tag builds (e.g. manual `workflow_dispatch`), the ISO is uploaded
as a workflow artifact instead.

## Directory layout

```
build/
  build-iso.sh          # Main build script (run this)
  installer/
    install.py          # Python curses TUI installer (embedded in ISO)
  rootfs/
    etc/
      motd              # Live-boot welcome message
      systemd/system/
        oxware-installer.service   # Launches installer on tty1 at live boot
        oxware.service             # OXware backend on installed system
  grub/
    grub.cfg            # GRUB boot menu
  README.md             # This file
```
