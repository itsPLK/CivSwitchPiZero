#!/usr/bin/env python3
"""Build the CivSwitch Raspberry Pi Zero / Zero W / Zero 2 W bootable image.

Produces:
  - build/boot/              FAT boot partition files (can be copied directly to a FAT32 SD card)
  - build/initramfs.cpio.gz  Minimal initramfs with static /init, USB gadget modules, and payload.txt
  - build/civ7-pizero.img    Ready-to-flash MBR + VFAT SD card image (40 MB)

Usage:
  python3 tools/build_image.py [--payload path/to/payload.js]
"""

import argparse
import gzip
import hashlib
import io
import lzma
import math
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.request
import zlib
from pathlib import Path

ALPINE_MIRROR = "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"

PACKAGES = {
    "wireless_regdb": {
        "url": f"{ALPINE_MIRROR}/armhf/wireless-regdb-2024.07.04-r0.apk",
        "sha256": "f61a21ef99a0f06423fa3842cd1fc472118824ec9d81d6763129ac433f6d8ee6",
    },
    "bootloader_common": {
        "url": f"{ALPINE_MIRROR}/armhf/raspberrypi-bootloader-common-1.20250210-r0.apk",
        "sha256": "68a43281777c54cc7353521180cd0e17843cafef9b5f3233e055e97f9eab1ba8",
    },
    "bootloader_full": {
        "url": f"{ALPINE_MIRROR}/armhf/raspberrypi-bootloader-1.20250210-r0.apk",
        "sha256": "a28f3f32ce187f848cc9460cb062267e6ac642d7acf015c26b0476eec14fbbf6",
    },
    "bootloader_cutdown": {
        "url": f"{ALPINE_MIRROR}/armhf/raspberrypi-bootloader-cutdown-1.20250210-r0.apk",
        "sha256": "39e8dbe00394bd39258d2e9a10005ed4ef558fdb02cf8e3b3c15ed6b3ca106ff",
    },
    "linux_rpi_armhf": {
        "url": f"{ALPINE_MIRROR}/armhf/linux-rpi-6.12.13-r0.apk",
        "sha256": "af825bed978b24d283f1d4422c4ad6535b884fe643aacc4a0c0473843e7f43dd",
    },
    "linux_rpi_armv7": {
        "url": f"{ALPINE_MIRROR}/armv7/linux-rpi-6.12.13-r0.apk",
        "sha256": "b98fa05abacb5678951a1134e3c82a43da7591658ae544174d793d4f5959aec6",
    },
}

DTB_FILES = [
    "bcm2708-rpi-zero.dtb",
    "bcm2708-rpi-zero-w.dtb",
    "bcm2835-rpi-zero.dtb",
    "bcm2835-rpi-zero-w.dtb",
    "bcm2710-rpi-zero-2.dtb",
    "bcm2710-rpi-zero-2-w.dtb",
    "bcm2837-rpi-zero-2-w.dtb",
]

OVERLAY_FILES = [
    "overlays/overlay_map.dtb",
    "overlays/dwc2.dtbo",
]

KERNEL_VER = "6.12.13-0-rpi"
USB_MODULES = [
    ("roles.ko",        f"lib/modules/{KERNEL_VER}/kernel/drivers/usb/roles/roles.ko.xz"),
    ("dwc2.ko",         f"lib/modules/{KERNEL_VER}/kernel/drivers/usb/dwc2/dwc2.ko.xz"),
    ("libcomposite.ko", f"lib/modules/{KERNEL_VER}/kernel/drivers/usb/gadget/libcomposite.ko.xz"),
    ("usb_f_hid.ko",    f"lib/modules/{KERNEL_VER}/kernel/drivers/usb/gadget/function/usb_f_hid.ko.xz"),
]


WIFI_MODULES = [(Path(p).name.removesuffix(".xz"), f"lib/modules/{KERNEL_VER}/kernel/{p}") for p in [
    "net/packet/af_packet.ko.xz",
    "net/rfkill/rfkill.ko.xz", "net/wireless/cfg80211.ko.xz",
    "drivers/net/wireless/broadcom/brcm80211/brcmutil/brcmutil.ko.xz",
    "drivers/net/wireless/broadcom/brcm80211/brcmfmac/brcmfmac.ko.xz",
    "drivers/net/wireless/broadcom/brcm80211/brcmfmac/cyw/brcmfmac-cyw.ko.xz",
    "drivers/net/wireless/broadcom/brcm80211/brcmfmac/bca/brcmfmac-bca.ko.xz",
    "drivers/net/wireless/broadcom/brcm80211/brcmfmac/wcc/brcmfmac-wcc.ko.xz",
]]


def add_wifi_firmware(cpio, cache_dir, nexmon=False):
    archive = cache_dir / "wifi-firmware.tar.gz"
    if not archive.exists():
        urllib.request.urlretrieve("https://api.github.com/repos/RPi-Distro/firmware-nonfree/tarball/5d2295b633d94641253e16ba90fc847436fc9d4a", archive)
    for directory in ["lib", "lib/firmware", "lib/firmware/brcm"]:
        cpio.add_dir(directory)
    regdb = download_pkg("wireless_regdb", PACKAGES["wireless_regdb"], cache_dir)
    paths = {f"lib/firmware/{name}": cache_dir / name for name in ["regulatory.db", "regulatory.db.p7s"]}
    extract_from_apk(regdb, paths)
    for name, path in paths.items():
        cpio.add_file(name, path.read_bytes())
    if nexmon:
        archive = cache_dir / "firmware-nexmon-0.2.tar.xz"
        if sha256_file(archive) != "48530a2865d115037021a30b7529dad93d49ae371068c5d3a0f92d76cc905680":
            raise RuntimeError("Nexmon firmware archive checksum mismatch")
    with tarfile.open(archive) as tf:
        for member in tf.getmembers():
            name = Path(member.name).name
            if ("/brcm/" in member.name) and "model-zero" in name and ("model-zero-w." in name or "model-zero-2-w." in name):
                cpio.add_file("lib/firmware/brcm/" + name, tf.extractfile(member).read())


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def download_pkg(name: str, info: dict, cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    dest = cache_dir / f"{name}.apk"
    if dest.exists():
        if not info.get("sha256") or sha256_file(dest) == info["sha256"]:
            return dest
        dest.unlink()

    print(f"[download] Fetching {info['url']} ...")
    urllib.request.urlretrieve(info["url"], dest)
    actual = sha256_file(dest)
    if info.get("sha256") and actual != info["sha256"]:
        raise RuntimeError(f"SHA-256 mismatch for {name}: expected {info['sha256']}, got {actual}")
    return dest


def extract_from_apk(apk_path: Path, member_map: dict[str, Path], decompress_xz: bool = False):
    """Extract specific members from an Alpine .apk (concatenated gzip tar streams)."""
    raw = apk_path.read_bytes()
    found = set()
    rem = memoryview(raw)
    while rem and len(found) < len(member_map):
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        tar_bytes = d.decompress(rem) + d.flush()
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
            for m in tf.getmembers():
                if m.name in member_map and m.name not in found:
                    fobj = tf.extractfile(m)
                    if fobj is None:
                        continue
                    data = fobj.read()
                    if decompress_xz and m.name.endswith(".xz"):
                        data = lzma.decompress(data)
                    out_path = member_map[m.name]
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_bytes(data)
                    found.add(m.name)
        rem = d.unused_data

    missing = set(member_map.keys()) - found
    if missing:
        raise RuntimeError(f"Missing members in {apk_path.name}: {sorted(missing)}")


def patch_dtbs_for_dwc2_and_led(boot_dir: Path):
    """Bake dwc2 peripheral mode and active-low ACT LED into all Zero DTBs."""
    if shutil.which("fdtput"):
        for dtb in DTB_FILES:
            p = boot_dir / dtb
            subprocess.run(["fdtput", "-t", "s", str(p), "/soc/usb@7e980000", "compatible", "brcm,bcm2835-usb"], check=True)
            subprocess.run(["fdtput", "-t", "s", str(p), "/soc/usb@7e980000", "dr_mode", "peripheral"], check=True)
            subprocess.run(["fdtput", "-t", "x", str(p), "/soc/usb@7e980000", "g-rx-fifo-size", "0x22e"], check=True)
            subprocess.run(["fdtput", "-t", "x", str(p), "/soc/usb@7e980000", "g-np-tx-fifo-size", "0x20"], check=True)
            subprocess.run(["fdtput", "-t", "x", str(p), "/soc/usb@7e980000", "g-tx-fifo-size",
                            "0x200", "0x200", "0x200", "0x200", "0x200", "0x100", "0x100"], check=True)
            subprocess.run(["fdtput", "-t", "s", str(p), "/soc/usb@7e980000", "status", "okay"], check=True)
        subprocess.run(["fdtput", "-t", "x", str(boot_dir / "bcm2835-rpi-zero.dtb"), "/leds/led-act", "gpios", "0x06", "0x2f", "0x01"], check=True)
        return

    if shutil.which("docker"):
        print("[dtb] Patching DTBs with dwc2 peripheral mode & LED polarity via fdtput ...")
        subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{boot_dir.resolve()}:/boot",
                "alpine:3.21", "sh", "-c",
                "apk add --no-cache dtc >/dev/null && "
                "for p in /boot/*.dtb; do "
                "  fdtput -t s \"$p\" /soc/usb@7e980000 compatible brcm,bcm2835-usb && "
                "  fdtput -t s \"$p\" /soc/usb@7e980000 dr_mode peripheral && "
                "  fdtput -t x \"$p\" /soc/usb@7e980000 g-rx-fifo-size 0x22e && "
                "  fdtput -t x \"$p\" /soc/usb@7e980000 g-np-tx-fifo-size 0x20 && "
                "  fdtput -t x \"$p\" /soc/usb@7e980000 g-tx-fifo-size 0x200 0x200 0x200 0x200 0x200 0x100 0x100 && "
                "  fdtput -t s \"$p\" /soc/usb@7e980000 status okay; "
                "done && "
                "fdtput -t x /boot/bcm2835-rpi-zero.dtb /leds/led-act gpios 0x06 0x2f 0x01",
            ],
            check=True,
        )


def build_init_binary(src_c: Path, out_bin: Path, ldn_crypto=False):
    out_bin.parent.mkdir(parents=True, exist_ok=True)

    if ldn_crypto:
        subprocess.run(["docker", "run", "--rm", "--platform", "linux/arm/v6",
            "-v", f"{src_c.parent.resolve()}:/src:ro", "-v", f"{out_bin.parent.resolve()}:/out",
            "alpine:3.21", "sh", "-c",
            "apk add --no-cache build-base linux-headers openssl-dev openssl-libs-static >/dev/null && "
            "gcc -DLDN_CRYPTO -I/out/ldn -O2 -Wall -Wextra -static -s /src/init.c -o /out/init -lcrypto -pthread"], check=True)
        out_bin.chmod(0o755)
        return

    toolchains = [
        ("arm-linux-musleabihf-gcc", ["-march=armv6zk+fp", "-mtune=arm1176jzf-s", "-mfloat-abi=hard"]),
        ("arm-linux-musleabi-gcc",   ["-march=armv6zk", "-mtune=arm1176jzf-s", "-mfloat-abi=soft"]),
        ("arm-linux-gnueabi-gcc",    ["-march=armv6zk", "-mtune=arm1176jzf-s", "-mfloat-abi=soft", "-marm"]),
        ("arm-linux-gnueabihf-gcc",  ["-march=armv6zk+fp", "-mtune=arm1176jzf-s", "-mfloat-abi=hard", "-marm"]),
    ]
    for cc, arch_flags in toolchains:
        if shutil.which(cc):
            print(f"[init] Compiling {src_c.name} with {cc} ...")
            subprocess.run(
                [cc, "-O2", "-Wall", "-Wextra", "-static", *arch_flags,
                 "-s", str(src_c), "-o", str(out_bin)],
                check=True,
            )
            out_bin.chmod(0o755)
            return

    if shutil.which("zig"):
        print(f"[init] Compiling {src_c.name} with zig cc ...")
        subprocess.run(
            ["zig", "cc", "-target", "arm-linux-musleabi", "-mcpu=arm1176jzf_s",
             "-O2", "-Wall", "-Wextra", "-static", "-s", str(src_c), "-o", str(out_bin)],
            check=True,
        )
        out_bin.chmod(0o755)
        return

    if shutil.which("docker"):
        print(f"[init] Compiling {src_c.name} in Docker (linux/arm/v6 alpine:3.21) ...")
        subprocess.run(
            [
                "docker", "run", "--rm", "--platform", "linux/arm/v6",
                "-v", f"{src_c.parent.resolve()}:/src:ro",
                "-v", f"{out_bin.parent.resolve()}:/out",
                "alpine:3.21", "sh", "-c",
                "apk add --no-cache build-base linux-headers >/dev/null && "
                f"gcc -O2 -Wall -Wextra -static -s /src/{src_c.name} -o /out/{out_bin.name}",
            ],
            check=True,
        )
        out_bin.chmod(0o755)
        return

    raise RuntimeError(
        "No ARM cross-compiler (arm-linux-musleabihf-gcc / zig) or Docker found to compile init.c"
    )


class CpioNewcBuilder:
    """Deterministic SVR4 'newc' (070701) CPIO archive builder for Linux initramfs."""

    def __init__(self):
        self.buf = bytearray()
        self.ino = 1

    def _add_raw(self, name: str, mode: int, data: bytes):
        name_bytes = name.encode("utf-8") + b"\x00"
        filesize = len(data)
        nlink = 2 if (mode & 0o170000) == 0o040000 else 1
        header = (
            f"070701"
            f"{self.ino:08x}"
            f"{mode:08x}"
            f"{0:08x}"          # uid = 0 (root)
            f"{0:08x}"          # gid = 0 (root)
            f"{nlink:08x}"
            f"{0:08x}"          # mtime = 0 (deterministic)
            f"{filesize:08x}"
            f"{0:08x}{0:08x}"   # devmajor, devminor
            f"{0:08x}{0:08x}"   # rdevmajor, rdevminor
            f"{len(name_bytes):08x}"
            f"{0:08x}"          # check
        ).encode("ascii")
        self.ino += 1
        self.buf.extend(header)
        self.buf.extend(name_bytes)
        while len(self.buf) % 4 != 0:
            self.buf.append(0)
        if data:
            self.buf.extend(data)
            while len(self.buf) % 4 != 0:
                self.buf.append(0)

    def add_dir(self, path: str, mode: int = 0o755):
        self._add_raw(path.lstrip("/"), 0o040000 | mode, b"")

    def add_file(self, path: str, data: bytes, mode: int = 0o644):
        self._add_raw(path.lstrip("/"), 0o100000 | mode, data)

    def finish_gzip(self) -> bytes:
        self._add_raw("TRAILER!!!", 0, b"")
        while len(self.buf) % 512 != 0:
            self.buf.append(0)
        out = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=out, compresslevel=9, mtime=0) as gz:
            gz.write(self.buf)
        return out.getvalue()


def build_initramfs(init_bin: Path, payload_txt: Path, modules_dir: Path, out_cpio_gz: Path, nexmon=False, ldn_crypto=False):
    cpio = CpioNewcBuilder()
    for d in ["dev", "proc", "sys", "boot", "modules", "modules/armv6l", "modules/armv7l"]:
        cpio.add_dir(d, 0o755)

    cpio.add_file("init", init_bin.read_bytes(), 0o755)
    cpio.add_file("payload.txt", payload_txt.read_bytes(), 0o644)
    if ldn_crypto:
        cpio.add_dir("ldn")
        for name in ("template.b64", "apply.b64"):
            cpio.add_file("ldn/" + name, (init_bin.parent / "ldn" / name).read_bytes())

    for arch in ["armv6l", "armv7l"]:
        for mod_name, _ in USB_MODULES + WIFI_MODULES:
            if nexmon and mod_name.startswith("brcmfmac-"):
                continue
            ko_path = modules_dir / arch / mod_name
            if nexmon and mod_name == "brcmfmac.ko":
                base = modules_dir.parent if arch == "armv6l" else modules_dir.parent / "nexmon-armv7"
                ko_path = base / "brcmfmac-nexmon-dkms-6.12.2" / "brcmfmac.ko"
            cpio.add_file(f"modules/{arch}/{mod_name}", ko_path.read_bytes(), 0o644)

    add_wifi_firmware(cpio, modules_dir.parent / "cache", nexmon)
    if nexmon:
        cpio.add_file("nexmon", b"driver=6.12.2 firmware=0.2\n")

    out_cpio_gz.parent.mkdir(parents=True, exist_ok=True)
    data = cpio.finish_gzip()
    out_cpio_gz.write_bytes(data)
    print(f"[initramfs] Wrote {out_cpio_gz} ({len(data) / 1024:.1f} KB)")


# --- Pure-Python MBR + VFAT (FAT16 with unmangled 8.3 short names + LFN) Image Builder ---

def _lfn_checksum(short_name_11: bytes) -> int:
    s = 0
    for b in short_name_11:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def _make_short_name(name: str, used: set[bytes]) -> tuple[bytes, bool, int]:
    """Return (11-byte 8.3 short name, needs_lfn, nt_reserved_byte).

    Crucial for Raspberry Pi boot ROM: any filename that fits in 8.3 (such as
    bootcode.bin, start.elf, fixup.dat, config.txt, cmdline.txt, kernel.img,
    kernel7.img, initramf.gz) MUST use its exact unmangled 8.3 short name
    (e.g. 'BOOTCODEBIN', 'START   ELF') so the BCM2835 mask ROM (which does
    not parse VFAT LFN entries) finds BOOTCODE.BIN and START.ELF immediately.
    """
    upper = name.upper()
    parts = upper.split(".")
    orig_parts = name.split(".")
    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()-@^_`{}~")

    if (
        len(parts) <= 2
        and 1 <= len(parts[0]) <= 8
        and (len(parts) == 1 or 1 <= len(parts[1]) <= 3)
        and all(c in valid_chars for c in parts[0])
        and (len(parts) == 1 or all(c in valid_chars for c in parts[1]))
    ):
        base = parts[0].ljust(8).encode("ascii")
        ext = (parts[1] if len(parts) == 2 else "").ljust(3).encode("ascii")
        cand = base + ext
        if cand not in used:
            used.add(cand)
            base_str = orig_parts[0]
            ext_str = orig_parts[1] if len(orig_parts) == 2 else ""
            base_lower = base_str == base_str.lower() and base_str != base_str.upper()
            base_upper = base_str == base_str.upper()
            ext_lower = ext_str == ext_str.lower() and ext_str != ext_str.upper()
            ext_upper = ext_str == ext_str.upper()
            if (base_lower or base_upper) and (ext_lower or ext_upper):
                nt_byte = (0x08 if base_lower else 0x00) | (0x10 if ext_lower else 0x00)
                return cand, False, nt_byte
            return cand, True, 0x00

    raw_base = "".join(c for c in (parts[0] if parts else "FILE") if c in valid_chars) or "FILE"
    raw_ext = "".join(c for c in (parts[-1] if len(parts) > 1 else "") if c in valid_chars)[:3]
    for idx in range(1, 10000):
        suffix = f"~{idx}"
        prefix = raw_base[: 8 - len(suffix)]
        cand = prefix.ljust(8 - len(suffix)) + suffix
        cand_bytes = cand.encode("ascii") + raw_ext.ljust(3).encode("ascii")
        if cand_bytes not in used:
            used.add(cand_bytes)
            return cand_bytes, True, 0x00
    raise RuntimeError(f"Could not allocate short name for {name}")


def _make_dir_entries(name: str, attr: int, first_cluster: int, size: int, used_short: set[bytes]) -> bytes:
    short_11, needs_lfn, nt_byte = _make_short_name(name, used_short)
    entries = bytearray()

    if needs_lfn:
        chk = _lfn_checksum(short_11)
        utf16 = name.encode("utf-16le") + b"\x00\x00"
        while len(utf16) % 26 != 0:
            utf16 += b"\xff\xff"
        num_slots = len(utf16) // 26
        for slot in range(num_slots, 0, -1):
            chunk = utf16[(slot - 1) * 26 : slot * 26]
            ord_byte = slot | (0x40 if slot == num_slots else 0)
            lfn = struct.pack(
                "<B10sBBB12sH4s",
                ord_byte,
                chunk[0:10],
                0x0F,       # ATTR_LONG_NAME
                0x00,       # type
                chk,
                chunk[10:22],
                0x0000,     # first cluster = 0
                chunk[22:26],
            )
            entries.extend(lfn)

    dos_date = ((2025 - 1980) << 9) | (2 << 5) | 10
    dos_time = 0
    sfn = struct.pack(
        "<11sBBBHHHHHHHL",
        short_11,
        attr,
        nt_byte,
        0,
        dos_time,
        dos_date,
        dos_date,
        (first_cluster >> 16) & 0xFFFF,
        dos_time,
        dos_date,
        first_cluster & 0xFFFF,
        size,
    )
    entries.extend(sfn)
    return bytes(entries)


def create_fat16_boot_image(boot_dir: Path, out_img: Path, size_mb: int = 40):
    """Create an MBR-partitioned FAT16 LBA bootable SD card image from boot_dir."""
    sector_size = 512
    total_sectors = (size_mb * 1024 * 1024) // sector_size
    part_start_lba = 2048  # 1 MiB alignment
    part_sectors = total_sectors - part_start_lba

    sectors_per_cluster = 8  # 4096 bytes per cluster
    cluster_size = sector_size * sectors_per_cluster
    reserved_sectors = 4
    num_fats = 2
    root_dir_entries = 512
    root_dir_sectors = (root_dir_entries * 32) // sector_size  # 32 sectors
    sectors_per_fat = 64

    data_start_sector = reserved_sectors + num_fats * sectors_per_fat + root_dir_sectors
    total_clusters = (part_sectors - data_start_sector) // sectors_per_cluster
    assert 4085 <= total_clusters < 65525, f"Invalid FAT16 cluster count: {total_clusters}"

    fat = [0] * (total_clusters + 2)
    fat[0] = 0xFFF8
    fat[1] = 0xFFFF
    next_cluster = 2
    clusters_data: dict[int, bytes] = {}

    def alloc_bytes(blob: bytes) -> int:
        nonlocal next_cluster
        if not blob:
            return 0
        n_clust = math.ceil(len(blob) / cluster_size)
        first = next_cluster
        for i in range(n_clust):
            c = next_cluster
            next_cluster += 1
            chunk = blob[i * cluster_size : (i + 1) * cluster_size]
            if len(chunk) < cluster_size:
                chunk = chunk + b"\x00" * (cluster_size - len(chunk))
            clusters_data[c] = chunk
            fat[c] = (c + 1) if (i + 1 < n_clust) else 0xFFFF
        return first

    root_entries = bytearray()
    used_root_short: set[bytes] = set()
    dos_date = ((2025 - 1980) << 9) | (2 << 5) | 10

    # Place critical 8.3 boot files first in the root directory so the BCM2835
    # ROM bootloader sees BOOTCODE.BIN and START.ELF in the very first slots.
    priority_order = [
        "bootcode.bin",
        "start.elf",
        "fixup.dat",
        "start4.elf",
        "fixup4.dat",
        "start_cd.elf",
        "fixup_cd.dat",
        "config.txt",
        "cmdline.txt",
        "kernel.img",
        "kernel7.img",
        "initramf.gz",
        "payload.txt",
    ]

    def sort_key(p: Path):
        if p.name in priority_order:
            return (0, priority_order.index(p.name), p.name)
        return (1, 0, p.name)

    for item in sorted(boot_dir.iterdir(), key=sort_key):
        if item.name.startswith("."):
            continue
        if item.is_file():
            content = item.read_bytes()
            c_start = alloc_bytes(content)
            root_entries.extend(_make_dir_entries(item.name, 0x20, c_start, len(content), used_root_short))
        elif item.is_dir():
            dir_cluster = next_cluster
            next_cluster += 1
            fat[dir_cluster] = 0xFFFF
            sub_entries = bytearray()
            sub_entries.extend(
                struct.pack("<11sBBBHHHHHHHL", b".          ", 0x10, 0, 0, 0, dos_date, dos_date, 0, 0, dos_date, dir_cluster, 0)
            )
            sub_entries.extend(
                struct.pack("<11sBBBHHHHHHHL", b"..         ", 0x10, 0, 0, 0, dos_date, dos_date, 0, 0, dos_date, 0, 0)
            )
            used_sub_short: set[bytes] = set()
            for sub in sorted(item.iterdir(), key=lambda p: p.name):
                if sub.is_file() and not sub.name.startswith("."):
                    scontent = sub.read_bytes()
                    sc_start = alloc_bytes(scontent)
                    sub_entries.extend(_make_dir_entries(sub.name, 0x20, sc_start, len(scontent), used_sub_short))
            clusters_data[dir_cluster] = bytes(sub_entries).ljust(cluster_size, b"\x00")
            root_entries.extend(_make_dir_entries(item.name, 0x10, dir_cluster, 0, used_root_short))

    # Place volume label entry at the end so bootcode.bin and start.elf remain at slots 0 and 1
    root_entries.extend(
        struct.pack("<11sBBBHHHHHHHL", b"CIVSWITCH  ", 0x08, 0, 0, 0, dos_date, dos_date, 0, 0, dos_date, 0, 0)
    )

    assert len(root_entries) <= root_dir_sectors * sector_size, "Root directory overflow"

    img = bytearray(total_sectors * sector_size)

    # 1. Write MBR at LBA 0
    mbr = bytearray(512)
    mbr[440:444] = struct.pack("<I", 0x43495637)
    mbr[446:462] = struct.pack(
        "<BBBBBBBBII",
        0x80,              # status: bootable
        0x00, 0x01, 0x00,  # CHS start
        0x0E,              # partition type: W95 FAT16 (LBA)
        0xFE, 0xFF, 0xFF,  # CHS end
        part_start_lba,
        part_sectors,
    )
    mbr[510:512] = b"\x55\xaa"
    img[0:512] = mbr

    # 2. Write FAT16 Boot Sector (VBR) at part_start_lba
    vbr = bytearray(512)
    vbr[0:3] = b"\xeb\x3c\x90"
    vbr[3:11] = b"mkfs.fat"
    struct.pack_into(
        "<HBHBHHBHHHII",
        vbr,
        11,
        sector_size,
        sectors_per_cluster,
        reserved_sectors,
        num_fats,
        root_dir_entries,
        part_sectors if part_sectors < 65536 else 0,
        0xF8,
        sectors_per_fat,
        63,
        255,
        part_start_lba,
        part_sectors if part_sectors >= 65536 else 0,
    )
    struct.pack_into(
        "<BBBI11s8s",
        vbr,
        36,
        0x80,
        0x00,
        0x29,
        0x20261102,
        b"CIVSWITCH  ",
        b"FAT16   ",
    )
    vbr[510:512] = b"\x55\xaa"
    part_offset = part_start_lba * sector_size
    img[part_offset : part_offset + 512] = vbr

    # 3. Write FAT tables
    fat_bytes = bytearray(sectors_per_fat * sector_size)
    for idx, val in enumerate(fat):
        struct.pack_into("<H", fat_bytes, idx * 2, val & 0xFFFF)

    for f_idx in range(num_fats):
        f_off = part_offset + (reserved_sectors + f_idx * sectors_per_fat) * sector_size
        img[f_off : f_off + len(fat_bytes)] = fat_bytes

    # 4. Write Root Directory
    root_off = part_offset + (reserved_sectors + num_fats * sectors_per_fat) * sector_size
    img[root_off : root_off + len(root_entries)] = root_entries

    # 5. Write Data Clusters
    data_off = part_offset + data_start_sector * sector_size
    for c_idx, c_blob in clusters_data.items():
        c_pos = data_off + (c_idx - 2) * cluster_size
        img[c_pos : c_pos + cluster_size] = c_blob

    out_img.parent.mkdir(parents=True, exist_ok=True)
    out_img.write_bytes(img)
    print(f"[image] Wrote {out_img} ({len(img) / (1024 * 1024):.1f} MB, {next_cluster - 2}/{total_clusters} clusters used)")


def main():
    parser = argparse.ArgumentParser(description="Build CivSwitch Raspberry Pi Zero minimal OS image")
    parser.add_argument("--payload", type=str, default=None, help="Optional custom JS payload to stage into ../core.js")
    parser.add_argument("--diagnostics", action="store_true", help="Enable SD logging and Wi-Fi bring-up probe")
    parser.add_argument("--nexmon", action="store_true", help="Use locally built Nexmon modules and cached firmware 0.2")
    parser.add_argument("--ldn-crypto", action="store_true", help="Enable SD-card key loading and advertisement decryption (Docker)")
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parent.parent
    civswitch_dir = root_dir / "CivSwitch"
    pico_dir = civswitch_dir / "PicoSwitch"
    if not pico_dir.exists():
        raise RuntimeError(
            f"Submodule directory {civswitch_dir} is missing or uninitialized. "
            "Run: git submodule update --init --recursive"
        )

    cache_dir = root_dir / "build" / "cache"
    stage_dir = root_dir / "build" / "stage"
    boot_out = root_dir / "build" / "boot"
    modules_out = root_dir / "build" / "modules"
    init_bin = root_dir / "build" / "init"
    payload_txt = root_dir / "build" / "payload.txt"

    # 1. Stage payload from CivSwitch submodule (keeping the submodule worktree 100% clean)
    stage_pico = stage_dir / "PicoSwitch"
    stage_pico.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(pico_dir / "package.json", stage_pico / "package.json")
    shutil.copyfile(pico_dir / "compress.js", stage_pico / "compress.js")

    if args.payload:
        shutil.copyfile(pico_dir / "tools" / "make_payload.py", stage_pico / "make_payload.py")
        subprocess.run([sys.executable, str(stage_pico / "make_payload.py"), str(Path(args.payload).resolve())], cwd=str(stage_pico), check=True)
    else:
        shutil.copyfile(civswitch_dir / "core.js", stage_dir / "core.js")

    if not (stage_pico / "node_modules" / "terser").exists():
        print("[payload] Installing terser in build/stage ...")
        subprocess.run(["npm", "install", "--silent"], cwd=str(stage_pico), check=True)

    print("[payload] Compressing CivSwitch/core.js -> build/payload.txt ...")
    subprocess.run(["node", "compress.js"], cwd=str(stage_pico), check=True)
    shutil.copyfile(stage_pico / "payload.txt", payload_txt)

    if args.ldn_crypto:
        subprocess.run([sys.executable, str(root_dir / "tools/ldn/build_payloads.py")], check=True)

    # 2. Compile static ARMv6 /init binary from src/init.c
    build_init_binary(root_dir / "src" / "init.c", init_bin, args.ldn_crypto)

    # 3. Download and extract RPi bootloader, DTBs, kernels, and USB gadget modules
    apk_paths = {k: download_pkg(k, v, cache_dir) for k, v in PACKAGES.items()}

    if boot_out.exists():
        shutil.rmtree(boot_out)
    boot_out.mkdir(parents=True, exist_ok=True)

    extract_from_apk(
        apk_paths["bootloader_common"],
        {"boot/bootcode.bin": boot_out / "bootcode.bin"},
    )
    extract_from_apk(
        apk_paths["bootloader_full"],
        {
            "boot/start.elf": boot_out / "start.elf",
            "boot/fixup.dat": boot_out / "fixup.dat",
            "boot/start4.elf": boot_out / "start4.elf",
            "boot/fixup4.dat": boot_out / "fixup4.dat",
        },
    )
    extract_from_apk(
        apk_paths["bootloader_cutdown"],
        {
            "boot/start_cd.elf": boot_out / "start_cd.elf",
            "boot/fixup_cd.dat": boot_out / "fixup_cd.dat",
        },
    )

    armhf_boot_map = {"boot/vmlinuz-rpi": boot_out / "kernel.img"}
    for dtb in DTB_FILES:
        armhf_boot_map[f"boot/{dtb}"] = boot_out / dtb
    for ovl in OVERLAY_FILES:
        armhf_boot_map[f"boot/{ovl}"] = boot_out / ovl
    extract_from_apk(apk_paths["linux_rpi_armhf"], armhf_boot_map)

    extract_from_apk(
        apk_paths["linux_rpi_armv7"],
        {"boot/vmlinuz-rpi": boot_out / "kernel7.img"},
    )

    patch_dtbs_for_dwc2_and_led(boot_out)

    extract_from_apk(
        apk_paths["linux_rpi_armhf"],
        {src: modules_out / "armv6l" / dst for dst, src in USB_MODULES + WIFI_MODULES},
        decompress_xz=True,
    )
    extract_from_apk(
        apk_paths["linux_rpi_armv7"],
        {src: modules_out / "armv7l" / dst for dst, src in USB_MODULES + WIFI_MODULES},
        decompress_xz=True,
    )

    # 4. Pack initramf.gz (pure 8.3 name so RPi bootloader needs no LFN)
    initramfs_path = boot_out / "initramf.gz"
    build_initramfs(init_bin, payload_txt, modules_out, initramfs_path, args.nexmon, args.ldn_crypto)
    shutil.copyfile(initramfs_path, root_dir / "build" / "initramfs.cpio.gz")

    # 5. Copy config.txt, cmdline.txt, civswitch.conf, and payload.txt to boot partition
    for cfg in ["config.txt", "cmdline.txt", "civswitch.conf"]:
        shutil.copyfile(root_dir / "boot" / cfg, boot_out / cfg)
    shutil.copyfile(payload_txt, boot_out / "payload.txt")

    if args.diagnostics:
        conf = boot_out / "civswitch.conf"
        conf.write_text(conf.read_text().replace("SD_LOG=0", "SD_LOG=1").replace("WIFI_DIAGNOSTICS=0", "WIFI_DIAGNOSTICS=1"))

    if args.nexmon:
        for archive, target in [("firmware-nexmon-0.2.tar.xz", "nexmon-firmware-license.txt"), ("brcmfmac-nexmon-6.12.2.tar.xz", "nexmon-driver-license.txt")]:
            with tarfile.open(cache_dir / archive) as tf:
                member = next(m for m in tf if m.name.endswith("/debian/copyright"))
                (boot_out / target).write_bytes(tf.extractfile(member).read())

    # 6. Create bootable SD card image build/civ7-pizero.img
    img_path = root_dir / "build" / "civ7-pizero.img"
    create_fat16_boot_image(boot_out, img_path, size_mb=40)
    print(f"[done] Ready to flash: {img_path}")


if __name__ == "__main__":
    main()
