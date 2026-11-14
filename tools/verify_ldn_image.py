#!/usr/bin/env python3
"""Reject release initramfs archives that lack the LDN build components."""
import gzip
import sys
from pathlib import Path


def read_newc(data):
    files = {}
    offset = 0
    while offset < len(data):
        header = data[offset:offset+110]
        if len(header) != 110 or header[:6] != b"070701":
            raise ValueError("Invalid newc archive")
        size = int(header[54:62], 16)
        namesize = int(header[94:102], 16)
        offset += 110
        name = data[offset:offset+namesize-1].decode()
        offset = (offset + namesize + 3) & ~3
        if name == "TRAILER!!!":
            return files
        files[name] = data[offset:offset+size]
        if len(files[name]) != size:
            raise ValueError("Truncated newc entry")
        offset = (offset + size + 3) & ~3
    raise ValueError("Missing newc trailer")


def verify(path):
    files = read_newc(gzip.decompress(Path(path).read_bytes()))
    required = ["nexmon", "ldn/template.b64", "ldn/apply.b64"]
    for arch in ("armv6l", "armv7l"):
        required.append(f"modules/{arch}/brcmfmac.ko")
        if f"modules/{arch}/brcmfmac-cyw.ko" in files:
            raise ValueError(f"Stock driver variant packaged for {arch}")
    for board in ("zero-w", "zero-2-w"):
        if not any("/brcm/" in name and f"model-{board}.bin" in name and data
                   for name, data in files.items()):
            raise ValueError(f"Missing Nexmon firmware for {board}")
    for name in required:
        if not files.get(name):
            raise ValueError(f"Missing LDN component: {name}")
    print("[verify] LDN payloads, Nexmon marker, both drivers and board firmwares present")


if __name__ == "__main__":
    verify(sys.argv[1])
