#!/usr/bin/env python3
"""Build the pinned Nexmon drivers required by LDN, for both Pi kernels."""
import argparse
import subprocess
import tarfile
from pathlib import Path

from build_image import download_pkg, sha256_file

ARCHIVES = {
    "brcmfmac-nexmon-6.12.2.tar.xz": {
        "url": "https://http.kali.org/pool/contrib/b/brcmfmac-nexmon-dkms/brcmfmac-nexmon-dkms_6.12.2.tar.xz",
        "sha256": "36217f4b8ad54015486b3317cab7b23c4b94c84e2dff46e00ea6bf9ce5c26837",
    },
    "firmware-nexmon-0.2.tar.xz": {
        "url": "https://http.kali.org/pool/non-free-firmware/f/firmware-nexmon/firmware-nexmon_0.2.tar.xz",
        "sha256": "48530a2865d115037021a30b7529dad93d49ae371068c5d3a0f92d76cc905680",
    },
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path(__file__).resolve().parents[1] / "build")
    args = parser.parse_args()
    build = args.build_dir.resolve()
    cache = build / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    # Reuse checksum-verified downloads, with the filenames expected by the image builder.
    for name, info in ARCHIVES.items():
        if not (cache / name).exists() or sha256_file(cache / name) != info["sha256"]:
            downloaded = download_pkg(name, info, cache)
            downloaded.replace(cache / name)
    source = cache / "brcmfmac-nexmon-6.12.2.tar.xz"
    for platform, relative in [("linux/arm/v6", "."), ("linux/arm/v7", "nexmon-armv7")]:
        output = build / relative
        output.mkdir(parents=True, exist_ok=True)
        with tarfile.open(source) as tf:
            members = tf.getmembers()
            for member in members:
                name = Path(member.name)
                if name.is_absolute() or ".." in name.parts or not (member.isfile() or member.isdir()):
                    raise ValueError(f"Unexpected archive member: {member.name}")
            tf.extractall(output, members=members)
        subprocess.run([
            "docker", "run", "--rm", "--platform", platform,
            "-v", f"{output}:/out", "alpine:3.21", "sh", "-ec",
            "apk add --no-cache build-base perl elfutils-dev bash linux-rpi-dev=6.12.13-r0; "
            "make -j2 -C /usr/src/linux-headers-6.12.13-0-rpi "
            "M=/out/brcmfmac-nexmon-dkms-6.12.2 modules",
        ], check=True)
        module = output / "brcmfmac-nexmon-dkms-6.12.2/brcmfmac.ko"
        if not module.is_file():
            raise RuntimeError(f"Missing driver: {module}")
        print(f"[nexmon] Built {platform}: {module}", flush=True)


if __name__ == "__main__":
    main()
