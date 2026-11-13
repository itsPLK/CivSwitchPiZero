# CivSwitch for Raspberry Pi Zero

Install CivSwitch over local wireless (LDN) or USB using a Raspberry Pi Zero.
The image boots from an SD card and runs in RAM. No Raspberry Pi OS setup is needed.

| Board | Installation method |
| --- | --- |
| Pi Zero | USB |
| Pi Zero W | LDN first, USB if no lobby is found |
| Pi Zero 2 W | LDN first, USB if no lobby is found |

LDN installation has been tested on Zero W and Zero 2 W. USB installation has
been tested on the original Zero (non-W).

## Setup

Flash `build/civ7-pizero.img` with Raspberry Pi Imager or BalenaEtcher.
The 40 MiB image supports all three boards.

### Wireless

1. Copy your `prod.keys` to the root of the `CIVSWITCH` SD partition.
2. Open a Civ VII local wireless host lobby on the Switch.
3. Power the Pi and leave the lobby open until installation finishes. Allow up to four minutes.

No internet connection or home Wi-Fi credentials are needed. You can power the
Pi through `PWR IN`. Connect the **USB** data port to the Switch or dock if you
also want USB fallback.

The Pi scans channels 1, 6, and 11 once per boot. Keep only the intended lobby
open nearby: it selects the first verified LDN network without checking the
game ID. Missing keys or no usable lobby lead to USB. After selecting a lobby,
it stays in wireless mode until reboot, even if installation fails.

**UDP PAYLOAD CHANNEL** on the console is normal. The installer sends its files
over that channel and requests any missing chunks. Check the console for the
installation result.

### USB

Follow the [CivSwitch/PicoSwitch setup instructions](https://github.com/Gezine/CivSwitch/tree/main/PicoSwitch)
to prepare the game, then connect the Pi's **USB** micro-USB port to the Switch
or dock. `PWR IN` supplies power only.

The non-W Zero starts in USB mode. On wireless models, either wait for discovery
to finish or set these options in `civswitch.conf` to skip it:

```ini
LDN_INSTALL=0
WIFI_DIAGNOSTICS=0
```

Typing starts two seconds after USB enumeration. The default 87-line bootstrap
takes about 15–20 minutes. Once finished, disconnecting USB for more than one
second re-arms playback.

ACT LED during USB operation:

- Blinking: waiting for the Switch.
- Solid: typing.
- Off: finished.
- Rapid blinking: initialization or USB delivery failed.

## SD-card settings

Edit `civswitch.conf` on the `CIVSWITCH` partition:

| Setting | Default | Purpose |
| --- | --- | --- |
| `LDN_INSTALL` | `1` | Try wireless installation before USB. |
| `WIFI_DIAGNOSTICS` | `0` | Run radio diagnostics even when LDN installation is disabled. |
| `SD_LOG` | `0` | Save a boot/install log to `civswitch.log`. |
| `LANG_JP` | `0` | Use Japanese input mode for USB typing. |

USB timing settings are in the same file. You can also replace `payload.txt`
without rebuilding; that file affects USB typing only.

`prod.keys` must contain `master_key_00`, `aes_kek_generation_source`, and
`aes_key_generation_source` as 16-byte hexadecimal values. Keys stay on the
card and are never included in the image or printed in logs.

## Troubleshooting

Set `SD_LOG=1`, retry, then power off and read `civswitch.log` from the card.
Allow four minutes for a wireless attempt to finish before removing power.
The log is overwritten on each boot.

- `boot_transport` shows which method was selected.
- `ldn_keys` reports whether the required keys loaded.
- `ldn_authenticated=1` means the LDN handshake succeeded.
- `assigned_ip=found` means the console assigned the Pi an address.
- `installer_transfer=acknowledged` means the files arrived. Confirm installation on the console.

Authentication retries up to three times. If the console keeps requesting
repairs and installation stalls, check the transfer receive/drop counters in
the log. Restart the game before retrying a partially started installer.

Logging briefly writes to the SD card after the wireless attempt and before USB
playback. Early initialization failures and later USB playback errors are not
captured in this log.

## Updating an existing card

When the kernels and firmware match, copy `build/boot/initramf.gz` over the
card's `initramf.gz`. Update `payload.txt` too if the USB payload changed.
Keep your keys and settings, then eject the card.

For kernel or firmware changes, update the other files in `build/boot/` as well,
or reflash the image. Back up keys and settings before reflashing.

## Building

Install Python 3, Node.js/npm, and Docker with ARMv6/ARMv7 container support.
Prepare the Nexmon modules below, then run:

```sh
git submodule update --init --recursive
python3 tools/build_image.py --nexmon --ldn-crypto
```

The build writes `build/civ7-pizero.img` and the boot files in `build/boot/`.
It downloads dependencies, so internet access is required while building.

Options:

- `--diagnostics`: enable SD logging and Wi-Fi diagnostics in the image.
- `--payload path/to/custom.js`: use a custom USB payload. LDN uses the pinned CivSwitch installer.
- Omit `--nexmon --ldn-crypto` for a USB-only image.

LDN payload generation lives in `tools/ldn/build_payloads.py`.

### Nexmon modules

The builder expects precompiled drivers for the packaged `6.12.13-0-rpi` kernels.
Use the `brcmfmac-nexmon-dkms` 6.12.2 and `firmware-nexmon` 0.2 archives from
Kali's package pool:

```text
build/cache/brcmfmac-nexmon-6.12.2.tar.xz
build/cache/firmware-nexmon-0.2.tar.xz
```

Compile the driver in separate Alpine 3.21 `linux/arm/v6` and `linux/arm/v7`
containers against `linux-rpi-dev=6.12.13-r0`. Place the results at:

```text
build/brcmfmac-nexmon-dkms-6.12.2/brcmfmac.ko
build/nexmon-armv7/brcmfmac-nexmon-dkms-6.12.2/brcmfmac.ko
```

The image includes the driver and firmware license notices on the boot partition.

### Tests

```sh
python3 -m unittest discover -s tests -p 'test_transport.py'
python3 -m unittest discover -s tests -p 'test_ldn_advertisement.py'
python3 tests/test_ldn_scan.py
```

The scan test uses the native C compiler on Linux and Docker on other platforms. On Linux, compile `tests/ldn_crypto_test.c` with
`-I src -lcrypto`. After generating LDN assets, compile
`tests/ldn_transfer_test.c` with `-DLDN_CRYPTO -Ibuild/ldn -lcrypto`.
Both require OpenSSL development headers.

## Credits

- Gezine: [CivSwitch and PicoSwitch](https://github.com/Gezine/CivSwitch).
- sean: `esp32-ldn-civ7`, the basis for the wireless installer port.
- CivSwitchLDN, Kinnay LDN, and pokeldn: LDN protocol work.
- Nexmon and brcmfmac: Wi-Fi driver and firmware support.

Upstream licenses apply to their respective components. The CivSwitch submodule
is pinned to `59e27b4894e91bc53ece58dd5e9add7335639ef3`.
