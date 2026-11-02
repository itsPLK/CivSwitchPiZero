# CivSwitch - Pi Zero Image

Minimal, instant-boot Raspberry Pi Zero / Zero W / Zero 2 W image based on [`CivSwitch/PicoSwitch`](https://github.com/Gezine/CivSwitch/tree/main/PicoSwitch):
- Uses [`CivSwitch`](https://github.com/Gezine/CivSwitch.git) as a git submodule (`CivSwitch/core.js`, `CivSwitch/PicoSwitch/compress.js`, `CivSwitch/installer-creator/`, `CivSwitch/send_js.py`).
- Uses PicoSwitch’s composite USB HID identity (`0x0F0D:0x0092`, `"PICO SWITCH PRO."` / `"J24 CONTROLLER"`, Interface 0 = Switch USB Gamepad, Interface 1 = Boot Keyboard).
- Runs a single **small static C binary** (`/init`) directly as PID 1 inside a **305 KB `initramf.gz`** — no systemd, no distro userland, no background services, no writable root filesystem.
- Boots in ~2 seconds straight into RAM and unmounts the SD card before typing, so power can be unplugged at any moment without filesystem writes during playback.
- Universal image (`build/civ7-pizero.img`, 40 MB): boots on both **Raspberry Pi Zero / Zero W** (`kernel.img`, ARMv6) and **Raspberry Pi Zero 2 W** (`kernel7.img`, ARMv7 SMP).
- **Live-editable payload & timings**: `payload.txt` and `civswitch.conf` sit directly on the FAT16/FAT32 boot partition (`CIVSWITCH`). You can edit `payload.txt` or tweak timings in `civswitch.conf` from any PC/Mac without rebuilding or reflashing the image.

## Hardware Connection

Use the micro-USB port labeled **`USB`** (the data/OTG port, **not** `PWR IN`) to connect the Raspberry Pi Zero to the Nintendo Switch or Switch Dock.
- Connecting the `USB` port directly to the Switch / Dock provides both 5V power and USB data.
- Alternatively, you can power the Pi Zero via `PWR IN` and connect `USB` to the Switch; `/init` waits for USB enumeration (`configured` state) before starting the macro countdown.

### LED Status (`ACT` LED)
- **3 rapid flashes at ~2s**: `/init` started in RAM.
- **Steady 2 Hz blink (250 ms ON / 250 ms OFF)**: Waiting for USB connection/enumeration with the Switch.
- **Solid ON**: Macro is actively running (~15–20 minutes for the default 87-line loader bootstrap).
- **OFF**: Macro playback finished.
- **Rapid 5 Hz blink**: HID delivery failed; playback stopped. Reconnect to retry.

Playback waits for each USB report transfer before timing its hold. A busy endpoint is retried for up to five seconds; failed transitions stop the macro instead of silently skipping inputs. USB completion does not guarantee the game UI processed the input. `KEY_GAP_MS` applies only to consecutive characters sharing a physical keycode.

The gamepad endpoint supports 64-byte packets; ordinary input reports remain eight bytes. Host reports are consumed without echoing. Each step sends its selected interface once; WAIT releases both. A neutral wait before the first Enter lets the final character settle.

Transport regression checks: `python3 -m unittest discover -s tests`.

## Flashing the Image

Flash `build/civ7-pizero.img` to a microSD card using **Raspberry Pi Imager**, **BalenaEtcher**, or `dd`:

```sh
# Linux / macOS example (replace /dev/sdX or /dev/rdiskX with your SD card device):
sudo dd if=build/civ7-pizero.img of=/dev/rdiskX bs=1m status=progress
```

Alternatively, format any microSD card as **FAT32** (MBR) and copy the contents of `build/boot/` directly to the root of the card.

## Building from Source

```sh
git submodule update --init --recursive
python3 tools/build_image.py
```

Options:
- `python3 tools/build_image.py --payload path/to/custom.js` — stages a custom JS payload using `CivSwitch/PicoSwitch/tools/make_payload.py` + `CivSwitch/PicoSwitch/compress.js` -> `build/payload.txt`, and packs `build/civ7-pizero.img`.

Building and flashing a new image restores the timings in `boot/civswitch.conf`. Reapply any SD-card timing customizations after flashing.

Playback starts two seconds after enumeration and runs once per connection. After completion, the device stays idle; disconnecting USB for more than one second re-arms it. `LANG_JP=0` is the English-console default; set `LANG_JP=1` to switch the Japanese IME using Alt+Space, followed by a 200 ms wait before each line.
