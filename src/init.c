/*
 * CivSwitch Raspberry Pi Zero / Zero W / Zero 2 W Minimal Init
 *
 * Runs directly as PID 1 (/init) inside a tiny initramfs.
 * - Mounts /proc, /sys, /dev, /sys/kernel/config
 * - Loads dwc2 + libcomposite + usb_f_hid kernel modules for the running board
 * - Configures a composite USB HID gadget modeled on PicoSwitch:
 *     VID 0x0F0D, PID 0x0092 ("PICO SWITCH PRO." / "J24 CONTROLLER")
 *     Interface 0: Switch USB Gamepad (8-byte input, 64-byte endpoint, 86-byte descriptor)
 *     Interface 1: Boot-protocol USB Keyboard (8-byte report, 63-byte descriptor)
 * - Reads payload.txt (and optional civswitch.conf) from the FAT32 SD card
 *   partition (/dev/mmcblk0p1), falling back to /payload.txt in initramfs,
 *   then unmounts the SD card so power can be removed at any time safely.
 * - Executes the CivSwitch chat-XSS macro with hardware-tested timings while
 *   lighting the onboard ACT LED.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <poll.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#endif

/* --- Pico-based macro timings; LANG_JP defaults off for English consoles. --- */
static uint32_t cfg_macro_start_delay_ms = 2000;
static uint32_t cfg_key_hold_ms          = 32;
static uint32_t cfg_key_gap_ms           = 32;
static uint32_t cfg_enter_hold_ms        = 32;
static uint32_t cfg_enter_gap_ms         = 200;
static uint32_t cfg_pre_a_wait_ms        = 750;
static uint32_t cfg_post_a_wait_ms       = 550;
static uint32_t cfg_a_press_ms           = 50;
static uint32_t cfg_preamble_a_count     = 5;
static uint32_t cfg_preamble_gap_ms      = 550;
static uint32_t cfg_esc_to_a_wait_ms     = 750;
static uint32_t cfg_lang_jp = 0;

/* --- Switch USB Gamepad & Keyboard HID structs (identical to SwitchConsts.h) --- */
typedef struct __attribute__((packed)) {
    uint16_t buttons;
    uint8_t  hat;
    uint8_t  lx;
    uint8_t  ly;
    uint8_t  rx;
    uint8_t  ry;
    uint8_t  vendor;
} SwitchUsbReport;

typedef struct __attribute__((packed)) {
    uint8_t modifier;
    uint8_t reserved;
    uint8_t keycode[6];
} KeyboardReport;

#define SWITCH_USB_HAT_NOTHING  0x08
#define SWITCH_USB_JOYSTICK_MID 0x80
#define SWITCH_USB_MASK_A       (1U << 2)

#define KEYBOARD_MODIFIER_LEFTSHIFT (1U << 1)
#define KEYBOARD_LED_CAPSLOCK       (1U << 1)

/* USB HID Usage Page 0x07 keycodes */
#define HID_KEY_NONE          0x00
#define HID_KEY_A             0x04
#define HID_KEY_1             0x1E
#define HID_KEY_2             0x1F
#define HID_KEY_3             0x20
#define HID_KEY_4             0x21
#define HID_KEY_5             0x22
#define HID_KEY_6             0x23
#define HID_KEY_7             0x24
#define HID_KEY_8             0x25
#define HID_KEY_9             0x26
#define HID_KEY_0             0x27
#define HID_KEY_ENTER         0x28
#define HID_KEY_ESCAPE        0x29
#define HID_KEY_TAB           0x2B
#define HID_KEY_SPACE         0x2C
#define HID_KEY_MINUS         0x2D
#define HID_KEY_EQUAL         0x2E
#define HID_KEY_BRACKET_LEFT  0x2F
#define HID_KEY_BRACKET_RIGHT 0x30
#define HID_KEY_BACKSLASH     0x31
#define HID_KEY_SEMICOLON     0x33
#define HID_KEY_APOSTROPHE    0x34
#define HID_KEY_GRAVE         0x35
#define HID_KEY_COMMA         0x36
#define HID_KEY_PERIOD        0x37
#define HID_KEY_SLASH         0x38

/* Exact 86-byte Switch gamepad HID report descriptor from SwitchConsts.h */
static const uint8_t switch_usb_report_descriptor[86] = {
    0x05, 0x01,        /* Usage Page (Generic Desktop Ctrls) */
    0x09, 0x05,        /* Usage (Game Pad) */
    0xA1, 0x01,        /* Collection (Application) */
    0x15, 0x00,        /*   Logical Minimum (0) */
    0x25, 0x01,        /*   Logical Maximum (1) */
    0x35, 0x00,        /*   Physical Minimum (0) */
    0x45, 0x01,        /*   Physical Maximum (1) */
    0x75, 0x01,        /*   Report Size (1) */
    0x95, 0x10,        /*   Report Count (16) */
    0x05, 0x09,        /*   Usage Page (Button) */
    0x19, 0x01,        /*   Usage Minimum (0x01) */
    0x29, 0x10,        /*   Usage Maximum (0x10) */
    0x81, 0x02,        /*   Input (Data,Var,Abs) */
    0x05, 0x01,        /*   Usage Page (Generic Desktop Ctrls) */
    0x25, 0x07,        /*   Logical Maximum (7) */
    0x46, 0x3B, 0x01,  /*   Physical Maximum (315) */
    0x75, 0x04,        /*   Report Size (4) */
    0x95, 0x01,        /*   Report Count (1) */
    0x65, 0x14,        /*   Unit (English Rotation) */
    0x09, 0x39,        /*   Usage (Hat switch) */
    0x81, 0x42,        /*   Input (Data,Var,Abs,Null State) */
    0x65, 0x00,        /*   Unit (None) */
    0x95, 0x01,        /*   Report Count (1) */
    0x81, 0x01,        /*   Input (Const,Array,Abs) */
    0x26, 0xFF, 0x00,  /*   Logical Maximum (255) */
    0x46, 0xFF, 0x00,  /*   Physical Maximum (255) */
    0x09, 0x30,        /*   Usage (X) */
    0x09, 0x31,        /*   Usage (Y) */
    0x09, 0x32,        /*   Usage (Z) */
    0x09, 0x35,        /*   Usage (Rz) */
    0x75, 0x08,        /*   Report Size (8) */
    0x95, 0x04,        /*   Report Count (4) */
    0x81, 0x02,        /*   Input (Data,Var,Abs) */
    0x06, 0x00, 0xFF,  /*   Usage Page (Vendor Defined 0xFF00) */
    0x09, 0x20,        /*   Usage (0x20) */
    0x95, 0x01,        /*   Report Count (1) */
    0x81, 0x02,        /*   Input (Data,Var,Abs) */
    0x0A, 0x21, 0x26,  /*   Usage (0x2621) */
    0x95, 0x08,        /*   Report Count (8) */
    0x91, 0x02,        /*   Output (Data,Var,Abs,Non-volatile) */
    0xC0               /* End Collection */
};

/* Exact 63-byte boot keyboard HID report descriptor from SwitchConsts.h */
static const uint8_t keyboard_usb_report_descriptor[63] = {
    0x05, 0x01,  /* Usage Page (Generic Desktop Ctrls) */
    0x09, 0x06,  /* Usage (Keyboard) */
    0xA1, 0x01,  /* Collection (Application) */
    0x75, 0x01,  /*   Report Size (1) */
    0x95, 0x08,  /*   Report Count (8) */
    0x05, 0x07,  /*   Usage Page (Kbrd/Keypad) */
    0x19, 0xE0,  /*   Usage Minimum (0xE0) */
    0x29, 0xE7,  /*   Usage Maximum (0xE7) */
    0x15, 0x00,  /*   Logical Minimum (0) */
    0x25, 0x01,  /*   Logical Maximum (1) */
    0x81, 0x02,  /*   Input (Data,Var,Abs) ; modifier byte */
    0x95, 0x01,  /*   Report Count (1) */
    0x75, 0x08,  /*   Report Size (8) */
    0x81, 0x01,  /*   Input (Const,Array,Abs) ; reserved byte */
    0x95, 0x05,  /*   Report Count (5) */
    0x75, 0x01,  /*   Report Size (1) */
    0x05, 0x08,  /*   Usage Page (LEDs) */
    0x19, 0x01,  /*   Usage Minimum (Num Lock) */
    0x29, 0x05,  /*   Usage Maximum (Kana) */
    0x91, 0x02,  /*   Output (Data,Var,Abs) ; LED report */
    0x95, 0x01,  /*   Report Count (1) */
    0x75, 0x03,  /*   Report Size (3) */
    0x91, 0x01,  /*   Output (Const,Array,Abs) ; LED padding */
    0x95, 0x06,  /*   Report Count (6) */
    0x75, 0x08,  /*   Report Size (8) */
    0x15, 0x00,  /*   Logical Minimum (0) */
    0x25, 0x65,  /*   Logical Maximum (101) */
    0x05, 0x07,  /*   Usage Page (Kbrd/Keypad) */
    0x19, 0x00,  /*   Usage Minimum (0x00) */
    0x29, 0x65,  /*   Usage Maximum (0x65) */
    0x81, 0x00,  /*   Input (Data,Array,Abs) ; 6 keycode bytes */
    0xC0         /* End Collection */
};

/* --- Macro Step Engine (matches MacroEngine.h) --- */
typedef enum {
    MACRO_OP_WAIT = 0,
    MACRO_OP_KEYS,
    MACRO_OP_PAD,
    MACRO_OP_BOTH,
    MACRO_OP_END
} MacroOp;

typedef struct {
    MacroOp         op;
    uint32_t        durationMs;
    KeyboardReport  keyboard;
    SwitchUsbReport gamepad;
    const char     *key_name; /* used for --verify-macro output */
} MacroStep;

typedef struct {
    bool        valid;
    uint8_t     shift;
    uint8_t     keycode;
    const char *name;
} AsciiKeyEntry;

static AsciiKeyEntry ascii_map[128];

static void init_ascii_map(void) {
    memset(ascii_map, 0, sizeof(ascii_map));
    ascii_map[' ']  = (AsciiKeyEntry){true, 0, HID_KEY_SPACE, "HID_KEY_SPACE"};
    ascii_map['\t'] = (AsciiKeyEntry){true, 0, HID_KEY_TAB,   "HID_KEY_TAB"};

    static const char *letter_names[26] = {
        "HID_KEY_A", "HID_KEY_B", "HID_KEY_C", "HID_KEY_D", "HID_KEY_E",
        "HID_KEY_F", "HID_KEY_G", "HID_KEY_H", "HID_KEY_I", "HID_KEY_J",
        "HID_KEY_K", "HID_KEY_L", "HID_KEY_M", "HID_KEY_N", "HID_KEY_O",
        "HID_KEY_P", "HID_KEY_Q", "HID_KEY_R", "HID_KEY_S", "HID_KEY_T",
        "HID_KEY_U", "HID_KEY_V", "HID_KEY_W", "HID_KEY_X", "HID_KEY_Y",
        "HID_KEY_Z"
    };
    for (int i = 0; i < 26; i++) {
        uint8_t kc = (uint8_t)(HID_KEY_A + i);
        ascii_map['a' + i] = (AsciiKeyEntry){true, 0, kc, letter_names[i]};
        ascii_map['A' + i] = (AsciiKeyEntry){true, 1, kc, letter_names[i]};
    }

    static const char *digit_names[10] = {
        "HID_KEY_0", "HID_KEY_1", "HID_KEY_2", "HID_KEY_3", "HID_KEY_4",
        "HID_KEY_5", "HID_KEY_6", "HID_KEY_7", "HID_KEY_8", "HID_KEY_9"
    };
    ascii_map['0'] = (AsciiKeyEntry){true, 0, HID_KEY_0, digit_names[0]};
    for (int i = 1; i <= 9; i++) {
        ascii_map['0' + i] = (AsciiKeyEntry){true, 0, (uint8_t)(HID_KEY_1 + (i - 1)), digit_names[i]};
    }

    ascii_map['!'] = (AsciiKeyEntry){true, 1, HID_KEY_1,             "HID_KEY_1"};
    ascii_map['@'] = (AsciiKeyEntry){true, 1, HID_KEY_2,             "HID_KEY_2"};
    ascii_map['#'] = (AsciiKeyEntry){true, 1, HID_KEY_3,             "HID_KEY_3"};
    ascii_map['$'] = (AsciiKeyEntry){true, 1, HID_KEY_4,             "HID_KEY_4"};
    ascii_map['%'] = (AsciiKeyEntry){true, 1, HID_KEY_5,             "HID_KEY_5"};
    ascii_map['^'] = (AsciiKeyEntry){true, 1, HID_KEY_6,             "HID_KEY_6"};
    ascii_map['&'] = (AsciiKeyEntry){true, 1, HID_KEY_7,             "HID_KEY_7"};
    ascii_map['*'] = (AsciiKeyEntry){true, 1, HID_KEY_8,             "HID_KEY_8"};
    ascii_map['('] = (AsciiKeyEntry){true, 1, HID_KEY_9,             "HID_KEY_9"};
    ascii_map[')'] = (AsciiKeyEntry){true, 1, HID_KEY_0,             "HID_KEY_0"};
    ascii_map['-'] = (AsciiKeyEntry){true, 0, HID_KEY_MINUS,         "HID_KEY_MINUS"};
    ascii_map['_'] = (AsciiKeyEntry){true, 1, HID_KEY_MINUS,         "HID_KEY_MINUS"};
    ascii_map['='] = (AsciiKeyEntry){true, 0, HID_KEY_EQUAL,         "HID_KEY_EQUAL"};
    ascii_map['+'] = (AsciiKeyEntry){true, 1, HID_KEY_EQUAL,         "HID_KEY_EQUAL"};
    ascii_map['['] = (AsciiKeyEntry){true, 0, HID_KEY_BRACKET_LEFT,  "HID_KEY_BRACKET_LEFT"};
    ascii_map['{'] = (AsciiKeyEntry){true, 1, HID_KEY_BRACKET_LEFT,  "HID_KEY_BRACKET_LEFT"};
    ascii_map[']'] = (AsciiKeyEntry){true, 0, HID_KEY_BRACKET_RIGHT, "HID_KEY_BRACKET_RIGHT"};
    ascii_map['}'] = (AsciiKeyEntry){true, 1, HID_KEY_BRACKET_RIGHT, "HID_KEY_BRACKET_RIGHT"};
    ascii_map['\\']= (AsciiKeyEntry){true, 0, HID_KEY_BACKSLASH,     "HID_KEY_BACKSLASH"};
    ascii_map['|'] = (AsciiKeyEntry){true, 1, HID_KEY_BACKSLASH,     "HID_KEY_BACKSLASH"};
    ascii_map[';'] = (AsciiKeyEntry){true, 0, HID_KEY_SEMICOLON,     "HID_KEY_SEMICOLON"};
    ascii_map[':'] = (AsciiKeyEntry){true, 1, HID_KEY_SEMICOLON,     "HID_KEY_SEMICOLON"};
    ascii_map['\'']= (AsciiKeyEntry){true, 0, HID_KEY_APOSTROPHE,    "HID_KEY_APOSTROPHE"};
    ascii_map['"'] = (AsciiKeyEntry){true, 1, HID_KEY_APOSTROPHE,    "HID_KEY_APOSTROPHE"};
    ascii_map['`'] = (AsciiKeyEntry){true, 0, HID_KEY_GRAVE,         "HID_KEY_GRAVE"};
    ascii_map['~'] = (AsciiKeyEntry){true, 1, HID_KEY_GRAVE,         "HID_KEY_GRAVE"};
    ascii_map[','] = (AsciiKeyEntry){true, 0, HID_KEY_COMMA,         "HID_KEY_COMMA"};
    ascii_map['<'] = (AsciiKeyEntry){true, 1, HID_KEY_COMMA,         "HID_KEY_COMMA"};
    ascii_map['.'] = (AsciiKeyEntry){true, 0, HID_KEY_PERIOD,        "HID_KEY_PERIOD"};
    ascii_map['>'] = (AsciiKeyEntry){true, 1, HID_KEY_PERIOD,        "HID_KEY_PERIOD"};
    ascii_map['/'] = (AsciiKeyEntry){true, 0, HID_KEY_SLASH,         "HID_KEY_SLASH"};
    ascii_map['?'] = (AsciiKeyEntry){true, 1, HID_KEY_SLASH,         "HID_KEY_SLASH"};
}

static SwitchUsbReport make_neutral_pad(void) {
    SwitchUsbReport pad = {
        .buttons = 0,
        .hat     = SWITCH_USB_HAT_NOTHING,
        .lx      = SWITCH_USB_JOYSTICK_MID,
        .ly      = SWITCH_USB_JOYSTICK_MID,
        .rx      = SWITCH_USB_JOYSTICK_MID,
        .ry      = SWITCH_USB_JOYSTICK_MID,
        .vendor  = 0
    };
    return pad;
}

static KeyboardReport make_neutral_kbd(void) {
    KeyboardReport kbd = {0, 0, {0, 0, 0, 0, 0, 0}};
    return kbd;
}

typedef struct {
    MacroStep *items;
    size_t     count;
    size_t     cap;
} StepList;

static void push_step(StepList *list, MacroStep step) {
    if (list->count == list->cap) {
        size_t new_cap = list->cap ? list->cap * 2 : 4096;
        MacroStep *n = realloc(list->items, new_cap * sizeof(MacroStep));
        if (!n) abort();
        list->items = n;
        list->cap   = new_cap;
    }
    list->items[list->count++] = step;
}

static void push_wait(StepList *list, uint32_t ms) {
    push_step(list, (MacroStep){
        .op         = MACRO_OP_WAIT,
        .durationMs = ms,
        .keyboard   = make_neutral_kbd(),
        .gamepad    = make_neutral_pad(),
        .key_name   = NULL
    });
}

static void push_pad_btn(StepList *list, uint32_t ms, uint16_t buttons) {
    SwitchUsbReport pad = make_neutral_pad();
    pad.buttons = buttons;
    push_step(list, (MacroStep){
        .op         = MACRO_OP_PAD,
        .durationMs = ms,
        .keyboard   = make_neutral_kbd(),
        .gamepad    = pad,
        .key_name   = NULL
    });
}

static void push_key(StepList *list, uint32_t ms, uint8_t shift, uint8_t keycode, const char *name) {
    KeyboardReport kbd = make_neutral_kbd();
    kbd.modifier   = shift ? KEYBOARD_MODIFIER_LEFTSHIFT : 0;
    kbd.keycode[0] = keycode;
    push_step(list, (MacroStep){
        .op         = MACRO_OP_KEYS,
        .durationMs = ms,
        .keyboard   = kbd,
        .gamepad    = make_neutral_pad(),
        .key_name   = name
    });
}

static bool build_macro_from_payload(const char *payload_path, StepList *out, size_t *out_batches) {
    FILE *f = fopen(payload_path, "rb");
    if (!f) return false;

    char **lines = NULL;
    size_t num_lines = 0, cap_lines = 0;
    char buf[2048];

    while (fgets(buf, sizeof(buf), f)) {
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
            buf[--len] = '\0';
        }
        bool non_ws = false;
        for (size_t i = 0; i < len; i++) {
            if (!isspace((unsigned char)buf[i])) {
                non_ws = true;
                break;
            }
        }
        if (!non_ws) continue;

        char filtered[2048];
        size_t flen = 0;
        for (size_t i = 0; i < len; i++) {
            unsigned char c = (unsigned char)buf[i];
            if (c < 128 && ascii_map[c].valid) {
                filtered[flen++] = (char)c;
            }
        }
        filtered[flen] = '\0';
        if (flen == 0) continue;

        if (num_lines == cap_lines) {
            cap_lines = cap_lines ? cap_lines * 2 : 128;
            lines = realloc(lines, cap_lines * sizeof(char *));
        }
        lines[num_lines++] = strdup(filtered);
    }
    fclose(f);

    if (num_lines == 0) {
        free(lines);
        return false;
    }

    /* Preamble: press A 5 times */
    for (uint32_t i = 0; i < cfg_preamble_a_count; i++) {
        push_pad_btn(out, cfg_a_press_ms, SWITCH_USB_MASK_A);
        push_wait(out, cfg_preamble_gap_ms);
    }

    for (size_t i = 0; i < num_lines; i++) {
        const char *line = lines[i];

        /* Press Esc, wait, press gamepad A, wait */
        push_key(out, cfg_key_hold_ms, 0, HID_KEY_ESCAPE, "HID_KEY_ESCAPE");
        push_wait(out, cfg_esc_to_a_wait_ms);
        push_pad_btn(out, cfg_a_press_ms, SWITCH_USB_MASK_A);
        push_wait(out, cfg_post_a_wait_ms);

        if (cfg_lang_jp) {
            push_key(out, 32, 0, HID_KEY_SPACE, "HID_KEY_SPACE");
            out->items[out->count - 1].keyboard.modifier = 0x04; /* Left Alt */
            push_wait(out, 200);
        }

        /* Type line: one new key per report, release only on consecutive identical key */
        uint8_t prev_keycode = 0;
        for (size_t j = 0; line[j] != '\0'; j++) {
            unsigned char c = (unsigned char)line[j];
            AsciiKeyEntry e = ascii_map[c];
            if (prev_keycode != 0 && e.keycode == prev_keycode) {
                push_wait(out, cfg_key_gap_ms);
            }
            push_key(out, cfg_key_hold_ms, e.shift, e.keycode, e.name);
            prev_keycode = e.keycode;
        }

        /* Release the final character and allow input to settle before submitting. */
        push_wait(out, cfg_enter_gap_ms);
        /* Press Enter twice */
        push_key(out, cfg_enter_hold_ms, 0, HID_KEY_ENTER, "HID_KEY_ENTER");
        push_wait(out, cfg_enter_gap_ms);
        push_key(out, cfg_enter_hold_ms, 0, HID_KEY_ENTER, "HID_KEY_ENTER");

        /* Separator between batches */
        if (i + 1 < num_lines) {
            push_wait(out, cfg_pre_a_wait_ms);
            push_pad_btn(out, cfg_a_press_ms, SWITCH_USB_MASK_A);
            push_wait(out, cfg_post_a_wait_ms);
        }
        free(lines[i]);
    }
    free(lines);

    push_step(out, (MacroStep){
        .op         = MACRO_OP_END,
        .durationMs = 0,
        .keyboard   = make_neutral_kbd(),
        .gamepad    = make_neutral_pad(),
        .key_name   = NULL
    });

    if (out_batches) *out_batches = num_lines;
    return true;
}

static void dump_steps_for_verification(const StepList *list) {
    for (size_t i = 0; i < list->count; i++) {
        const MacroStep *s = &list->items[i];
        switch (s->op) {
            case MACRO_OP_WAIT:
                printf("    WAIT(%u),\n", s->durationMs);
                break;
            case MACRO_OP_PAD:
                printf("    PAD_BTN(%u, SWITCH_USB_MASK_A),\n", s->durationMs);
                break;
            case MACRO_OP_KEYS:
                printf("    KEYS(%u, %s, %s, 0, 0, 0, 0, 0),\n",
                       s->durationMs,
                       s->keyboard.modifier ? "KEYBOARD_MODIFIER_LEFTSHIFT" : "0",
                       s->key_name ? s->key_name : "0");
                break;
            case MACRO_OP_END:
                printf("    END(),\n");
                break;
            default:
                break;
        }
    }
}

#ifdef __linux__

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static void sleep_us(uint32_t us) {
    struct timespec ts = {
        .tv_sec  = us / 1000000U,
        .tv_nsec = (long)(us % 1000000U) * 1000L
    };
    nanosleep(&ts, NULL);
}

static void sleep_ms(uint32_t ms) {
    sleep_us(ms * 1000U);
}

static bool write_file_bytes(const char *path, const void *data, size_t len) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) return false;
    const uint8_t *p = (const uint8_t *)data;
    size_t rem = len;
    while (rem > 0) {
        ssize_t w = write(fd, p, rem);
        if (w <= 0) {
            close(fd);
            return false;
        }
        p   += w;
        rem -= (size_t)w;
    }
    close(fd);
    return true;
}

static bool write_file_str(const char *path, const char *str) {
    return write_file_bytes(path, str, strlen(str));
}

/* --- Onboard LED control --- */
static char led_brightness_path[256] = {0};

static void led_init(void) {
    const char *candidates[] = {
        "/sys/class/leds/ACT",
        "/sys/class/leds/led0",
        NULL
    };
    const char *chosen = NULL;
    for (int i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0) {
            chosen = candidates[i];
            break;
        }
    }
    if (!chosen) {
        DIR *d = opendir("/sys/class/leds");
        if (d) {
            struct dirent *de;
            static char dynamic_led[256];
            while ((de = readdir(d)) != NULL) {
                if (de->d_name[0] != '.') {
                    snprintf(dynamic_led, sizeof(dynamic_led), "/sys/class/leds/%s", de->d_name);
                    chosen = dynamic_led;
                    break;
                }
            }
            closedir(d);
        }
    }
    if (!chosen) return;

    char trigger_path[256];
    snprintf(trigger_path, sizeof(trigger_path), "%s/trigger", chosen);
    write_file_str(trigger_path, "none\n");
    snprintf(led_brightness_path, sizeof(led_brightness_path), "%s/brightness", chosen);

    /* Immediate startup blink (3 quick flashes) so boot into /init is visually obvious */
    for (int i = 0; i < 3; i++) {
        write_file_str(led_brightness_path, "255\n");
        sleep_ms(100);
        write_file_str(led_brightness_path, "0\n");
        sleep_ms(100);
    }
}

static void led_set(bool on) {
    if (led_brightness_path[0] == '\0') return;
    write_file_str(led_brightness_path, on ? "255\n" : "0\n");
}

/* --- Kernel module loading --- */
static bool load_single_ko(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        close(fd);
        return false;
    }
    void *buf = malloc((size_t)st.st_size);
    if (!buf) {
        close(fd);
        return false;
    }
    size_t off = 0;
    while (off < (size_t)st.st_size) {
        ssize_t r = read(fd, (uint8_t *)buf + off, (size_t)st.st_size - off);
        if (r <= 0) break;
        off += (size_t)r;
    }
    close(fd);
    if (off != (size_t)st.st_size) {
        free(buf);
        return false;
    }
    long ret = syscall(SYS_init_module, buf, (unsigned long)st.st_size, "");
    int err = errno;
    free(buf);
    if (ret == 0 || err == EEXIST) {
        return true;
    }
    return false;
}

static void load_usb_modules(void) {
    struct utsname uts;
    const char *primary_arch = "armv6l";
    if (uname(&uts) == 0 && strncmp(uts.machine, "armv7", 5) == 0) {
        primary_arch = "armv7l";
    }
    const char *alt_arch = (strcmp(primary_arch, "armv6l") == 0) ? "armv7l" : "armv6l";
    const char *mods[] = {"roles.ko", "dwc2.ko", "libcomposite.ko", "usb_f_hid.ko", NULL};

    for (int i = 0; mods[i]; i++) {
        char path[256];
        snprintf(path, sizeof(path), "/modules/%s/%s", primary_arch, mods[i]);
        if (load_single_ko(path)) {
            continue;
        }
        snprintf(path, sizeof(path), "/modules/%s/%s", alt_arch, mods[i]);
        (void)load_single_ko(path);
    }
}

/* --- ConfigFS Composite USB HID Gadget setup --- */
static bool find_udc_name(char *out_name, size_t max_len) {
    for (int attempt = 0; attempt < 40; attempt++) {
        DIR *d = opendir("/sys/class/udc");
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (de->d_name[0] != '.') {
                    snprintf(out_name, max_len, "%s", de->d_name);
                    closedir(d);
                    return true;
                }
            }
            closedir(d);
        }
        led_set((attempt % 4) < 2);
        sleep_ms(50);
    }
    return false;
}

static bool setup_usb_gadget(char *udc_name, size_t udc_max) {
    const char *g = "/sys/kernel/config/usb_gadget/g1";
    mkdir(g, 0755);

    write_file_str("/sys/kernel/config/usb_gadget/g1/bcdUSB",          "0x0200\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/bDeviceClass",    "0x00\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/bDeviceSubClass", "0x00\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/bDeviceProtocol", "0x00\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/bMaxPacketSize0", "0x40\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/idVendor",        "0x0f0d\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/idProduct",       "0x0092\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/bcdDevice",       "0x0100\n");

    mkdir("/sys/kernel/config/usb_gadget/g1/strings/0x409", 0755);
    write_file_str("/sys/kernel/config/usb_gadget/g1/strings/0x409/manufacturer", "PICO SWITCH PRO.\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/strings/0x409/product",      "J24 CONTROLLER\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/strings/0x409/serialnumber", "1.0\n");

    mkdir("/sys/kernel/config/usb_gadget/g1/configs/c.1", 0755);
    write_file_str("/sys/kernel/config/usb_gadget/g1/configs/c.1/MaxPower",     "500\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/configs/c.1/bmAttributes", "0x80\n");
    mkdir("/sys/kernel/config/usb_gadget/g1/configs/c.1/strings/0x409", 0755);
    write_file_str("/sys/kernel/config/usb_gadget/g1/configs/c.1/strings/0x409/configuration", "Switch Controller\n");

    /* Interface 0: Switch USB Gamepad */
    mkdir("/sys/kernel/config/usb_gadget/g1/functions/hid.usb0", 0755);
    write_file_str("/sys/kernel/config/usb_gadget/g1/functions/hid.usb0/protocol",        "0\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/functions/hid.usb0/subclass",        "0\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/functions/hid.usb0/report_length",   "64\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/functions/hid.usb0/no_out_endpoint", "0\n");
    write_file_bytes("/sys/kernel/config/usb_gadget/g1/functions/hid.usb0/report_desc",
                     switch_usb_report_descriptor, sizeof(switch_usb_report_descriptor));
    symlink("/sys/kernel/config/usb_gadget/g1/functions/hid.usb0",
            "/sys/kernel/config/usb_gadget/g1/configs/c.1/hid.usb0");

    /* Interface 1: Boot-protocol USB Keyboard */
    mkdir("/sys/kernel/config/usb_gadget/g1/functions/hid.usb1", 0755);
    write_file_str("/sys/kernel/config/usb_gadget/g1/functions/hid.usb1/protocol",        "1\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/functions/hid.usb1/subclass",        "1\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/functions/hid.usb1/report_length",   "8\n");
    write_file_str("/sys/kernel/config/usb_gadget/g1/functions/hid.usb1/no_out_endpoint", "0\n");
    write_file_bytes("/sys/kernel/config/usb_gadget/g1/functions/hid.usb1/report_desc",
                     keyboard_usb_report_descriptor, sizeof(keyboard_usb_report_descriptor));
    symlink("/sys/kernel/config/usb_gadget/g1/functions/hid.usb1",
            "/sys/kernel/config/usb_gadget/g1/configs/c.1/hid.usb1");

    if (!find_udc_name(udc_name, udc_max)) {
        return false;
    }

    char udc_buf[128];
    snprintf(udc_buf, sizeof(udc_buf), "%s\n", udc_name);
    if (!write_file_str("/sys/kernel/config/usb_gadget/g1/UDC", udc_buf)) {
        return false;
    }
    return true;
}

static int open_dev_node(const char *dev_path, const char *sys_dev_path, bool is_block, int flags) {
    for (int tries = 0; tries < 40; tries++) {
        int fd = open(dev_path, flags);
        if (fd >= 0) return fd;

        int sfd = open(sys_dev_path, O_RDONLY);
        if (sfd >= 0) {
            char buf[64] = {0};
            if (read(sfd, buf, sizeof(buf) - 1) > 0) {
                unsigned int maj = 0, min = 0;
                if (sscanf(buf, "%u:%u", &maj, &min) == 2) {
                    mknod(dev_path, (is_block ? S_IFBLK : S_IFCHR) | 0600, makedev(maj, min));
                }
            }
            close(sfd);
            fd = open(dev_path, flags);
            if (fd >= 0) return fd;
        }
        sleep_ms(25);
    }
    return -1;
}

static void load_optional_config(const char *conf_path) {
    FILE *f = fopen(conf_path, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = line;
        char *v = eq + 1;
        while (*k && isspace((unsigned char)*k)) k++;
        char *kend = k + strlen(k);
        while (kend > k && isspace((unsigned char)kend[-1])) *--kend = '\0';
        if (k[0] == '#' || k[0] == '\0') continue;
        uint32_t val = (uint32_t)strtoul(v, NULL, 10);
        if (strcmp(k, "LANG_JP") == 0) cfg_lang_jp = val != 0;
        else if (strcmp(k, "MACRO_START_DELAY_MS") == 0) cfg_macro_start_delay_ms = val;
        else if (strcmp(k, "KEY_HOLD_MS") == 0)      cfg_key_hold_ms          = val;
        else if (strcmp(k, "KEY_GAP_MS") == 0)       cfg_key_gap_ms           = val;
        else if (strcmp(k, "ENTER_HOLD_MS") == 0)    cfg_enter_hold_ms        = val;
        else if (strcmp(k, "ENTER_GAP_MS") == 0)     cfg_enter_gap_ms         = val;
        else if (strcmp(k, "PRE_A_WAIT_MS") == 0)    cfg_pre_a_wait_ms        = val;
        else if (strcmp(k, "POST_A_WAIT_MS") == 0)   cfg_post_a_wait_ms       = val;
        else if (strcmp(k, "A_PRESS_MS") == 0)       cfg_a_press_ms           = val;
        else if (strcmp(k, "PREAMBLE_A_COUNT") == 0) cfg_preamble_a_count     = val;
        else if (strcmp(k, "PREAMBLE_GAP_MS") == 0)  cfg_preamble_gap_ms      = val;
        else if (strcmp(k, "ESC_TO_A_WAIT_MS") == 0) cfg_esc_to_a_wait_ms     = val;
    }
    fclose(f);
}

static bool is_udc_configured(const char *udc_name) {
    if (!udc_name || udc_name[0] == '\0') return false;
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/udc/%s/state", udc_name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    char buf[64] = {0};
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) return false;
    return strncmp(buf, "configured", 10) == 0;
}

static void drain_hid_out_reports(int fd_pad, int fd_kbd) {
    uint8_t buf[64];
    /* Consume gamepad host reports without echoing. Bound draining per call. */
    for (int i = 0; i < 16; i++) {
        if (read(fd_pad, buf, sizeof(buf)) <= 0) break;
    }
    /* Keyboard OUT reports are LED state, not data to echo. */
    for (int i = 0; i < 16; i++) {
        if (read(fd_kbd, buf, sizeof(buf)) <= 0) break;
    }
}

static bool wait_report_ready(int fd, int fd_pad, int fd_kbd, uint64_t deadline) {
    while (now_ms() < deadline) {
        drain_hid_out_reports(fd_pad, fd_kbd);
        struct pollfd p = {.fd = fd, .events = POLLOUT};
        int result = poll(&p, 1, 10);
        if (result < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            errno = EIO;
            return false;
        }
        if (p.revents & POLLOUT) return true;
    }
    errno = ETIMEDOUT;
    return false;
}

static bool write_report_reliable(int fd, const void *report, size_t len, int fd_pad, int fd_kbd) {
    uint64_t deadline = now_ms() + 5000;
    for (;;) {
        if (!wait_report_ready(fd, fd_pad, fd_kbd, deadline)) return false;
        ssize_t w = write(fd, report, len);
        if (w == (ssize_t)len) {
            /* f_hid clears write_pending on completion. POLLOUT after write
             * waits for that transfer before timing a hold.
             * This is USB completion, not acknowledgement by the game UI. */
            return wait_report_ready(fd, fd_pad, fd_kbd, deadline);
        }
        if (w >= 0) { errno = EIO; return false; }
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return false;
    }
}

#endif /* __linux__ */

int main(int argc, char **argv) {
    init_ascii_map();

    /* Host verification helper: ./init --verify-macro <payload.txt> */
    if (argc == 3 && strcmp(argv[1], "--verify-macro") == 0) {
        (void)cfg_macro_start_delay_ms;
        (void)switch_usb_report_descriptor;
        (void)keyboard_usb_report_descriptor;
        StepList steps = {0};
        size_t batches = 0;
        if (!build_macro_from_payload(argv[2], &steps, &batches)) {
            fprintf(stderr, "Failed to parse %s\n", argv[2]);
            return 1;
        }
        dump_steps_for_verification(&steps);
        free(steps.items);
        return 0;
    }

#ifdef __linux__
    mkdir("/proc", 0755);
    mkdir("/sys", 0755);
    mkdir("/dev", 0755);
    mkdir("/boot", 0755);

    mount("proc",     "/proc",              "proc",     0, NULL);
    mount("sysfs",    "/sys",               "sysfs",    0, NULL);
    mount("devtmpfs", "/dev",               "devtmpfs", 0, NULL);
    mkdir("/sys/kernel/config", 0755);
    mount("configfs", "/sys/kernel/config", "configfs", 0, NULL);


    led_init();
    load_usb_modules();

    char udc_name[128] = {0};
    if (!setup_usb_gadget(udc_name, sizeof(udc_name))) {
        for (;;) { led_set(true); sleep_ms(100); led_set(false); sleep_ms(100); }
    }

    int fd_pad = open_dev_node("/dev/hidg0", "/sys/class/hidg/hidg0/dev", false, O_RDWR | O_NONBLOCK);
    int fd_kbd = open_dev_node("/dev/hidg1", "/sys/class/hidg/hidg1/dev", false, O_RDWR | O_NONBLOCK);
    if (fd_pad < 0 || fd_kbd < 0) {
        for (;;) { led_set(true); sleep_ms(100); led_set(false); sleep_ms(100); }
    }

    /* Try mounting FAT32 boot partition read-only to check for user-edited payload.txt */
    bool boot_mounted = false;
    int blk_fd = open_dev_node("/dev/mmcblk0p1", "/sys/class/block/mmcblk0p1/dev", true, O_RDONLY);
    if (blk_fd >= 0) {
        close(blk_fd);
        if (mount("/dev/mmcblk0p1", "/boot", "vfat", MS_RDONLY | MS_NOATIME, "iocharset=ascii") == 0 ||
            mount("/dev/mmcblk0p1", "/boot", "vfat", MS_RDONLY | MS_NOATIME, NULL) == 0) {
            boot_mounted = true;
            load_optional_config("/boot/civswitch.conf");
        }
    }

    StepList steps = {0};
    size_t batches = 0;
    bool payload_ok = boot_mounted && build_macro_from_payload("/boot/payload.txt", &steps, &batches);
    if (!payload_ok) payload_ok = build_macro_from_payload("/payload.txt", &steps, &batches);

    if (boot_mounted) {
        umount("/boot");
    }

    if (!payload_ok) {
        for (;;) { led_set(true); sleep_ms(100); led_set(false); sleep_ms(100); }
    }

    SwitchUsbReport neutral_pad = make_neutral_pad();
    KeyboardReport  neutral_kbd = make_neutral_kbd();

    while (1) {
        /* 1. Wait until USB gadget is enumerated ("configured") by the Switch */
        while (!is_udc_configured(udc_name)) {
            uint64_t t = now_ms();
            led_set((t % 500ULL) < 250ULL); /* 2 Hz 50% duty blink while waiting for console */
            drain_hid_out_reports(fd_pad, fd_kbd);
            sleep_ms(20);
        }

        /* 2. Armed: hold neutral outputs for MACRO_START_DELAY_MS */
        led_set(false);
        uint64_t arm_end = now_ms() + cfg_macro_start_delay_ms;
        while (now_ms() < arm_end) {
            drain_hid_out_reports(fd_pad, fd_kbd);
            ssize_t w1 = write(fd_pad, &neutral_pad, sizeof(neutral_pad));
            ssize_t w2 = write(fd_kbd, &neutral_kbd, sizeof(neutral_kbd));
            (void)w1;
            (void)w2;
            sleep_ms(8);
        }

        /* 3. Execute macro steps (LED solid ON during playback, matching PicoSwitch) */
        led_set(true);

        bool playback_ok = true;
        for (size_t idx = 0; idx < steps.count; idx++) {
            const MacroStep *step = &steps.items[idx];
            if (step->op == MACRO_OP_END) {
                break;
            }

            SwitchUsbReport cur_pad = neutral_pad;
            KeyboardReport  cur_kbd = neutral_kbd;
            if (step->op == MACRO_OP_KEYS || step->op == MACRO_OP_BOTH) {
                cur_kbd = step->keyboard;
            }
            if (step->op == MACRO_OP_PAD || step->op == MACRO_OP_BOTH) {
                cur_pad = step->gamepad;
            }

            /* Send only the interface selected by the step.
             * WAIT releases both; Linux writes still retry endpoint backpressure. */
            if (step->op != MACRO_OP_KEYS &&
                !write_report_reliable(fd_pad, &cur_pad, sizeof(cur_pad), fd_pad, fd_kbd)) {
                playback_ok = false;
                break;
            }
            if (step->op != MACRO_OP_PAD &&
                !write_report_reliable(fd_kbd, &cur_kbd, sizeof(cur_kbd), fd_pad, fd_kbd)) {
                playback_ok = false;
                break;
            }
            uint64_t step_end = now_ms() + step->durationMs;
            while (now_ms() < step_end) {
                drain_hid_out_reports(fd_pad, fd_kbd);
                sleep_ms(1);
            }
        }

        /* 4. Finished: release all keys/buttons and turn LED OFF */
        for (int i = 0; i < 5; i++) {
            bool pad_ok = write_report_reliable(fd_pad, &neutral_pad, sizeof(neutral_pad), fd_pad, fd_kbd);
            bool kbd_ok = write_report_reliable(fd_kbd, &neutral_kbd, sizeof(neutral_kbd), fd_pad, fd_kbd);
            if (!pad_ok || !kbd_ok) { playback_ok = false; break; }
            sleep_ms(10);
        }
        led_set(false);

        /* 5. Stay idle serving neutral HID reports; re-arm if unplugged for >1s */
        uint64_t unconf_since = 0;
        while (1) {
            if (!playback_ok) led_set((now_ms() % 200) < 100);
            drain_hid_out_reports(fd_pad, fd_kbd);
            ssize_t w1 = write(fd_pad, &neutral_pad, sizeof(neutral_pad));
            ssize_t w2 = write(fd_kbd, &neutral_kbd, sizeof(neutral_kbd));
            (void)w1;
            (void)w2;
            if (!is_udc_configured(udc_name)) {
                if (unconf_since == 0) unconf_since = now_ms();
                else if (now_ms() - unconf_since > 1000) break;
            } else {
                unconf_since = 0;
            }
            sleep_ms(16);
        }
    }
#endif
    return 0;
}
