
//
// SPDX-FileCopyrightText: 2026 R0rt1z2 <roger@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <lib/spoof.h>
#include <lib/common.h>

int is_spoofing_enabled(void) {
    const char *val = get_env(KAERU_ENV_BLDR_SPOOF);
    return val && strcmp(val, "1") == 0;
}

// Absent or unparsable means "apply everything". That keeps the default identical to a
// build with no mask support, so this can never change behaviour on its own.
static unsigned int spoof_mask(void) {
    const char *val = get_env(KAERU_ENV_BLDR_MASK);
    if (!val || !val[0])
        return SPOOF_MASK_ALL;

    unsigned int v;
    int base = 10, i = 0;
    if (val[0] == '0' && (val[1] == 'x' || val[1] == 'X')) {
        base = 16;
        i = 2;
    }
    if (!val[i])
        return SPOOF_MASK_ALL;

    v = 0;
    for (; val[i]; i++) {
        char c = val[i];
        int d;
        if (c >= '0' && c <= '9')      d = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return SPOOF_MASK_ALL;
        if (d >= base)
            return SPOOF_MASK_ALL;
        v = v * base + d;
    }
    return v;
}

int spoof_group_enabled(unsigned int mask) {
    if (!is_spoofing_enabled())
        return 0;
    return (spoof_mask() & mask) == mask;
}

void spoof_publish_mask(void) {
    char buf[16];
    unsigned int v = spoof_mask();
    int i = 15;
    buf[i] = '\0';
    if (!v) {
        buf[14] = '0';
        fastboot_publish("spoof-mask", buf);
        return;
    }
    while (v && i > 0) {
        buf[--i] = "0123456789abcdef"[v & 0xF];
        v >>= 4;
    }
    fastboot_publish("spoof-mask", &buf[i]);
}

void cmd_spoof_patch_mask(const char *arg, void *data, unsigned sz) {
    (void)data; (void)sz;

    const char *opt = arg + 1;

    if (!strcmp(opt, "status")) {
        unsigned int v = spoof_mask();
        char buf[16];
        int i = 15;
        buf[i] = '\0';
        if (!v) {
            buf[14] = '0';
        } else {
            while (v && i > 0) {
                buf[--i] = "0123456789abcdef"[v & 0xF];
                v >>= 4;
            }
        }
        fastboot_info("Active spoof patch mask:");
        fastboot_info("  01 vbmeta key       load_and_verify_vbmeta");
        fastboot_info("  02 avb cmdline      vbmeta.device_state");
        fastboot_info("  04 cmdline hook     handle_recovery_boot");
        fastboot_info("  08 cmdline green    verifiedbootstate pin");
        fastboot_info("  10 state show       boot state display");
        fastboot_info("  20 orange screen    orange_state_warning");
        fastboot_info("  3f all");
        fastboot_info("");
        fastboot_info(&buf[i]);
        fastboot_okay("");
        return;
    }

    if (!strncmp(opt, "0x", 2) || !strncmp(opt, "0X", 2) || (opt[0] >= '0' && opt[0] <= '9')) {
        unsigned int v = 0;
        int i = (!strncmp(opt, "0x", 2) || !strncmp(opt, "0X", 2)) ? 2 : 0;
        if (!opt[i]) {
            fastboot_fail("Usage: fastboot oem bldr_spoof_mask <0xHEX|all>");
            return;
        }
        for (; opt[i]; i++) {
            char c = opt[i];
            int d;
            if (c >= '0' && c <= '9')           d = c - '0';
            else if (c >= 'a' && c <= 'f')      d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')      d = c - 'A' + 10;
            else {
                fastboot_fail("Not a hex number.");
                return;
            }
            v = v * 16 + d;
        }
        if (v > SPOOF_MASK_ALL) {
            fastboot_fail("Mask must be 0x00-0x3f.");
            return;
        }
        set_env(KAERU_ENV_BLDR_MASK, opt);
        fastboot_publish("spoof-mask", opt);
        fastboot_info("Spoof patch mask set. A reboot is required.");
        fastboot_okay("");
        return;
    }

    if (!strcmp(opt, "all")) {
        set_env(KAERU_ENV_BLDR_MASK, "0x3f");
        fastboot_publish("spoof-mask", "0x3f");
        fastboot_info("Spoof patch mask set to all. A reboot is required.");
        fastboot_okay("");
        return;
    }

    fastboot_info("kaeru spoof patch mask");
    fastboot_info("");
    fastboot_info("Selects which parts of the spoof to apply.");
    fastboot_info("");
    fastboot_info("Commands:");
    fastboot_info("  0xHEX  - Bitmask of groups to apply");
    fastboot_info("  all    - All groups (default)");
    fastboot_info("  status - Show groups and current mask");
    fastboot_info("");
    fastboot_info("Bits:");
    fastboot_info("  01 vbmeta key     02 avb cmdline    04 cmdline hook");
    fastboot_info("  08 cmdline green  10 state show     20 orange screen");
    fastboot_info("  3f all");
    fastboot_fail("Usage: fastboot oem bldr_spoof_mask <0xHEX|all|status>");
}

int get_lock_state(uint32_t *lock_state) {
    int spoofing = is_spoofing_enabled();
#if KAERU_DEBUG
    printf("Attempted to get lock state, spoofing is %s\n",
            spoofing ? "enabled" : "disabled");
#endif
    *lock_state = spoofing ? LKS_LOCK : LKS_UNLOCK;
    return 0;
}

// Stubs that boards patch over the LK security checks so download mode,
// secure boot and the lock status always report the values we want.
int sec_usbdl_enabled(void) {
    return 0;
}

unsigned int seclib_sec_boot_enabled(unsigned int) {
    return 0;
}

unsigned get_unlocked_status(void) {
    return 1;
}

void cmd_spoof_bootloader_lock(const char *arg, void *data, unsigned sz) {
    int status = is_spoofing_enabled();
    const char *option = arg + 1;
    int target = -1;

    if (!strcmp(option, "on"))       target = 1;
    else if (!strcmp(option, "off")) target = 0;

    if (target != -1) {
        if (status != target) {
            set_env(KAERU_ENV_BLDR_SPOOF, target ? "1" : "0");
            fastboot_info(target ?
                "Bootloader spoofing enabled." :
                "Bootloader spoofing disabled.");
            fastboot_info("A factory reset may be required.");
        } else {
            fastboot_info(target ?
                "Bootloader spoofing is already enabled." :
                "Bootloader spoofing is already disabled.");
        }
        fastboot_publish("is-spoofing", target ? "1" : "0");
        fastboot_okay("");
        return;
    }

    if (!strcmp(option, "status")) {
        fastboot_info(status ?
            "Bootloader spoofing is currently enabled." :
            "Bootloader spoofing is currently disabled.");
        fastboot_info(status ?
            "Device is currently spoofed as bootloader locked." :
            "Device is not being spoofed as bootloader locked.");
        fastboot_okay("");
        return;
    }

    fastboot_info("kaeru bootloader lock spoofing control");
    fastboot_info("");
    fastboot_info("When enabled, device reports as 'locked' to TEE");
    fastboot_info("while maintaining full fastboot and root capabilities.");
    fastboot_info("");
    fastboot_info("Commands:");
    fastboot_info("  on     - Enable spoofing (reboot required)");
    fastboot_info("  off    - Disable spoofing (reboot required)");
    fastboot_info("  status - Show current state");
    fastboot_fail("Usage: fastboot oem bldr_spoof <on|off|status>");
}