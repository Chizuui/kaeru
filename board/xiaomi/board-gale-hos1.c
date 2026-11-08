//
// SPDX-FileCopyrightText: 2026 Chizuui
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Redmi 13C (gale), MIUI 14 / HyperOS 1 LK profile.
// Signatures and patch offsets in this file were checked against the matching
// lk.img with image base 0x4C400000. Do not reuse them for the HyperOS 2 LK.

#include <board_ops.h>

static uint32_t lock_state_veneer;

static void patch_hos1_recovery_cmdline(void) {
    bootmode_t mode = get_bootmode();
    if (!is_spoofing_enabled())
        return;

    // MediaTek/Xiaomi LK variants do not all report fastbootd the same way.
    // Keep ordinary Android (BOOTMODE_NORMAL) untouched, but allow recovery,
    // eRecovery, and fastboot boot modes to advertise orange to fastbootd.
    if (mode != BOOTMODE_RECOVERY && mode != BOOTMODE_ERECOVERY &&
        mode != BOOTMODE_FASTBOOT) {
        printf("MIUI recovery cmdline patch skipped for LK bootmode %d.\n", mode);
        return;
    }

    static const uint32_t cmdline_addrs[] = {
        CONFIG_RECOVERY_CMDLINE1_ADDRESS,
        CONFIG_RECOVERY_CMDLINE2_ADDRESS,
    };

    printf("MIUI LK bootmode %d: patching recovery cmdline templates.\n", mode);
    for (unsigned i = 0; i < ARRAY_SIZE(cmdline_addrs); i++) {
        uint32_t addr = cmdline_addrs[i];
        if (!addr)
            continue;

        bool patched = cmdline_replace((char *)addr,
                                       "androidboot.verifiedbootstate=",
                                       "green", "orange");
        printf("MIUI cmdline template 0x%08X: %s\n", addr,
               patched ? "green -> orange" : "no green value found");
    }
}

// Keep Android's normal boot reported as locked, but expose the real unlocked
// state to LK fastboot so bootloader-fastboot can authorize flash operations.
// Recovery fastbootd gets its unlocked signal from verifiedbootstate=orange in
// the recovery cmdline, handled separately below.
static int get_lock_state_for_bootmode(uint32_t *lock_state) {
    bootmode_t mode = get_bootmode();
    if (!is_spoofing_enabled() || mode == BOOTMODE_FASTBOOT ||
        mode == BOOTMODE_RECOVERY || mode == BOOTMODE_ERECOVERY) {
        *lock_state = LKS_UNLOCK;
        return 0;
    }

    *lock_state = LKS_LOCK;
    return 0;
}

static void install_veneer(uint32_t slot, void* target) {
    WRITE32(slot, 0xC004F8DF);  // ldr.w ip, [pc, #4]
    WRITE16(slot + 4, 0x4760);  // bx ip
    WRITE16(slot + 6, 0xBF00);  // nop
    WRITE32(slot + 8, (uint32_t)target | 1);
    arch_sync_cache_range(slot, 12);
}

static void spoof_lock_state(void) {
    uint32_t addr = 0;

    // The MIUI 14 adapter calls these two lock-state readers at distinct sites.
    // Both call-site signatures are unique in the matching image.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF034, 0xFD42, 0x4604, 0xB958);
    if (addr) {
        printf("Found MIUI seccfg_get_lock_state call at 0x%08X\n", addr);
        PATCH_CALL(addr, lock_state_veneer, TARGET_THUMB);
    }

    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF7FF, 0xFFBB, 0xB9B8, 0x9B02);
    if (addr) {
        printf("Found MIUI custom_get_lock_state call at 0x%08X\n", addr);
        PATCH_CALL(addr, lock_state_veneer, TARGET_THUMB);
    }

    int spoofing = is_spoofing_enabled();
    fastboot_publish("is-spoofing", spoofing ? "1" : "0");
    if (!spoofing) {
        printf("Bootloader lock status spoofing disabled.\n");
        return;
    }

    printf("Bootloader lock status spoofing enabled, applying MIUI 14 patches.\n");

    // MIUI 14 fastboot command processor. The four writes below are independent
    // gates: bypass sec_usbdl, allow handlers marked unavailable while locked,
    // and remove the two rejection calls.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0x000E, 0xE92D, 0x4FF0, 0xB087);
    if (addr) {
        printf("Found MIUI fastboot command processor at 0x%08X\n", addr);
        PATCH_MEM(addr + 0x12A, 0xE017);
        PATCH_MEM(addr + 0x16A, 0xE7E3);
        NOP(addr + 0x170, 2);
        NOP(addr + 0x17C, 2);
    }

    // Keep the cmdline state selector pinned to green for normal Android boots.
    // For recovery/fastbootd, rewrite the green cmdline template to orange below;
    // this avoids replacing cmdline_pre_process's PUSH/LDR prologue with a hook.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0x4B11, 0x447B, 0x681B);
    if (addr) {
        printf("Found MIUI cmdline_pre_process at 0x%08X\n", addr);
        PATCH_MEM(addr + 0x0A, 0x2300);  // cmp r3,#3 -> movs r3,#0
    }

    // fastbootd runs from the recovery ramdisk and checks verifiedbootstate.
    // Only rewrite the recovery cmdline templates; leave vbmeta.device_state
    // locked because changing it can hang recovery on some devices.
    // The boot-state display uses a sibling function; pin it to green as well.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0x4B1C, 0x447B, 0x681B);
    if (addr) {
        printf("Found MIUI boot-state display at 0x%08X\n", addr);
        PATCH_MEM(addr + 0x0A, 0x2300);
    }

    // Suppress the orange-state dispatcher, not just the screen it calls.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0x4B0E, 0x447B);
    if (addr) {
        printf("Found MIUI orange_state_warning at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // The main and chained-vbmeta checks are separate. Patch both at their
    // MIUI-specific sites.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF47F, 0xAE6B, 0xE688, 0xF8DD);
    if (addr) {
        printf("Found MIUI load_and_verify_vbmeta check at 0x%08X\n", addr);
        PATCH_MEM(addr - 0x32C, 0x451B);  // cmp r2,r3 -> cmp r3,r3
        NOP(addr, 2);
        PATCH_MEM(addr + 0x72, 0x2301);   // force key_is_trusted
    }

    // Allow AVB's recoverable verification errors through the separate slot gate.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF005, 0x0301, 0xF083, 0x0A01, 0x930D, 0x9B70);
    if (addr) {
        printf("Found MIUI avb_slot_verify error gate at 0x%08X\n", addr);
        PATCH_MEM(addr, 0xF04F, 0x0301);
    }

    // Fastboot's device-download security check is a separate path from the
    // dispatch gates above.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB538, 0x4B18, 0x447B, 0x681B);
    if (addr) {
        printf("Found MIUI sec_usbdl_enabled at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
}

FASTBOOT_CMD(bldr_spoof, "oem bldr_spoof", cmd_spoof_bootloader_lock, 1);

void board_early_init(void) {
    printf("Entering early init for Redmi 13C (gale, MIUI 14 / HyperOS 1)\n");
    uint32_t addr = 0;

    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFF63, 0xF3C0);
    if (addr) {
        printf("Found MIUI get_vfy_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFF5D, 0xF000);
    if (addr) {
        printf("Found MIUI get_dl_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // Reserve two veneer slots in the now-unreachable modem-verification body.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x41F0, 0x460A, 0x4604);
    if (!addr) {
        printf("MIUI ccci_ld_md_sec_ptr_hdr_verify signature missing.\n");
        return;
    }

    printf("Found MIUI ccci_ld_md_sec_ptr_hdr_verify at 0x%08X\n", addr);
    FORCE_RETURN(addr, 0);
    lock_state_veneer = addr + 4;
    install_veneer(lock_state_veneer, (void *)get_lock_state_for_bootmode);
    install_veneer(addr + 16, (void *)spoof_lock_state);

    // This printf runs after environment initialization, when get_env() is safe.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF03D, 0xF8D5, 0x6823, 0x2000);
    if (addr) {
        printf("Found MIUI env_init_done call at 0x%08X\n", addr);
        PATCH_CALL(addr, lock_state_veneer + 12, TARGET_THUMB);
    }
}

void board_late_init(void) {
    printf("Entering late init for Redmi 13C (gale, MIUI 14 / HyperOS 1)\n");
    // Bootmode may be finalized after platform/environment initialization.
    // Run the recovery cmdline patch here so it sees the final LK boot mode.
    patch_hos1_recovery_cmdline();

    // AVB's device_state selector is pinned to locked for ordinary Android
    // boots. In recovery/fastbootd keep the original selector so our
    // mode-aware lock-state hook can report unlocked instead.
    if (is_spoofing_enabled()) {
        bootmode_t mode = get_bootmode();
        if (mode != BOOTMODE_RECOVERY && mode != BOOTMODE_ERECOVERY &&
            mode != BOOTMODE_FASTBOOT) {
            uint32_t addr = SEARCH_PATTERN(LK_START, LK_END,
                                           0xE92D, 0x4FF0, 0x4691, 0xF102);
            if (addr) {
                printf("Found MIUI AVB cmdline function at 0x%08X; pinning normal boot locked.\n",
                       addr);
                NOP(addr + 0xA2, 1);
            }
        } else {
            printf("MIUI recovery/fastboot mode %d: leaving AVB device_state unlocked.\n",
                   mode);
        }
    }

    uint32_t addr = SEARCH_PATTERN(LK_START, LK_END, 0xB530, 0xB083, 0xAB02, 0x2200);
    if (addr) {
        printf("Found MIUI dm_verity corruption warning at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
}
