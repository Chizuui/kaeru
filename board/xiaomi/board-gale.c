//
// SPDX-FileCopyrightText: 2026 rexix01 <rexix01@proton.me>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>

// Stage 1 loads the payload into the heap. Keep LK's relative calls local
// and use absolute tail branches to reach the payload, preserving lr/r0-r3.
static uint32_t lock_state_veneer;
#ifdef CONFIG_RECOVERY_CMDLINE_PATCH
static uint32_t recovery_veneer;

static void recovery_cmdline_hook(void) {
    handle_recovery_boot();
    ((void (*)(void))(0x4C42FFBC | 1))(); // Original cmdline_pre_process().
}
#endif

static void install_veneer(uint32_t slot, void* target) {
    WRITE32(slot, 0xC004F8DF);     // ldr.w ip, [pc, #4]
    WRITE16(slot + 4, 0x4760);    // bx ip
    WRITE16(slot + 6, 0xBF00);    // nop
    WRITE32(slot + 8, (uint32_t)target | 1);
    arch_sync_cache_range(slot, 12);
}

static void spoof_lock_state(void) {
    uint32_t addr = 0;

    // Xiaomi uses a custom lock state implementation based on RPMB.
    // They expect the device to have a signature stored inside the
    // RPMB partition that indicates whether the device has been
    // officially unlocked or not. This signature has priority over
    // MediaTek's standard lock state mechanism (seccfg lock state),
    // so if you try to unlock the device through tools like MTKClient,
    // it will still remain locked.
    //
    // Most LK APIs call sec_get_lock_state_adapter(), which is a
    // wrapper that calls both seccfg_get_lock_state() and
    // custom_get_lock_state(), then, based on these results,
    // determines the final lock state.
    //
    // The idea is that people can benefit from this custom LK to
    // unlock their devices without having to worry about the custom
    // lock state, but at the same time, we need to provide the
    // ability to spoof the lock state for Play Integrity related
    // uses.
    // 0x4C438584: BL seccfg_get_lock_state (0x4C46E448).
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF035, 0xFF60, 0x4604, 0xB958);
    if (addr) {
        printf("Found seccfg_get_lock_state call at 0x%08X\n", addr);
        PATCH_CALL(addr, lock_state_veneer, TARGET_THUMB);
    }

    // 0x4C43858E: BL custom_get_lock_state (0x4C438508).
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF7FF, 0xFFBB, 0xB9B8, 0x9B02);
    if (addr) {
        printf("Found custom_get_lock_state call at 0x%08X\n", addr);
        PATCH_CALL(addr, lock_state_veneer, TARGET_THUMB);
    }

    int spoofing = is_spoofing_enabled();
    fastboot_publish("is-spoofing", spoofing ? "1" : "0");

    if (!spoofing) {
        printf("Bootloader lock status spoofing disabled.\n");
        return;
    }

    printf("Bootloader lock status spoofing enabled, applying patches.\n");

    // When we spoof the lock state to appear "locked", fastboot
    // starts rejecting commands with "not support on security" and
    // "not allowed in locked state" errors. Since the device is
    // actually unlocked underneath, the security checks are just
    // being overly paranoid.
    //
    // This patch removes both security gates so fastboot commands
    // work regardless of what the spoofed lock state reports.
    // Gale fastboot command processor at 0x4C42C6B4.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4FF0, 0xB087, 0x4D5F);
    if (addr) {
        printf("Found fastboot command processor at 0x%08X\n", addr);

        // 0x4C42C7AE -> 0x4C42C7C2: dispatch without the security gates.
        PATCH_MEM(addr + 0xFA, 0xE008);

        // 0x4C42C7DC -> 0x4C42C71E: resume the loop without repeating
        // the security gates after a handler leaves fastboot state at 1.
        PATCH_MEM(addr + 0x128, 0xE79F);
    }

    // AVB adds device state info to the kernel cmdline, but it
    // keeps showing "unlocked" even when we want it to say "locked".
    // This patch forces the cmdline to always use the "locked"
    // string instead of checking the actual device state.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4FF0, 0x4691, 0xF102);
    if (addr) {
        printf("Found AVB cmdline function at 0x%08X\n", addr);

        // NOP out the code that checks the actual device state,
        // forcing libavb to always use the "locked" string.
        NOP(addr + 0x9C, 4);
    }

#ifdef CONFIG_RECOVERY_CMDLINE_PATCH
    // 0x4C42B298: patch boot arguments, then run the original preprocessing.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF004, 0xFE90, 0xF7FA, 0xFBF4);
    if (addr) {
        printf("Found cmdline_pre_process at 0x%08X\n", addr);
        PATCH_CALL(addr, recovery_veneer, TARGET_THUMB);
    }
#endif

    // AVB verifies vbmeta public keys in two places: once for the main
    // vbmeta image (validate_vbmeta_public_key) and once for chained
    // vbmeta images (avb_safe_memcmp against the expected key). Both
    // reject the boot if the key doesn't match, causing the "Public key
    // used to sign data rejected" error. We patch both checks so any
    // key is accepted regardless.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF47F, 0xAE6B, 0xE688, 0xF8DD);
    if (addr) {
        printf("Found load_and_verify_vbmeta at 0x%08X\n", addr);

        // The chain key check first compares key lengths before calling
        // memcmp. If lengths differ, it skips memcmp and falls straight
        // to the error path. Change "cmp r2, r3" to "cmp r3, r3" so the
        // length check always succeeds, allowing execution to reach the
        // memcmp path (which we NOP below).
        PATCH_MEM(addr - 0x32C, 0x451B);

        // NOP the bne.w that rejects mismatched chained vbmeta keys,
        // falling through to the success path unconditionally.
        NOP(addr, 2);

        // Replace "cmp r3, #0" with "movs r3, #1" so key_is_trusted
        // is always nonzero and the following bne.w takes the success
        // branch.
        PATCH_MEM(addr + 0x72, 0x2301);
    }
}

// kaeru bootloader lock spoofing control command.
FASTBOOT_CMD(bldr_spoof, "oem bldr_spoof", cmd_spoof_bootloader_lock, 1);

void board_early_init(void) {
    printf("Entering early init for Redmi 13C (gale)\n");

    uint32_t addr = 0;

    // Regardless of whether spoofing is enabled, we always need to disable
    // image authentication. The user may just be using this custom LK to
    // unlock (bypassing Xiaomi's RPMB lock), or they may be spoofing where
    // the locked state would enforce verification.
    //
    // Forcing get_vfy_policy to return 0 skips certificate verification for
    // all partitions and firmware images (boot, recovery, dtbo, SCP, etc.)
    // so the device can boot with modified or unsigned images.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFF63, 0xF3C0);
    if (addr) {
        printf("Found get_vfy_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // Same idea but for download policy, forcing get_dl_policy to return
    // 0 ensures no partition is marked as download-forbidden, so flashing
    // via fastboot works for all partitions.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFF5D, 0xF000);
    if (addr) {
        printf("Found get_dl_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // This function handles certificate chain and hash verification for
    // modem-related images (md1rom, md3rom, etc.) during the modem loading
    // process. Same idea as above — force it to return 0 so modem images
    // can be loaded without passing signature verification.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x41F0, 0x460A, 0x4604);
    if (addr) {
        printf("Found ccci_ld_md_sec_ptr_hdr_verify at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
        // Its body is unreachable after the forced return. Reserve three
        // aligned 12-byte slots there for calls back into the heap payload.
        lock_state_veneer = addr + 4;
        install_veneer(lock_state_veneer, (void *)get_lock_state);
        install_veneer(addr + 16, (void *)spoof_lock_state);
#ifdef CONFIG_RECOVERY_CMDLINE_PATCH
        recovery_veneer = addr + 28;
        install_veneer(recovery_veneer, (void *)recovery_cmdline_hook);
#endif
    } else {
        printf("Gale modem verification signature missing; cannot install hooks.\n");
        return;
    }

    // The environment area isn't initialized yet when board_early_init
    // runs, so any get_env calls would return NULL at this stage. We
    // hook a printf call in platform_init that runs right after env
    // initialization completes, it's a convenient entry point since
    // the call itself is non-essential and we need the env to be ready
    // before applying our lock state patches.
    // 0x4C403B5A follows env_init() and print_env() in platform_init().
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF039, 0xF859, 0x6823, 0x2000);
    if (addr) {
        printf("Found env_init_done at 0x%08X\n", addr);
        PATCH_CALL(addr, lock_state_veneer + 12, TARGET_THUMB);
    }
}

void board_late_init(void) {
    printf("Entering late init for Redmi 13C (gale)\n");

    uint32_t addr = 0;

    // Disables the dm-verity corruption warning shown during boot when
    // the device is unlocked. Without this patch, the user gets a scary
    // "Your device is corrupt" screen that waits for a power button
    // press and powers off after 5 seconds if ignored.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB530, 0xB083, 0xAB02, 0x2200);
    if (addr) {
        printf("Found dm_verity_corruption at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
}
