//
// SPDX-FileCopyrightText: 2026 R0rt1z2 <roger@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>
#include <lib/bootmode.h>

static void spoof_lock_state(void) {
    uint32_t addr = 0;

    // Xiaomi doesn't rely on MediaTek's seccfg lock state alone. Their getter
    // reads the seccfg lock state *and* a second (RPMB-backed) source and only
    // agrees when both match, otherwise it forces "locked".
    //
    // Every lock-state consumer in LK funnels through this single getter, so
    // instead of chasing individual call sites we redirect its entry to our own
    // get_lock_state() (same ABI: writes the state through the pointer in r0,
    // returns 0). Reports the real unlocked state normally and a spoofed
    // "locked" state when the user enables spoofing.
    //
    // The lock state lives behind two small adapters. Each one calls
    // seccfg_get_lock_state() first and falls back to custom_get_lock_state(),
    // which is what decides the value every other LK API observes. Redirect both
    // calls to kaeru's shim, which reports "locked" only while spoofing is on.
    uint32_t adapter_a = SEARCH_PATTERN(LK_START, LK_END, 0xB510, 0xB082, 0x4C10, 0x2304);
    uint32_t adapter_b = SEARCH_PATTERN(LK_START, LK_END, 0xB510, 0xB082, 0x4C11, 0x2304);
    uint32_t seccfg_get_lock_state_addr = SEARCH_PATTERN(LK_START, LK_END, 0xB530, 0x4605, 0x4917, 0xB087);
    uint32_t custom_get_lock_state_addr = SEARCH_PATTERN(LK_START, LK_END, 0x4B01, 0x447B, 0x6818, 0x4770, 0x3552);

    if (adapter_a && seccfg_get_lock_state_addr) {
        int n = PATCH_ALL_BL(adapter_a, 70, seccfg_get_lock_state_addr, get_lock_state);
        printf("Patched %d seccfg_get_lock_state call(s) in adapter A\n", n);
    }

    if (adapter_b && seccfg_get_lock_state_addr) {
        int n = PATCH_ALL_BL(adapter_b, 76, seccfg_get_lock_state_addr, get_lock_state);
        printf("Patched %d seccfg_get_lock_state call(s) in adapter B\n", n);
    }

    if (adapter_a && custom_get_lock_state_addr) {
        int n = PATCH_ALL_BL(adapter_a, 70, custom_get_lock_state_addr, get_lock_state);
        printf("Patched %d custom_get_lock_state call(s) in adapter A\n", n);
    }

    if (adapter_b && custom_get_lock_state_addr) {
        int n = PATCH_ALL_BL(adapter_b, 76, custom_get_lock_state_addr, get_lock_state);
        printf("Patched %d custom_get_lock_state call(s) in adapter B\n", n);
    }

    // When we spoof the lock state to appear "locked", fastboot
    // starts rejecting commands with "not support on security" and
    // "not allowed in locked state" errors. Since the device is
    // actually unlocked underneath, the security checks are just
    // being overly paranoid.
    //
    // This patch removes both security gates so fastboot commands
    // work regardless of what the spoofed lock state reports.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0x000E, 0xE92D, 0x4FF0, 0xB087);
    if (addr) {
        printf("Found fastboot command processor at 0x%08X\n", addr);

        // "not support on security" call
        NOP(addr + 0x170, 2);

        // "not allowed in locked state" calls
        NOP(addr + 0x17C, 2);

        // Branch straight into the dispatch that follows the gate. The gate sits at
        // +0x12A and the dispatch at +0x15C, so the branch must cover 0x15C - 0x12A
        // - 4 = 0x2E bytes, giving imm11 = 0x17 and the encoding 0xE017.
        PATCH_MEM(addr + 0x12A, 0xE017);

        // Jump directly to the command handler
        PATCH_MEM(addr + 0x16A, 0xE7E3);
    }

    int spoofing = is_spoofing_enabled();
    fastboot_publish("is-spoofing", spoofing ? "1" : "0");

    if (!spoofing) {
        printf("Bootloader lock status spoofing disabled.\n");
        return;
    }

    printf("Bootloader lock status spoofing enabled, applying patches.\n");

    // AVB adds device state info to the kernel cmdline, but it
    // keeps showing "unlocked" even when we want it to say "locked".
    // This patch forces the cmdline to always use the "locked"
    // string instead of checking the actual device state.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4FF0, 0x4691, 0xF102);
    if (addr) {
        printf("Found AVB cmdline function at 0x%08X\n", addr);

        // The CBNZ at +0xA2 is what picks between the "locked" and "unlocked" strings:
        //
        //     +0xA0  ldr  r3, [sp, #0x24]    ; the device state libavb just fetched
        //     +0xA2  cbnz r3, +0x52          ; non-zero -> "unlocked"
        //     +0xA4  ldr  r2, [pc, #0x244]   ; "locked"
        //     +0xA6  add  r2, pc
        //     +0xA8  ldr  r1, [pc, #0x244]   ; "androidboot.vbmeta.device_state"
        //     +0xAE  bl   append_option
        //
        // NOPing the CBNZ forces the fallthrough, so the "locked" string is always used.
        // Exactly one halfword: the two literal loads right after it are what supply that
        // string and its key, so a wider NOP would leave append_option reading whatever r1
        // and r2 happened to hold.
        NOP(addr + 0xA2, 1);
    }

    // cmdline_pre_process runs just before the cmdline is handed to the kernel. It is the
    // function that appends androidboot.verifiedbootstate: it reads the boot state and calls
    // append_option() once, with "green", "yellow", "orange" or "red", picked through a tbb
    // at +0x0E.
    //
    // Its entry is deliberately not hooked. PATCH_CALL writes two halfwords, a 4-byte BL, and
    // this function begins with "push {r3, lr}" followed by "ldr r3, [pc, #0x44]". A BL at
    // +0x00 destroys both: the load that supplies the boot-state pointer is gone, so the
    // "add r3, pc" after it adds PC to whatever the callee left in caller-saved r3, and the
    // two "ldr r3, [r3]" that follow dereference that. It also drops the only save of lr and
    // unbalances the stack against the "pop {r3, pc}" at +0x20. board-fire.c can use the same
    // call only because its cmdline_pre_process begins with a 4-byte BL, so nothing is lost
    // there.
    //
    // Pin androidboot.verifiedbootstate to green.
    //
    // With the spoof on, the function still dispatches to orange, because the boot-state byte
    // it reads is not the one the patched getters produce. A log from the test run shows both
    // values in the same boot:
    //
    //     [3463] [AVB20] lock_state = 0x3      LKS_SECURITY_LOCKED, the spoofed value
    //     [3684] boot state: orange             driven by something else
    //     dump lock_state, 0x0                  LKS_UNLOCKED, the real value
    //     androidboot.verifiedbootstate=orange  what the kernel is then told
    //
    // verifiedbootstate is what becomes ro.boot.verifiedbootstate, which is what init and
    // most apps read, so leaving it at orange is the spoof failing where it counts. The
    // reader behind the orange decision has not been located, so the dispatch itself is
    // pinned: "cmp r3, #3" becomes "movs r3, #0".
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0x4B11, 0x447B, 0x681B);
    if (addr) {
        printf("Found cmdline_pre_process at 0x%08X, forcing green state\n", addr);
        // cmp r3, #3  ->  movs r3, #0
        PATCH_MEM(addr + 0x0A, 0x2300);

        // A recovery boot needs orange, or adbd and fastbootd refuse to do anything. Give it
        // orange by repointing the state-0 literal in this function's own literal pool,
        // rather than by rewriting the green string: green is the last entry of a
        // 40-byte-per-entry table and is followed immediately by "Your device has wrong
        // setting and may not ..." at 0x4C516418, and green -> orange is one byte longer, so
        // cmdline_replace() would move the terminator one byte on and blank that message.
        //
        // The state-0 arm loads its string as literal + 0x4C454798, so the shipped
        // 0x000C1C5C resolves to the green template at 0x4C5163F4 and 0x000C1BE8 to the
        // orange one at 0x4C516380.
        if (get_bootmode() == BOOTMODE_RECOVERY) {
            volatile uint32_t *lit = (volatile uint32_t *)(addr + 0x58);

            if (*lit == 0x000C1C5C) {
                printf("Recovery boot, pointing verifiedbootstate at orange\n");
                PATCH_MEM(addr + 0x58, 0x1BE8, 0x000C);
            } else {
                printf("State 0 literal is 0x%08X, not repointed\n", *lit);
            }
        }
    }

    // Pin the on-screen warning too. cmdline_pre_process only decides what the kernel
    // is told; the warning text is emitted by its sibling 528 bytes earlier, which
    // reads the same boot-state global and has the identical cmp/tbb. Without this the
    // kernel is told "green" while the display still says "orange", which is the
    // inconsistency the test run showed. Same one-halfword patch, same effect.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0x4B1C, 0x447B, 0x681B);
    if (addr) {
        printf("Found boot state display at 0x%08X, forcing green state\n", addr);
        PATCH_MEM(addr + 0x0A, 0x2300);
    }

    // Suppress the boot-time unlock warning. This is the one that actually works.
    //
    // orange_state_warning() is the dispatcher: it reads the same boot-state global,
    // and for state 2 (orange) it tail-calls the Orange State screen at 0x4C4545D4,
    // which prints the warning and adds the 5 second delay:
    //
    //     0x4C4546FE  cmp   r3, #2
    //     0x4C454700  beq   0x4C45471A
    //     0x4C45471A  pop.w {r3, lr}
    //     0x4C45471E  b.w   0x4C4545D4     ; Orange State screen + delay
    //
    // Forcing it to return 0 skips the state dispatch entirely, so the orange, yellow
    // and red paths are all bypassed at one point.
    //
    // Credit: wulan17, commit 0a7ed94 in his fork, which was confirmed on hardware.
    // Earlier attempts here pinned the state in the printer and stubbed the screen;
    // both sit below this dispatcher and only cover part of it.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0x4B0E, 0x447B);
    if (addr) {
        printf("Found orange_state_warning at 0x%08X, suppressing warning\n", addr);
        FORCE_RETURN(addr, 0);
    }

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
    printf("Entering early init for Xiaomi Redmi 13C 4G\n");

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
    }

    // The environment area isn't initialized yet when board_early_init
    // runs, so any get_env calls would return NULL at this stage. We
    // hook a printf call in platform_init that runs right after env
    // initialization completes, it's a convenient entry point since
    // the call itself is non-essential and we need the env to be ready
    // before applying our lock state patches.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF03D, 0xF8D5, 0x6823, 0x2000);
    if (addr) {
        printf("Found env_init_done at 0x%08X\n", addr);
        PATCH_CALL(addr, (void *)spoof_lock_state, TARGET_THUMB);
    }
}

void board_late_init(void) {
    printf("Entering late init for Xiaomi Redmi 13C 4G\n");

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
