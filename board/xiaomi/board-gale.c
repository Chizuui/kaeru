//
// SPDX-FileCopyrightText: 2026 Chizuui
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Board file for Redmi 13C (gale), MediaTek MT6768.
//
// Every SEARCH_PATTERN below was extracted from this device's own lk.img rather
// than copied from another board, because kaeru's offsets are not portable between
// LK builds. Sanity checks that the load base is right:
//   * CONFIG_MTK_DETECT_KEY lands exactly on an IDA function start
//   * the dm_verity pattern used here is byte-identical to the one earth uses,
//     which only matches if BOOTLOADER_BASE is 0x4C400000
//   * every signature below resolves to exactly one hit in the image
//
// Spoofing strategy follows board-earth.c: the lock state reported to the TEE is
// forced to "locked" so attestation and Play Integrity see a locked device, while
// fastboot keeps working and recovery keeps booting, because both of those are
// explicitly un-spoofed here.

#include <board_ops.h>
#include <lib/bootmode.h>

// ── LK signatures, verified unique in gale's lk.img ────────────────────────────
//
// sec_usbdl_enabled()            -> "sec_usbdl_enabled -- invalid susbd" string
#define SIG_SEC_USBDL        0xB538, 0x4B18, 0x447B, 0x681B
// lock-state adapters; both call seccfg_get_lock_state() and then
// custom_get_lock_state(), printing "get lock state fail" if both fail.
#define SIG_LOCK_ADAPTER_A   0xB510, 0xB082, 0x4C10, 0x2304
#define SIG_LOCK_ADAPTER_B   0xB510, 0xB082, 0x4C11, 0x2304
#define ADAPTER_A_SIZE       70
#define ADAPTER_B_SIZE       76
#define SIG_SECCFG_GET_LOCK  0xB530, 0x4605, 0x4917, 0xB087
// custom_get_lock_state() is only four instructions long, so its own bytes are not
// unique; the fifth halfword pins it down to a single hit in this image.
#define SIG_CUSTOM_GET_LOCK  0x4B01, 0x447B, 0x6818, 0x4770, 0x3552
// fastboot command processor: prints "fastboot: processing commands"
#define SIG_FB_PROCESSOR     0x000E, 0xE92D, 0x4FF0, 0xB087
// cmdline_pre_process(): the verifiedbootstate switcher holding
// "androidboot.verifiedbootstate=orange" and "...=green"
#define SIG_CMDLINE_PREPROC  0xB508, 0x4B11, 0x447B, 0x681B
// the printf inside platform_init that reports "ENV init"; runs once the
// environment is ready, which is the earliest point get_env() returns non-NULL
#define SIG_ENV_INIT_PRINTF  0xF03D, 0xF8D5, 0x6823, 0x2000
// dm-verity corruption warning shown while booting
#define SIG_DM_VERITY        0xB530, 0xB083, 0xAB02, 0x2200
// avb_add_cmdline_options(): the function that assembles
// androidboot.vbmeta.device_state=... for the kernel cmdline
#define SIG_AVB_CMDLINE      0xE92D, 0x4FF0, 0x4691, 0xF102
// get_vfy_policy() / get_dl_policy(): image authentication and download policy
#define SIG_GET_VFY_POLICY   0xB508, 0xF7FF, 0xFF63, 0xF3C0
#define SIG_GET_DL_POLICY    0xB508, 0xF7FF, 0xFF5D, 0xF000

// Offsets inside the fastboot command processor, measured from its entry above.
#define FB_FAIL_NOT_SUPPORTED   0x170   // BL fastboot_fail, "not support on security"
#define FB_FAIL_NOT_ALLOWED     0x17C   // BL fastboot_fail, "not allowed in locked state"
#define FB_SECURITY_GATE        0x12A   // BL sec_usbdl_enabled, branches into the handler

// Offset inside avb_add_cmdline_options(), measured from its entry above. This is
// the CBNZ that picks between the "locked" and "unlocked" strings:
//
//     +0xA0  LDR  R3, [SP,#var_88]     ; the device state libavb just fetched
//     +0xA2  CBNZ R3, +0x52            ; non-zero -> "unlocked"
//     +0xA4  LDR  R2, ="locked"
//     +0xA8  LDR  R1, ="androidboot.vbmeta.device_state"
//     +0xAE  BL   append_option
//
// NOPing the CBNZ forces the fallthrough, so the "locked" string is always used.
// Only that one halfword is NOPed: the very next instruction is the literal load
// for "locked", and a wider NOP would eat it.
//
// This is +0xA2 and deliberately not the +0x9C that board-earth.c uses. On this
// build +0x9C holds "BEQ loc_622E8", which is libavb's
// `if (state == 1) return 1;` error check; NOPing it would quietly disable error
// handling and would not change the device state at all.
#define AVB_DEVICE_STATE_SEL   0xA2

static void spoof_lock_state(void) {
    uint32_t addr = 0;
    uint32_t adapter_a = 0;
    uint32_t adapter_b = 0;
    uint32_t seccfg_get_lock = 0;
    uint32_t custom_get_lock = 0;

    // Regardless of whether spoofing is on, we always need download mode to be
    // permitted and the dm-verity warning suppressed. Otherwise the device shows a
    // "your device is corrupt" screen and refuses fastboot downloads.
    //
    // sec_usbdl_enabled() gates whether USB download is allowed at all. Forcing it
    // to 0 disables the check for every caller in one place.
    addr = SEARCH_PATTERN(LK_START, LK_END, SIG_SEC_USBDL);
    if (addr) {
        printf("Found sec_usbdl_enabled at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    addr = SEARCH_PATTERN(LK_START, LK_END, SIG_DM_VERITY);
    if (addr) {
        printf("Found dm_verity_corruption at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    int spoofing = is_spoofing_enabled();
    fastboot_publish("is-spoofing", spoofing ? "1" : "0");

    if (!spoofing) {
        printf("Bootloader lock status spoofing disabled.\n");
        return;
    }

    printf("Bootloader lock status spoofing enabled, applying patches.\n");

    // The lock state lives behind two small adapters. Each one calls
    // seccfg_get_lock_state() first and falls back to custom_get_lock_state(),
    // which is what decides the value every other LK API observes. Redirect both
    // calls to kaeru's shim, which reports "locked" only while spoofing is on.
    //
    // PATCH_ALL_BL is used rather than a single fixed call site because on this LK
    // each adapter has its own call to each getter, so patching one site would leave
    // the other path reporting the real state.
    adapter_a = SEARCH_PATTERN(LK_START, LK_END, SIG_LOCK_ADAPTER_A);
    adapter_b = SEARCH_PATTERN(LK_START, LK_END, SIG_LOCK_ADAPTER_B);
    seccfg_get_lock = SEARCH_PATTERN(LK_START, LK_END, SIG_SECCFG_GET_LOCK);
    custom_get_lock = SEARCH_PATTERN(LK_START, LK_END, SIG_CUSTOM_GET_LOCK);

    if (adapter_a && seccfg_get_lock) {
        int n = PATCH_ALL_BL(adapter_a, ADAPTER_A_SIZE, seccfg_get_lock, get_lock_state);
        printf("Patched %d seccfg_get_lock_state call(s) in adapter A\n", n);
    }
    if (adapter_b && seccfg_get_lock) {
        int n = PATCH_ALL_BL(adapter_b, ADAPTER_B_SIZE, seccfg_get_lock, get_lock_state);
        printf("Patched %d seccfg_get_lock_state call(s) in adapter B\n", n);
    }
    if (adapter_a && custom_get_lock) {
        int n = PATCH_ALL_BL(adapter_a, ADAPTER_A_SIZE, custom_get_lock, get_lock_state);
        printf("Patched %d custom_get_lock_state call(s) in adapter A\n", n);
    }
    if (adapter_b && custom_get_lock) {
        int n = PATCH_ALL_BL(adapter_b, ADAPTER_B_SIZE, custom_get_lock, get_lock_state);
        printf("Patched %d custom_get_lock_state call(s) in adapter B\n", n);
    }

    // fastboot must not be affected by the spoof, so drop both refusal messages and
    // branch straight into the command handler. Without this, spoofing the lock
    // state to "locked" makes fastboot reject commands with "not support on
    // security" and "not allowed in locked state" even though the device is really
    // unlocked underneath.
    addr = SEARCH_PATTERN(LK_START, LK_END, SIG_FB_PROCESSOR);
    if (addr) {
        printf("Found fastboot command processor at 0x%08X\n", addr);

        NOP(addr + FB_FAIL_NOT_SUPPORTED, 2);
        NOP(addr + FB_FAIL_NOT_ALLOWED, 2);

        // Branch straight into the dispatch that follows the gate. The gate sits at
        // +0x12A and the dispatch at +0x15C, so the branch must cover 0x15C - 0x12A
        // - 4 = 0x2E bytes, giving imm11 = 0x17 and the encoding 0xE017.
        PATCH_MEM(addr + FB_SECURITY_GATE, 0xE017);
    }

    // libavb appends androidboot.vbmeta.device_state to the kernel cmdline, and it
    // keeps reporting "unlocked" because the state it reads is the real one, not the
    // spoofed one the lock shim hands out. Forcing the "locked" string keeps the
    // cmdline consistent with the lock state everything else observes.
    addr = SEARCH_PATTERN(LK_START, LK_END, SIG_AVB_CMDLINE);
    if (addr) {
        printf("Found AVB cmdline function at 0x%08X\n", addr);
        NOP(addr + AVB_DEVICE_STATE_SEL, 1);
    }

    // cmdline_pre_process runs just before the cmdline is handed to the kernel. It is
    // the function that appends androidboot.verifiedbootstate: it switches on the boot
    // state and calls append_option() once, with "green", "yellow", "orange" or "red".
    //
    // PATCH_CALL overwrites the callee's first two halfwords, so hooking it this way does
    // not add a call, it *replaces* the function. Because handle_recovery_boot() returns
    // immediately unless the bootmode is RECOVERY, that replacement means a normal boot
    // never runs this code at all, and the kernel is handed a cmdline with no
    // androidboot.verifiedbootstate token whatsoever.
    //
    // That is not acceptable here. With the spoof on, this cmdline also carries
    // androidboot.vbmeta.device_state=locked, androidboot.secureboot=1 and
    // androidboot.veritymode.managed=yes. Verifiedbootstate is what tells init which of
    // those it is allowed to trust, so dropping it leaves the kernel unable to reconcile
    // them and it stalls during boot, before printing its first line.
    //
    // cmdline_pre_process is reached through a function pointer, not a BL, so redirecting
    // the caller is not available and a chain would need a trampoline. Instead only hook
    // it when recovery is actually being booted: handle_recovery_boot() does nothing
    // except during recovery anyway, so this keeps its one useful behaviour while leaving
    // every other boot with LK's own verifiedbootstate handling intact.
    if (get_bootmode() == BOOTMODE_RECOVERY) {
        addr = SEARCH_PATTERN(LK_START, LK_END, SIG_CMDLINE_PREPROC);
        if (addr) {
            printf("Found cmdline_pre_process at 0x%08X\n", addr);
            PATCH_CALL(addr, (void *)handle_recovery_boot, TARGET_THUMB);
        }
    }
}

// kaeru bootloader lock spoofing control command.
//
// The trailing argument is LK's allowed_when_security_on flag, not "requires unlock".
// Leaving it at 0 makes the fastboot dispatcher take this path at 0x4C42B994:
//
//     ldr  r3, [r7, #0xc]     ; cmd->allowed_when_security_on
//     cmp  r3, #0
//     bne  0x4C42B962          ; flag set -> run the handler
//     bl   fastboot_fail       ; "not support on security" (NOPped above, so silent)
//     b    0x4C42B89A          ; loop continue, command never runs
//
// NOPping fastboot_fail only suppresses the message; the command is still skipped.
// It must be 1, which also makes the dispatcher's second gate
// (ldr r3, [r7, #0x10] = forbidden_when_lock_on) reachable, since that one is only
// evaluated once allowed_when_security_on passes.
FASTBOOT_CMD(bldr_spoof, "oem bldr_spoof", cmd_spoof_bootloader_lock, 1);

void board_early_init(void) {
    printf("Entering early init for Redmi 13C (gale)\n");

    uint32_t addr = 0;

    // Regardless of whether spoofing is enabled we have to disable image
    // authentication, because the user may be running this LK purely to unlock the
    // device, and because reporting "locked" makes LK enforce verification. Forcing
    // get_vfy_policy() to 0 skips certificate verification for every partition and
    // firmware image (boot, recovery, dtbo, SCP, ...), so modified or unsigned
    // images can boot.
    addr = SEARCH_PATTERN(LK_START, LK_END, SIG_GET_VFY_POLICY);
    if (addr) {
        printf("Found get_vfy_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // Same idea for downloads. While the spoof reports "locked", get_dl_policy()
    // would otherwise mark partitions as download-forbidden and break flashing.
    addr = SEARCH_PATTERN(LK_START, LK_END, SIG_GET_DL_POLICY);
    if (addr) {
        printf("Found get_dl_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // The environment area is not initialized yet when board_early_init runs, so
    // get_env() always returns NULL at this point and the spoof cannot be gated on
    // its flag yet. platform_init prints a "[PROFILE] ... ENV init" line right
    // after the environment comes up; that printf is not needed for anything, so we
    // hijack the call to run once the environment is ready.
    addr = SEARCH_PATTERN(LK_START, LK_END, SIG_ENV_INIT_PRINTF);
    if (addr) {
        printf("Found env_init_done at 0x%08X\n", addr);
        PATCH_CALL(addr, (void *)spoof_lock_state, TARGET_THUMB);
    }
}

void board_late_init(void) {
    printf("Entering late init for Redmi 13C (gale)\n");
}
