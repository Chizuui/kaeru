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
// The sibling that decides which boot state to *display*. Same shape as
// cmdline_pre_process - same prologue, same global, same cmp/tbb - and it is what prints
// "boot state: orange" plus the "Orange State / Your device has been unlocked and can't be
// trusted" screen. The two differ only in the second halfword, 0x4B1C against 0x4B11, so
// SIG_CMDLINE_PREPROC does not match it.
#define SIG_BOOT_STATE_SHOW  0xB508, 0x4B1C, 0x447B, 0x681B
// orange_state_warning(): the dispatcher that decides whether to show the boot-time
// unlock warning. Shares the 0xB508 prologue with the two functions above, differing only
// in the second halfword, 0x4B0E against 0x4B11 and 0x4B1C, so the three never collide.
// This is the correct place to cut the warning, and the one confirmed on hardware.
#define SIG_ORANGE_STATE_WARNING  0xB508, 0x4B0E, 0x447B
// The screen orange_state_warning() tail-calls for state 2. Listed only for reference;
// it is reached through a tail branch rather than a BL, which is why earlier attempts to
// find its caller by scanning BL came up empty.
#define SIG_ORANGE_SCREEN   0xB508, 0xF7EC, 0xF97F, 0xF7B1, 0xF89F
// the printf inside platform_init that reports "ENV init"; runs once the
// environment is ready, which is the earliest point get_env() returns non-NULL
#define SIG_ENV_INIT_PRINTF  0xF03D, 0xF8D5, 0x6823, 0x2000
// dm-verity corruption warning shown while booting
#define SIG_DM_VERITY        0xB530, 0xB083, 0xAB02, 0x2200
// load_and_verify_vbmeta(): the AVB public-key check. On this build it sits mid-function
// at 0x4C464CF8, inside a function whose entry is at 0x4C462708.
//
// gale's bytes are 0xF47F, 0xAE6B, 0xE688, 0xF8DD. board-earth.c searches for
// 0xF47F, 0xAE71, 0xE68D, 0xF8DD, which does not match here: the two differing halfwords
// are branch immediates, so the instruction shapes are identical but the branch targets
// are not. That is why the check was previously recorded as absent.
//
// Both of earth's applicable offsets were re-derived against this image rather than copied:
//
//     addr + 0x00   7F F4 6B AE   bne.w #0x4C4649D2
//     addr + 0x72   00 2B         cmp r3, #0        (halfword 0x2B00)
#define SIG_LOAD_VERIFY_VBMETA  0xF47F, 0xAE6B, 0xE688, 0xF8DD
// avb_add_cmdline_options(): the function that assembles
// androidboot.vbmeta.device_state=... for the kernel cmdline
#define SIG_AVB_CMDLINE      0xE92D, 0x4FF0, 0x4691, 0xF102
// get_vfy_policy() / get_dl_policy(): image authentication and download policy
#define SIG_GET_VFY_POLICY   0xB508, 0xF7FF, 0xFF63, 0xF3C0
#define SIG_GET_DL_POLICY    0xB508, 0xF7FF, 0xFF5D, 0xF000

// Offsets inside the fastboot command processor, measured from its entry above.
//
// sec_usbdl_enabled() is forced to 0, so "cbz r0" at +0x12E is always taken and the whole
// block from +0x130 to +0x148 is dead for us. The live path is:
//
//     +0x15C  mov  r0, r4
//     +0x15E  bl   <match command>
//     +0x162  cmp  r0, #0
//     +0x164  beq  +0x134
//     +0x166  ldr  r3, [r7, #0xc]    ; cmd->allowed_when_security_on
//     +0x168  cmp  r3, #0
//     +0x16A  bne  +0x134             ; set -> carry on to the handler
//     +0x16C  ldr  r0, ="not support on security"
//     +0x170  bl   fastboot_fail
//     +0x176  b    <loop continue>
//
// The refusal is skipped by branching to the loop-continue label, not by the failure call,
// so NOPing +0x170 only silences the message: execution still falls through to "b
// <loop continue>" and the command never runs. LK's built-in flash and erase entries carry
// allowed_when_security_on = 0 in LK's own command table, which kaeru cannot edit, so the
// branch has to be forced instead.
//
// PATCH_CALL/PATCH_ALL_BL cannot help here either: they rewrite call sites, and this is a
// table field read inside the dispatcher.
//
// 0xD1E3 is a 16-bit B<cond> T1 with an 8-bit signed offset (-0x3A), not the 32-bit imm11
// form, so flipping the condition field in place is not possible. The unconditional B T2 is
// 11100 imm11; imm11 = -0x3A/2 = 0x7E3, giving 0xE7E3, which capstone confirms decodes to
// "b #0x4C42B962" - the same target as the BNE it replaces.
#define FB_FAIL_NOT_SUPPORTED   0x170   // BL fastboot_fail, "not support on security"
#define FB_FAIL_NOT_ALLOWED     0x17C   // BL fastboot_fail, "not allowed in locked state"
#define FB_SECURITY_GATE        0x12A   // BL sec_usbdl_enabled, branches into the handler
#define FB_ALLOWED_GATE_BRANCH  0x16A   // BNE +0x134 -> B +0x134

// Offset inside cmdline_pre_process(), measured from its entry above. The function reads a
// boot-state byte, checks it is in range, then dispatches with tbb:
//
//     +0x0A  cmp  r3, #3
//     +0x0C  bhi  +0x20               ; out of range -> append nothing
//     +0x0E  tbb  [pc, r3]
//
// The four arms resolve, in this image, to:
//     state 0 -> "androidboot.verifiedbootstate=green"
//     state 1 -> "androidboot.verifiedbootstate=yellow"
//     state 2 -> "androidboot.verifiedbootstate=orange"
//     state 3 -> "androidboot.verifiedbootstate=red"
//
// The cross-check is the recovery config: CONFIG_RECOVERY_CMDLINE2_ADDRESS is 0x4C5163F4,
// which is exactly the address of the "green" string.
//
// Replacing the range check with "movs r3, #0" pins the dispatch to green. movs sets Z and
// clears C, so the bhi is not taken and tbb reads index 0. One halfword, no shift in the
// instruction stream.
#define CMDLINE_STATE_RANGE     0x0A

// Offset of the key_is_trusted test inside load_and_verify_vbmeta, measured from the
// match above. The instruction there is 0x2B00, "cmp r3, #0", immediately followed by
// "bne.w", so forcing r3 to 1 takes the branch that accepts the key.
#define VBMETA_KEY_TRUSTED      0x72

// Same offset in the boot-state display function, whose prologue is identical. See
// SIG_BOOT_STATE_SHOW.
#define BOOT_STATE_SHOW_RANGE   0x0A

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

    // fastboot must not be affected by the spoof, so drop both refusal messages and
    // branch straight into the command handler. Without this, spoofing the lock
    // state to "locked" makes fastboot reject commands with "not support on
    // security" and "not allowed in locked state" even though the device is really
    // unlocked underneath.
    //
    // Applied unconditionally, like sec_usbdl_enabled and dm_verity_corruption above.
    // It used to sit after the "spoofing disabled" early return, which meant that with
    // the spoof off these gates were left intact, so on a device whose real state is
    // locked fastboot refused to flash. That is backwards: the gates exist to stop the
    // spoof from locking fastboot out, and with the spoof off there is nothing to stop.
    // Access to fastboot should never depend on the spoof flag.
    addr = SEARCH_PATTERN(LK_START, LK_END, SIG_FB_PROCESSOR);
    if (addr) {
        printf("Found fastboot command processor at 0x%08X\n", addr);

        NOP(addr + FB_FAIL_NOT_SUPPORTED, 2);
        NOP(addr + FB_FAIL_NOT_ALLOWED, 2);

        // Branch straight into the dispatch that follows the gate. The gate sits at
        // +0x12A and the dispatch at +0x15C, so the branch must cover 0x15C - 0x12A
        // - 4 = 0x2E bytes, giving imm11 = 0x17 and the encoding 0xE017.
        PATCH_MEM(addr + FB_SECURITY_GATE, 0xE017);

        // Force the allowed_when_security_on branch. Without this, fastboot flash works
        // with the spoof off and silently does nothing with it on: the dispatcher skips
        // LK's own flash/erase entries because their table flag is 0, and the NOPs above
        // only removed the message. See the comment on FB_ALLOWED_GATE_BRANCH.
        PATCH_MEM(addr + FB_ALLOWED_GATE_BRANCH, 0xE7E3);
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

    // Accept any vbmeta signing key.
    //
    // The spoof reports the device as locked, and a locked device treats a vbmeta signed
    // with an unrecognised key as fatal, which is where the observed
    // "invalid pubk size" and "vbmeta_a : Public key used to sign data rejected" come
    // from. Without this the boot never gets past AVB.
    //
    // Only two of board-earth.c's three patches apply here. The third one rewrites a
    // chained-key length check at -0x32C; that offset in gale holds a different
    // comparison and gale has no "cmp r2, r3" anywhere near, so it is left alone rather
    // than guessed. See docs/gale.md.
    addr = SEARCH_PATTERN(LK_START, LK_END, SIG_LOAD_VERIFY_VBMETA);
    if (addr) {
        printf("Found load_and_verify_vbmeta at 0x%08X\n", addr);

        // NOP the bne.w at +0x00 (2 halfwords = the full 4-byte instruction), so the
        // following unconditional branch is always taken.
        NOP(addr, 2);

        // cmp r3, #0 -> movs r3, #1, so key_is_trusted is always non-zero and the branch
        // after it takes the accepted path.
        PATCH_MEM(addr + VBMETA_KEY_TRUSTED, 0x2301);
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
    } else {
        // Pin androidboot.verifiedbootstate to green.
        //
        // With the spoof on, the restored function runs but still dispatches to orange,
        // because the boot-state byte it reads is not the one the patched getters produce.
        // A log from the test run shows both values in the same boot:
        //
        //     [3463] [AVB20] lock_state = 0x3      LKS_SECURITY_LOCKED, the spoofed value
        //     [3684] boot state: orange             driven by something else
        //     dump lock_state, 0x0                  LKS_UNLOCKED, the real value
        //     androidboot.verifiedbootstate=orange  what the kernel is then told
        //
        // verifiedbootstate is what becomes ro.boot.verifiedbootstate, which is what init
        // and most apps read, so leaving it at orange is the spoof failing where it counts.
        // The reader behind the orange decision has not been located, so instead of chasing
        // it the dispatch itself is pinned.
        addr = SEARCH_PATTERN(LK_START, LK_END, SIG_CMDLINE_PREPROC);
        if (addr) {
            printf("Found cmdline_pre_process at 0x%08X, forcing green state\n", addr);
            // cmp r3, #3  ->  movs r3, #0
            PATCH_MEM(addr + CMDLINE_STATE_RANGE, 0x2300);
        }

        // Pin the on-screen warning too. cmdline_pre_process only decides what the kernel
        // is told; the warning text is emitted by its sibling 528 bytes earlier, which
        // reads the same boot-state global and has the identical cmp/tbb. Without this the
        // kernel is told "green" while the display still says "orange", which is the
        // inconsistency the test run showed. Same one-halfword patch, same effect.
        addr = SEARCH_PATTERN(LK_START, LK_END, SIG_BOOT_STATE_SHOW);
        if (addr) {
            printf("Found boot state display at 0x%08X, forcing green state\n", addr);
            PATCH_MEM(addr + BOOT_STATE_SHOW_RANGE, 0x2300);
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
        addr = SEARCH_PATTERN(LK_START, LK_END, SIG_ORANGE_STATE_WARNING);
        if (addr) {
            printf("Found orange_state_warning at 0x%08X, suppressing warning\n", addr);
            FORCE_RETURN(addr, 0);
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
