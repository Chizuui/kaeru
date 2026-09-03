//
// SPDX-FileCopyrightText: 2026 Chizuui <desckun@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>

#define CMDLINE_ADDR 0x4C579624

static void patch_cmdline_state(char *cmdline, bool locked) {
    if (locked) {
        cmdline_replace(cmdline, "androidboot.verifiedbootstate=",
                        "orange", "green");
        cmdline_replace(cmdline, "androidboot.secureboot=", "0", "1");
        cmdline_replace(cmdline, "androidboot.vbmeta.device_state=",
                        "unlocked", "locked");
    } else {
        cmdline_replace(cmdline, "androidboot.verifiedbootstate=",
                        "green", "orange");
        cmdline_replace(cmdline, "androidboot.secureboot=", "1", "0");
        cmdline_replace(cmdline, "androidboot.vbmeta.device_state=",
                        "locked", "unlocked");
    }
}

__attribute__((used)) void apply_android_bootargs(void) {
    bootmode_t mode = get_bootmode();
    bool locked = is_spoofing_enabled() && mode == BOOTMODE_NORMAL;

    if (!is_spoofing_enabled())
        return;

    printf("%s boot: applying %s Android boot arguments.\n",
           bootmode2str(mode), locked ? "locked" : "unlocked");
    printf("Patching cmdline at 0x%08X\n", CMDLINE_ADDR);
    patch_cmdline_state((char *)CMDLINE_ADDR, locked);
}

static volatile uint32_t cmdline_pre_process_cont = 0;

static void __attribute__((naked)) cmdline_pre_process_hook(void) {
    asm volatile(
        "push {r0-r3, r12, lr}\n"
        "bl apply_android_bootargs\n"
        "pop {r0-r3, r12, lr}\n"
        "push.w {r4, r5, r6, r7, r8, r9, r10, lr}\n"
        "movw ip, #:lower16:cmdline_pre_process_cont\n"
        "movt ip, #:upper16:cmdline_pre_process_cont\n"
        "ldr ip, [ip]\n"
        "bx ip\n"
    );
}

static uint32_t load_and_verify_vbmeta_addr = 0;
static volatile uint32_t vbmeta_bypass_cont = 0;

static int get_root_of_trust_lock_state(uint32_t *lock_state) {
    bool locked = is_spoofing_enabled() && get_bootmode() == BOOTMODE_NORMAL;

    *lock_state = locked ? 1 : 0;
    printf("Root-of-trust lock state: %s.\n", locked ? "locked" : "unlocked");
    return 0;
}

__attribute__((used)) void apply_optional_vbmeta_bypass(void) {
    if (!is_spoofing_enabled() || !load_and_verify_vbmeta_addr)
        return;

    NOP(load_and_verify_vbmeta_addr, 2);
    PATCH_MEM(load_and_verify_vbmeta_addr + 0x72, 0x2301);
}

static void __attribute__((naked)) optional_vbmeta_bypass_hook(void) {
    asm volatile(
        "push {r0-r3, r12, lr}\n"
        "bl apply_optional_vbmeta_bypass\n"
        "pop {r0-r3, r12, lr}\n"
        "movw ip, #:lower16:vbmeta_bypass_cont\n"
        "movt ip, #:upper16:vbmeta_bypass_cont\n"
        "ldr ip, [ip]\n"
        "bx ip\n"
    );
}

void board_early_init(void) {
    printf("Entering early init for Redmi 13C (gale)\n");

    uint32_t root_of_trust_lock_state_call = SEARCH_PATTERN(
        LK_START, LK_END,
        0x2800, 0xF040, 0x808C, 0x4620,
        0xF44F, 0x7180, 0x4632, 0xF052,
        0xFB1B, 0x2800, 0xD17A, 0x4640,
        0xF04C, 0xFE02, 0x2800, 0xD16C);
    uint32_t vfy_policy_addr = SEARCH_PATTERN(
        LK_START, LK_END, 0xB508, 0xF7FF, 0xFF63, 0xF3C0);
    uint32_t dl_policy_addr = SEARCH_PATTERN(
        LK_START, LK_END, 0xB508, 0xF7FF, 0xFF5D, 0xF000);
    uint32_t avb_allow_error_addr = SEARCH_PATTERN(
        LK_START, LK_END, 0xF005, 0x0301, 0xF083,
        0x0A01, 0x930D, 0x9B70);
    uint32_t vbmeta_addr = SEARCH_PATTERN(
        LK_START, LK_END, 0xF47F, 0xAE6B, 0xE688, 0xF8DD);
    uint32_t platform_init_hook_base = SEARCH_PATTERN(
        LK_START, LK_END, 0x2200, 0x2300, 0xE966, 0x2302);
    uint32_t cmdline_pre_process_addr = SEARCH_PATTERN(
        LK_START, LK_END, 0xE92D, 0x47F0, 0xF7FF, 0xFFA6);

    if (!root_of_trust_lock_state_call || !vfy_policy_addr ||
        !dl_policy_addr || !avb_allow_error_addr || !vbmeta_addr ||
        !platform_init_hook_base || !cmdline_pre_process_addr) {
        printf("ERROR: Required Gale patch anchor not found.\n");
        return;
    }

    printf("Found get_vfy_policy at 0x%08X\n", vfy_policy_addr);
    FORCE_RETURN(vfy_policy_addr, 0);

    printf("Found get_dl_policy at 0x%08X\n", dl_policy_addr);
    FORCE_RETURN(dl_policy_addr, 0);

    printf("Found avb_slot_verify allow-error gate at 0x%08X\n",
           avb_allow_error_addr);
    PATCH_MEM(avb_allow_error_addr, 0xF04F, 0x0301);

    load_and_verify_vbmeta_addr = vbmeta_addr;
    printf("Found load_and_verify_vbmeta at 0x%08X\n",
           load_and_verify_vbmeta_addr);
    PATCH_MEM(load_and_verify_vbmeta_addr - 0x32C, 0x429B);

    uint32_t hook_addr = platform_init_hook_base + 8;
    printf("Found platform_init env ready point at 0x%08X, hooking...\n",
           hook_addr);
    vbmeta_bypass_cont = DECODE_BL_TARGET(hook_addr) | 1;
    PATCH_CALL(hook_addr, (void *)optional_vbmeta_bypass_hook, TARGET_THUMB);

    printf("Found cmdline_pre_process at 0x%08X\n", cmdline_pre_process_addr);
    cmdline_pre_process_cont = (cmdline_pre_process_addr + 4) | 1;
    PATCH_BRANCH(cmdline_pre_process_addr, (void *)cmdline_pre_process_hook);

    printf("Found root-of-trust lock-state call at 0x%08X\n",
           root_of_trust_lock_state_call + 24);
    PATCH_CALL(root_of_trust_lock_state_call + 24,
               (void *)get_root_of_trust_lock_state, TARGET_THUMB);

    fastboot_register("oem bldr_spoof", cmd_spoof_bootloader_lock, 0);
}

void board_late_init(void) {
    uint32_t addr;

    printf("Entering late init for Redmi 13C (gale)\n");
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB530, 0xB083, 0xAB02, 0x2200);
    if (addr) {
        printf("Found dm_verity_corruption at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    video_printf("\n[KAERU] Loaded on Redmi 13C (gale)!\n");
    if (is_spoofing_enabled())
        video_printf("[KAERU] Normal Android boot state spoofed; fastboot/recovery unchanged.\n");
    else
        video_printf("[KAERU] Bootloader spoofing is disabled.\n");
}
