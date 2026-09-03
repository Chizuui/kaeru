//
// SPDX-FileCopyrightText: 2025-2026 Roger Ortiz <roger@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <arch/arm.h>
#include <board_ops.h>
#include <main/main.h>

uint32_t kaeru_reloc_delta;

void kaeru_late_init(void) {
    OPTIONAL_INIT(framebuffer_init);
    OPTIONAL_INIT(storage_init);

    board_late_init();

    ((void (*)(const struct app_descriptor*))(CONFIG_APP_ADDRESS | 1))(NULL);
}

static int redirect_direct_app_calls(void) {
#ifdef CONFIG_XIAOMI_GALE
    uint32_t app_call = SEARCH_PATTERN(
        CONFIG_BOOTLOADER_BASE,
        CONFIG_BOOTLOADER_BASE + CONFIG_BOOTLOADER_SIZE,
        0xF7FF, 0xFBE2, 0x2000, 0x4C61);

    if (!app_call || (DECODE_BL_TARGET(app_call) & ~1) != CONFIG_APP_ADDRESS) {
        printf("ERROR: Gale app() call anchor not found.\n");
        return 0;
    }

    PATCH_CALL(app_call, (void *)kaeru_late_init, TARGET_THUMB);
    printf("Redirected Gale app() call at 0x%08X to kaeru_late_init\n", app_call);
    return 1;
#else
    uint32_t start = CONFIG_BOOTLOADER_BASE;
    uint32_t end = CONFIG_BOOTLOADER_BASE + CONFIG_BOOTLOADER_SIZE;
    uint32_t app_addr = CONFIG_APP_ADDRESS & ~1;
    int count = 0;

    for (uint32_t addr = start; addr < end - 2; addr += 2) {
        uint16_t hi = *(volatile uint16_t *)addr;
        uint16_t lo = *(volatile uint16_t *)(addr + 2);

        if ((hi & 0xF800) != 0xF000 || (lo & 0xD000) != 0xD000)
            continue;
        if ((DECODE_BL_TARGET(addr) & ~1) != app_addr)
            continue;

        PATCH_CALL(addr, (void *)kaeru_late_init, TARGET_THUMB);
        printf("Redirected app() call at 0x%08X to kaeru_late_init\n", addr);
        count++;
    }

    return count;
#endif
}

void kaeru_early_init(void) {
    OPTIONAL_INIT(sej_init);

    uint32_t search_val = CONFIG_APP_ADDRESS | 1;
    uint32_t start = CONFIG_BOOTLOADER_BASE;
    uint32_t end = CONFIG_BOOTLOADER_BASE + CONFIG_BOOTLOADER_SIZE;
    uint32_t ptr_addr = 0;

    print_kaeru_info(printf);
    common_early_init();
    board_early_init();

    for (uint32_t addr = start; addr < end; addr += 4) {
        if (*(volatile uint32_t*)addr == search_val) {
            ptr_addr = addr;
            break;
        }
    }

    if (ptr_addr != 0) {
        *(volatile uint32_t*)ptr_addr = (uint32_t)kaeru_late_init | 1;
        arch_clean_cache_range(ptr_addr, 4);
    } else if (redirect_direct_app_calls() > 0) {
        // No '.apps' table entry; Gale direct app() call was redirected.
    } else {
        printf("Failed to patch mt_init_boot() pointer\n");
        printf("kaeru won't be able to run its late init!\n");
    }

    ((void (*)(void))(CONFIG_PLATFORM_INIT_ADDRESS | 1))();
}
