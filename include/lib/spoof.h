//
// SPDX-FileCopyrightText: 2026 R0rt1z2 <roger@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include <lib/string.h>
#include <lib/environment.h>
#include <lib/security/seccfg.h>
#include <lib/fastboot.h>

int is_spoofing_enabled(void);
int get_lock_state(uint32_t *lock_state);
int sec_usbdl_enabled(void);
unsigned int seclib_sec_boot_enabled(unsigned int);
unsigned get_unlocked_status(void);
void cmd_spoof_bootloader_lock(const char *arg, void *data, unsigned sz);

// Which parts of the spoof to apply. Stored as a bitmask so a single build can be
// narrowed down from fastboot without rebuilding for each combination.
//
//   SPOOF_MASK_VBMETA_KEY    load_and_verify_vbmeta
//   SPOOF_MASK_AVB_CMDLINE   androidboot.vbmeta.device_state
//   SPOOF_MASK_CMDLINE_HOOK  handle_recovery_boot call
//   SPOOF_MASK_CMDLINE_GREEN verifiedbootstate pin
//   SPOOF_MASK_STATE_SHOW    boot state display pin
//   SPOOF_MASK_ORANGE_SCREEN orange_state_warning
//
// Unset means all of them, which is what every release should default to.
#define SPOOF_MASK_VBMETA_KEY    0x01
#define SPOOF_MASK_AVB_CMDLINE   0x02
#define SPOOF_MASK_CMDLINE_HOOK  0x04
#define SPOOF_MASK_CMDLINE_GREEN 0x08
#define SPOOF_MASK_STATE_SHOW    0x10
#define SPOOF_MASK_ORANGE_SCREEN 0x20
#define SPOOF_MASK_ALL           0x3F

// Non-zero when every bit in mask is enabled for this boot.
int spoof_group_enabled(unsigned int mask);
// Published as "spoof-mask" so fastboot getvar can report the active set.
void spoof_publish_mask(void);
void cmd_spoof_patch_mask(const char *arg, void *data, unsigned sz);