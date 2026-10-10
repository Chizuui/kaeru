# Redmi 13C (`gale`) — Porting Notes

Reference document for the `gale` port: how every offset in
`configs/xiaomi/gale_defconfig` and every signature in `board/xiaomi/board-gale.c`
was obtained, and what is still missing.

> [!CAUTION]
> Read the [kaeru wiki](https://github.com/R0rt1z2/kaeru/wiki) before flashing
> anything. Modifying a bootloader can permanently brick the device. These notes
> describe a port that is still being validated on hardware; offsets are derived from
> this device's own image, and the warning-suppression patch has been confirmed on
> hardware by a collaborator rather than by this repository. See
> [Not yet implemented](#not-yet-implemented) for the parts that are known incomplete.

## Device

| | |
|---|---|
| Codename | `gale` |
| Model | Redmi 13C |
| SoC | MediaTek MT6768 (from the DTB root compatible `mediatek,MT6768`) |
| Bootloader | ARMv7 Little Kernel, 32-bit, little-endian |
| LK load address | `0x4C400000` |
| LK size | `0x173C00` |
| Analysis image | `lk.img`, 1658768 bytes, loaded at file offset `0x200` |

The LK image contains six partitions: `lk`, `cert1`, `cert2`, `lk_main_dtb`,
`cert1`, `cert2`. The `lk` partition itself spans `0x0`–`0x173C00`.

## The load base, and a `get_load_addr()` quirk that does *not* fire

`utils/parse.py` finds the load address by scanning forward from file offset `0x200`
for `10 ff 2f e1` (`bx r0`) and then reading the following word. On this image the
first such instruction is at file offset `0x26C`, and the word right after it is
`0x4C400020` — which looks like the load address but is a data word inside LK.

`get_load_addr()` nevertheless returns the correct `0x4C400000`. Its last line is:

```python
return struct.unpack('<I', lk.read(4))[0] if lk.read(4) else None
```

Python evaluates the condition of a conditional expression first, so `lk.read(4)`
runs, discards its result and advances the cursor, and only then does the
`struct.unpack` read fire. Two reads happen, and the word that gets unpacked is the
one at **+8**, which is `0x4C400000`.

Confirmed empirically: running `utils/parse.py` against this image reproduces every
value in `configs/xiaomi/gale_defconfig` unchanged, with exactly one exception —
`FASTBOOT_OKAY_ADDRESS`, see [below](#fastboot_okay-is-mislabelled-by-parsepy).

The base is worth recording as verified three ways regardless:

1. **The LK descriptor.** At IDA EA `0x6C` sits
   `{ bx r0 ; 0x4C400020 ; 0x4C400000 ; 0x4C573C00 ; 0x4C400080 }`.
   `0x4C573C00 - 0x4C400000 == 0x173C00`, which is exactly the size word from the
   image header at offset `0x04`. So the pair is `{lk_base, lk_base + lk_size}`,
   making `0x4C400000` the base and `0x4C400020` a data address *inside* LK.
2. **A Thumb literal pool entry.** The `LDR.W`/`ADD R0, PC` pair at EA `0x39FA`/
   `0x3A00` loads `0x76E20` from the literal at EA `0x42A4` and adds the runtime
   PC. That resolves to `0x4C400000 + 0x7A824`, which is the address of the
   `"platform_init()\n"` string.
3. **Cross-check against `earth`.** `mtk_detect_key` lands 4 bytes from the same
   function on the MT6768 `earth` LK, which is the expected drift between two LK
   builds of the same platform.

A fourth confirmation came after the fact: the `dm_verity_corruption` signature
derived for `gale` (`B530 B083 AB02 2200`) turned out to be **byte-identical** to
the one `board-earth.c` already uses. That can only match if the base is correct.

> An earlier revision of these notes claimed `setup.sh` prints `0x4C400020` and that
> every address needs a `-0x20`. That was wrong — it came from reading
> `get_load_addr()`'s source without noticing the double `lk.read(4)`. Nothing needs
> adjusting.

## `fastboot_okay` is mislabelled by `parse.py`

`utils/parse.py` reports `CONFIG_FASTBOOT_OKAY=0x4C42B820` for this image. That is
**`fastboot_fail`**, and the defconfig overrides it.

The two functions compile to the same shape:

```
mov r1, r0 ; ldr r0, [pc, #8] ; add r0, pc ; b.w <emit>
```

and the only thing the signature distinguishes is the low byte of the branch
displacement (`0xBE` for okay, `0xBF` for fail). On this LK the branch is a `B.W`
rather than the `BL` those bytes were derived from, so that byte is just part of the
offset and the signature matches whichever function happens to fit — here, the wrong
one.

Which is which is settled by the string each one loads:

| Address | Loads | Callers | Function |
|---|---|---|---|
| `0x4C42BA00` | `"OKAY"` | 12, all success paths | `fastboot_okay` |
| `0x4C42B820` | `"FAIL"` | 36, including both fastboot refusal sites | `fastboot_fail` |

This one matters: `lib/fastboot/fastboot.c` calls
`(CONFIG_FASTBOOT_OKAY_ADDRESS | 1)` for **every** `fastboot_okay("")`, so with the
value `parse.py` produces, kaeru would answer `FAIL` to every successful fastboot
command.

## Address model

| | |
|---|---|
| File offset | `0x200` = start of the LK image |
| IDA EA | `file offset − 0x200` (IDA's loader already applies the `0x200` offset) |
| Runtime address | `IDA EA + 0x4C400000` |
| `LK_START` / `LK_END` | `0x4C400000` / `0x4C573C00` |
| BSS | starts at `LK_END`, so `CONFIG_BOOTMODE_ADDRESS` legitimately sits above it |

## Configuration

Every value below was verified against the image rather than copied from another
board. "Exact" means the address coincides with an IDA function start.

| Config | Value | Evidence |
|---|---|---|
| `BOOTLOADER_BASE` | `0x4C400000` | three proofs above |
| `BOOTLOADER_SIZE` | `0x173C00` | header word at `0x04` |
| `APP_ADDRESS` | `0x4C42A9F0` | `.apps` table row, exact |
| `PLATFORM_INIT_ADDRESS` | `0x4C4039DC` | `PUSH.W {R4-R11,LR}` + `"platform_init()\n"` |
| `INIT_STORAGE_CALLER` | `0x4C403A0C` | `BL init_storage` at +0x30 into `platform_init` |
| `BOOTMODE_ADDRESS` | `0x4C5765A4` | written by `fastboot_continue`, in BSS |
| `FASTBOOT_REGISTER` | `0x4C42B1F0` | exact |
| `FASTBOOT_PUBLISH` | `0x4C42B22C` | exact |
| `FASTBOOT_INFO` | `0x4C42B680` | exact |
| `FASTBOOT_OKAY` | `0x4C42BA00` | loads `"OKAY"`; `parse.py` gets this wrong, see [above](#fastboot_okay-is-mislabelled-by-parsepy) |
| `VIDEO_PRINTF` | `0x4C42DA1C` | exact |
| `MTK_DETECT_KEY` | `0x4C4054A8` | exact, −4 bytes from `earth` |
| `LK_LOG_STORE` | `0x4C455694` | exact |
| `THREAD_CREATE` | `0x4C4265C8` | exact |
| `THREAD_RESUME` | `0x4C4267DC` | exact |
| `MALLOC` | `0x4C4419E0` | exact |
| `FREE` | `0x4C441114` | exact |
| `DPRINTF` | `0x4C440CE4` | exact |
| `GET_ENV` | `0x4C45C4E8` | prints `"[%s]get_env %s from area %d\n"` |
| `SET_ENV` | `0x4C45C51E` | prints `"[%s]set_env %s %s\n"` |
| `RECOVERY_CMDLINE1` | `0x4C516380` | `"…verifiedbootstate=orange"` |
| `RECOVERY_CMDLINE2` | `0x4C5163F4` | `"…verifiedbootstate=green"` |
| `PLATFORM_INIT_CALLER` | `0x4C425E0C` | the `bl platform_init` in `bootstrap2`; hand-derived, see below |

### Why `app()` is not found by the usual method

The wiki suggests locating `app()` through the string `"starting app %s\n"`. On this
LK **that string is never referenced** — it survives in rodata but no instruction
points at it. `utils/parse.py` therefore fails to detect `app` for this device.

MediaTek also does not name the app `"app"`. LK keeps a table:

```c
struct apps { char *name; uint32_t entry; };
```

and on this device it holds exactly one row, at EA `0x122E9C`:

```
{ name = "mt_boot", entry = 0x4C42A9F1, terminator = 0 }
```

`CONFIG_APP_ADDRESS` is `entry & ~1` = `0x4C42A9F0`. The function loads
`"MTK_DEVICE_ID"` first, and the string `app/mt_boot/mt_boot.c` confirms the
identity.

## Board file

`board/xiaomi/board-gale.c` follows the approach of `board-earth.c`. All twelve
`SEARCH_PATTERN` signatures resolve to **exactly one hit** in this image, which was
verified before committing.

| Signature | Resolves to | Purpose |
|---|---|---|
| `B538 4B18 447B 681B` | `0x4C46FD04` | `sec_usbdl_enabled()` |
| `B510 B082 4C10 2304` | `0x4C473888` | lock-state adapter A |
| `B510 B082 4C11 2304` | `0x4C4738D8` | lock-state adapter B |
| `B530 4605 4917 B087` | `0x4C43C67C` | `seccfg_get_lock_state()` |
| `4B01 447B 6818 4770 3552` | `0x4C424F68` | `custom_get_lock_state()` |
| `000E E92D 4FF0 B087` | `0x4C42B82E` | fastboot command processor |
| `B508 4B11 447B 681B` | `0x4C454758` | `cmdline_pre_process()` |
| `F03D F8D5 6823 2000` | `0x4C403B36` | the `"ENV init"` printf |
| `B530 B083 AB02 2200` | `0x4C467F18` | `dm_verity_corruption()` |
| `E92D 4FF0 4691 F102` | `0x4C462260` | `avb_add_cmdline_options()` |
| `B508 F7FF FF63 F3C0` | `0x4C417B58` | `get_vfy_policy()` |
| `B508 F7FF FF5D F000` | `0x4C417B64` | `get_dl_policy()` |

The two policy signatures are the ones `board-earth.c` uses, and they each match once.
They are forced to return `0` unconditionally, as on `earth`: image authentication has
to be off for unsigned images to boot, and download policy has to be off because the
spoofed `locked` state would otherwise mark partitions as download-forbidden. Note
they land 12 bytes apart, which looks alarming until you check that the signatures are
`B508 F7FF FF63 F3C0` and `B508 F7FF FF5D F000` — different at the fourth halfword, and
non-overlapping.

### Identified LK internals

Two functions were identified from their own embedded strings:

- **`sec_usbdl_enabled` = `0x4C46FD04`** — it prints
  `"[%s] sec_usbdl_enabled -- invalid susbd"` and `"SEC_USBDL"`. kaeru already ships
  a stub returning `0` in `lib/spoof.c`.
- **Lock-state adapters** — `sub_73888` and `sub_738D8` both call
  `seccfg_get_lock_state()` and fall back to `custom_get_lock_state()`, printing
  `"get lock state fail"` when both fail. This is the wrapper earth describes in its
  comments.

`custom_get_lock_state` is only four instructions long, so its own bytes are not
unique (8 hits). The signature is extended with a fifth halfword to pin it to one.

### `PATCH_ALL_BL` instead of fixed call sites

`board-earth.c` patches a single hardcoded call site per lock-state getter. On this
LK each of the two adapters calls *both* getters, so a single-site patch would leave
one path reporting the real state. `board-gale.c` uses
`PATCH_ALL_BL(func, size, orig, hook)` from `include/arch/arm.h` instead, which
rewrites every `BL` inside the function that targets `orig`.

### Fastboot processor offsets

Measured from the entry at `0x4C42B82E`:

| Offset | Address | Instruction | Action |
|---|---|---|---|
| `+0x12A` | `0x4C42B958` | `BL sec_usbdl_enabled` | replaced with `b +0x2E` (`0xE017`) to reach the dispatch at `+0x15C` |
| `+0x170` | `0x4C42B99E` | `BL fastboot_fail` — `"not support on security"` | NOP |
| `+0x17C` | `0x4C42B9AA` | `BL fastboot_fail` — `"not allowed in locked state"` | NOP |

These are **not** the offsets `earth` uses (`+0x19A`, `+0x22A`, `+0x23E`, `+0x24A`);
they were re-derived from this image.

## Recovery and fastboot are deliberately not spoofed

The lock state is forced to `"locked"` so the TEE, attestation and Play Integrity see
a locked device. That would normally break two things, and both are handled
explicitly:

- **Recovery.** `cmdline_pre_process()` (`0x4C454758`) is hooked to
  `handle_recovery_boot()` from `lib/recovery.c`. When the boot mode is
  `BOOTMODE_RECOVERY` and spoofing is on, it rewrites `androidboot.verifiedbootstate`
  from `green` back to `orange` in both cmdline templates, so `adbd` and `fastbootd`
  still function. `vbmeta.device_state` is deliberately left alone — rewriting it to
  `unlocked` hangs recovery on some devices.
- **Fastboot.** The two refusal messages and the security gate are removed, so
  fastboot commands keep working even though the spoofed state reads `locked`. The
  `oem bldr_spoof` command itself is registered with `allowed_when_security_on = 1`;
  see [below](#the-bldr_spoof-command-needs-allowed_when_security_on-1).

### The `bldr_spoof` command needs `allowed_when_security_on = 1`

The last argument to `FASTBOOT_CMD` is not "requires unlock" — it is LK's
`allowed_when_security_on`, passed straight through by `fastboot_register()`. With it
at `0`, LK's dispatcher takes this path at `0x4C42B994`:

```
0x4C42B994  ldr  r3, [r7, #0xc]   ; cmd->allowed_when_security_on
0x4C42B996  cmp  r3, #0
0x4C42B998  bne  0x4C42B962        ; flag set -> run the handler
0x4C42B99A  ldr  r0, ="not support on security"
0x4C42B99E  bl   fastboot_fail     ; NOPped by board-gale.c, so silent
0x4C42B9A2  ldr  r4, [r5]
0x4C42B9A4  b    0x4C42B89A        ; loop continue - the command never runs
```

`r7` is the command pointer and `0x4C42B962` is the handler, so this is confirmed
against the image rather than inferred. Note that NOPping `fastboot_fail` only
suppresses the message; the command is still skipped. Setting the flag to `1` takes the
`bne`, and it also makes the dispatcher's second gate — `ldr r3, [r7, #0x10]`,
`forbidden_when_lock_on` — reachable at all, since that one is only evaluated once
`allowed_when_security_on` has passed.

`board-merlin.c` already uses `1`; `board-earth.c` uses `0`.

Without the fastboot patch, spoofing alone makes fastboot reject commands with
*"not support on security"* and *"not allowed in locked state"* on a device that is
really unlocked underneath.

## `PLATFORM_INIT_CALLER` had to be derived by hand

`utils/parse.py` cannot produce this value on `gale`, but the caller exists.

`parse.py` looks for the anchor `bootstrap2` and then searches the 256 bytes after
it for a `bl`/`blx` aimed at `platform_init` (`find_caller`). Neither of its
`bootstrap2` patterns

```
48 XX 10 b5 78 44 XX f0 XX XX XX 4b
08 b5 ff f7 38 ea df f7 e3 fb
```

occurs anywhere in this image — zero hits each. Since the lookup is guarded by
`if 'bootstrap2' in offsets and 'platform_init' in offsets`, `parse.py` never even
attempts it, and no `CONFIG_PLATFORM_INIT_CALLER` line is emitted.

The instruction it is looking for is present. `bootstrap2` in this build is:

```c
dprintf("initializing target\n");     // string at EA 0x499F78
platform_init(args);                  // BL at 0x4C425E0C  <-- the hook
dprintf("calling apps_init()\n");     // string at EA 0x499F90
apps_init(args);
```

Both strings are referenced from this function, which is what pins the
identification rather than guesswork. Recovering it required hand-decoding the
region, because IDA classifies those bytes as data and Capstone's linear sweep
misreads them. The identification was then confirmed against already-known config
addresses: the decompiled body calls `0x4C4039DC` (`CONFIG_PLATFORM_INIT_ADDRESS`)
and `0x4C440CE4` (`CONFIG_DPRINTF_ADDRESS`), and the two `dprintf` literals resolve
to `0x499F78` and `0x499F90`.

To prove the `bl` is the only one, every Thumb-2 `BL`/`BLX` in `[0, 0x79388)` was
decoded with a hand-written decoder over 2-byte-aligned offsets — 13205 calls, with
a sane target histogram — giving exactly one call to `0x4C4039DC` and none to any
other address in `0x39C0`–`0x3A40`.

### Why the rewrite is safe here

`0x4C425E0C` is the *first* instruction of the function, and `patch.py` replaces
exactly those 4 bytes, so the instruction stream stays consistent and `LR` still
points at `0x4C425E10`. stage1's `main()` returns normally, execution resumes at
`0x4C425E10`, and `dprintf("calling apps_init()")` plus `apps_init()` still run.

The skipped `platform_init()` call is not lost: `kaeru_early_init()` invokes the
real one through `CONFIG_PLATFORM_INIT_ADDRESS` before returning (`main/main.c`), and
stage1 has already done `init_storage()` itself — which is why
`CONFIG_INIT_STORAGE_CALLER` is NOPed out on the way in.

## AVB device state in the kernel cmdline

`libavb` appends `androidboot.vbmeta.device_state=...` to the kernel cmdline, and on
this LK it keeps saying `"unlocked"` because the state it reads is the real one rather
than the spoofed one. `board-gale.c` forces the `"locked"` string.

The function is `avb_add_cmdline_options()` at `0x4C462260`, found with the same
signature `board-earth.c` uses (`E92D 4FF0 4691 F102`, one hit). IDA has it as
`sub_62260`, called from `sub_65E0E`, and its strings confirm the identity:
`"androidboot.vbmeta.device_state"` sits right next to the `locked`/`unlocked` pair.

The pick between the two strings is a single `CBNZ`:

```
0x4C462300  LDR   R3, [SP,#0x24]    ; device state libavb just fetched
0x4C462302  CBNZ  R3, 0x4C462354   ; non-zero -> "unlocked"
0x4C462304  LDR   R2, ="locked"
0x4C462308  LDR   R1, ="androidboot.vbmeta.device_state"
0x4C46230E  BL    append_option    ; append "...device_state=locked"
...
0x4C462354  LDR   R2, ="unlocked"
```

So `NOP(addr + 0xA2, 1)` forces the fallthrough and the cmdline always claims locked.

Two things differ from `earth`, and both matter:

- **The offset is `+0xA2`, not `+0x9C`.** On this build `+0x9C` holds
  `BEQ loc_622E8`, which is libavb's `if (state == 1) return 1;` error check.
  Copying earth's offset would disable error handling and change nothing about the
  device state.
- **Only one halfword is NOPed.** `NOP(addr, n)` writes `n` halfwords, and the
  instruction immediately after the `CBNZ` is the literal load for `"locked"`. A
  two-halfword NOP would eat it and leave `r2` holding garbage.

This patch is gated behind the spoof being enabled, so disabling the spoof leaves the
cmdline reporting the real state.

### Partition API

`gale` sets `CONFIG_USE_LEGACY_PARTITION_API=y`, the same mode `amazon`'s `austin` and
`ford` use. The default mode does not work here: it calls
`partition_read(part, offset, buf, size)` as AAPCS `(r0, r1:r2, r3, [sp])`, and this LK
has no such function. Its primitive at `0x4C45DC8C` takes
`(r0=name, r1=?, r2:r3=offset, [sp]=buf, [sp+4]=size)`, pinned by `set_env`'s own call
into the write twin: `sub_5DDD8("env", 0x4000, 0x20000, buf, 0x4000)`. The buffer lands
in a different register, so reusing it would make stage1 read out of bounds.

Everything in `partition.c` was identified:

| Address | Role | Evidence |
|---|---|---|
| `0x4C45C120` | name → index | `strcmp` loop, stride `0x30`, four name slots per entry at `+0x0 +0xC +0x18 +0x24` |
| `0x4C45C1C4` | name → size | `bl 0x4C45C120 ; pop.w {r3,lr} ; b.w 0x4C45BBEC` — a tail call, not a return |
| `0x4C45C1D4` | name → offset | tail-calls `0x4C45BB90` |
| `0x4C45C1E4` | "not found" | `index == -1` via `clz`/`lsr` |
| `0x4C45C1F8` | name → blockdev | tail-calls `0x4C45BB0C` |
| `0x4C45BB0C` | index → part | `index <= 0x7F ? table[index] : -1`, stride `0x20` |
| `0x4C45BB90` | index → offset | via `0x4C4696B8` |
| `0x4C45BBEC` | index → size | block size × sector count, `-1` on failure |
| `0x4C45DC8C` | read, 5 args | not usable as `partition_read` |
| `0x4C45DDD8` | write, 5 args | sets the 5-arg shape |
| `0x4C4696B8` | `mt_part_get_device()` | returns the device, lazily initialising it |

Enabling this mode required `struct device_t` to match `include/lib/mt_part.h`, since
stage1 calls `dev->read()` through it. Verified field by field:

| Offset | Field | Evidence |
|---|---|---|
| `+0x00` | `init` | `0x4C4696B8` writes `1` here after calling `init_dev` |
| `+0x04` | `id` | loaded and passed as `init_dev`'s argument |
| `+0x08` | `blkdev` | `0x4C4696DC` / `0x4C4696EC` dereference `[dev+8]` then `[+0x14]`/`[+0x18]` |
| `+0x0C` | `init_dev` | `ldr r3,[r0,#0xc] ; blx r3` |
| `+0x10` | `read` | `0x4C4696FC`: `ldr r1,[r0,#0x10] ; blx r1` |
| `+0x14` | `write` | `0x4C469764`: `ldr r4,[r0,#0x14] ; blx r4` |

`dev->read()`'s last argument is the partition type and stage1 passes `USER_PART` (8).
`gale` is eMMC — 93 `mmc` references in the image against 2 for `ufs` — so that is the
right selector rather than a UFS LUN.

## Removing the unlock warning

Two separate things are going on, and only one of them is the warning.

The spoof makes `fastboot getvar unlocked` report `no` and the OS report `unlocked`. The
orange splash is a third thing: LK reads the same boot-state global that feeds the
`androidboot.verifiedbootstate=` value and draws a warning screen from it. Forcing the
cmdline value green does not touch the screen, and vice versa.

Three sites were tried, in order, and the lesson is that the dispatch point is the only
one that works:

| Patch | Address | Result |
|---|---|---|
| pin state in `cmdline_pre_process` | `0x4C454762` | kernel told `green`, screen unchanged |
| pin state in the boot-state printer | `0x4C454552` | log line renamed, screen unchanged |
| stub the Orange State screen | `0x4C4545D4` | plausible, never confirmed |
| **force `orange_state_warning` to return 0** | `0x4C4546F4` | **confirmed on hardware** |

The first two fail for the same reason. `cmdline_pre_process` and the boot-state printer
share a prologue, `B508 4B11 447B 681B` and `B508 4B1C 447B 681B`, one hit each, differing
only in the second halfword. Both switch on the boot state and both have their `cmp r3, #3`
at `+0x0A`, which is what the two halfword patch rewrites. But the printer always returns
`0` from every one of its arms, including the orange one, so its caller at `0x4C46831C`
takes `cbz r0` unconditionally. The `0x10007000` boot-state code that caller carries is
dead on this path, and pinning the state only renames the log line.

The screen at `0x4C4545D4` has no `BL` caller anywhere in the payload, which is why the
caller cannot be found by scanning for callers. It is not called, it is tail-called:

```
0x4C4546FE  02 2B        cmp   r3, #2
0x4C454700  0B D0        beq   0x4C45471A
0x4C454702  03 2B        cmp   r3, #3
0x4C454704  03 D0        beq   0x4C45470E
0x4C454706  01 2B        cmp   r3, #1
0x4C454708  01 D0        beq   0x4C45470E
0x4C45470A  00 20        movs  r0, #0
0x4C45470C  08 BD        pop   {r3, pc}
0x4C45471A  BD E8 08 40  pop.w {r3, lr}
0x4C45471E  FF F7 59 BF  b.w   0x4C4545D4     ; Orange State screen + 5s delay
```

`orange_state_warning()` at `0x4C4546F4` is the dispatcher, and `b.w` at `+0x2A` is the
tail call into the screen. Forcing it to return `0` skips the state dispatch entirely, so
orange, yellow and red are all bypassed at one point, and it sits above the two functions
whose patches did nothing.

It is found by the third prologue in the group, `B508 4B0E 447B`, again one hit. The three
signatures cannot collide, since the second halfword differs.

Credit: `wulan17`, commit [`0a7ed94`](https://github.com/wulan17/kaeru/commit/0a7ed9481fb4fdbc5377716be8be48eb8ef849e8)
in his fork, confirmed on hardware. The screen stub that briefly lived here in `6dd8840`
has been removed, since it was superseded and never confirmed.

## Accepting any vbmeta signing key

The lock spoof reports the device as locked, and a locked device treats a vbmeta signed
with an unrecognised key as fatal. That is where the observed `invalid pubk size` and
`vbmeta_a : Public key used to sign data rejected` come from, and it happens before the
board file's other AVB work matters. `board-gale.c` forces the key to be accepted.

`load_and_verify_vbmeta()` is reached through a pointer, not called directly, so it is
matched mid-function. The match sits at `0x4C464CF8`, inside a function whose entry is at
`0x4C462708`, so the offset from entry is `+0x25F0`.

The obvious move is to reuse `board-earth.c`'s signature verbatim. **It does not match.**
`earth` searches `F47F AE71 E68D F8DD`; this image holds `F47F AE6B E688 F8DD`. The two
differing halfwords are branch immediates:

```
0x4C464CF8  7F F4 6B AE   bne.w  #0x4C4649D2
0x4C464CFC  88 E6        b      #0x4C464A10
```

Same instruction shapes, different branch targets. Searching for `earth`'s exact four
halfwords returns zero hits, which is why this function was previously recorded as absent
from `gale`. A search built from this image's own bytes, `F47F AE6B E688 F8DD`, returns
exactly one hit.

`board-fire.c` (Redmi 12 4G) turns out to use that same signature and the same `+0x72`, so
`fire` and `gale` share an AVB layout while `earth` and `ruby` do not. That is what made
the third offset findable:

| Offset | Board | Address here | Instruction |
|---|---|---|---|
| `-0x320` | `earth`, `ruby` | `0x4C4649D8` | `lsrs` — not a comparison |
| `-0x32C` | `fire` | `0x4C4649CC` | `cmp r2, r3` — the real check |

Copying `earth`'s `-0x320` would write a compare over an unrelated shift instruction. The
three patches are:

| Offset | Bytes | Instruction | Patch |
|---|---|---|---|
| `-0x32C` | `9A 42` (`0x429A`) | `cmp r2, r3` | `PATCH_MEM(,0x451B)` |
| `+0x00` | `7F F4 6B AE` | `bne.w #0x4C4649D2` | `NOP(,2)` |
| `+0x72` | `00 2B` (`0x2B00`) | `cmp r3, #0` | `PATCH_MEM(,0x2301)` |

`0x451B` is `cmp r3, r3`, always equal, which is what the chained-key length check needs.
It is followed by a `beq.w` that skips the error, so forcing it equal always lands on the
accepted path:

```
0x4C4649CC  9A 42        cmp   r2, r3       <- -0x32C, chained-key length check
0x4C4649CE  00 F0 8C 81  beq.w 0x4C464CEA   ; equal -> skip error
0x4C4649D2  DF F8 84 09  ldr.w r0, [pc, #0x984]
0x4C4649D6  4F F0 05 09  mov.w sb, #5
0x4C4649DC  01 F0 A8 FF  bl    0x4C466930
```

`+0x00` is NOPped, so the unconditional `b` at `+0x04` is always taken. `+0x72` is the
`key_is_trusted` test, immediately followed by `bne.w`, and rewriting it as
`movs r3, #1` makes the branch take the accepted path:

```
0x4C464D5A  01 2C        cmp   r4, #1
0x4C464D5C  00 F0 8C 82  beq.w 0x4C465278
0x4C464D60  00 2C        cmp   r4, #0
0x4C464D62  40 F0 92 82  bne.w 0x4C46528A
0x4C464D66  DC F8 00 30  ldr.w r3, [ip]
0x4C464D6A  00 2B        cmp   r3, #0        <- +0x72
0x4C464D6C  7F F4 50 AE  bne.w 0x4C464A10    <- accepted path
```

`earth`'s third patch, at `-0x32C`, rewrites a chained-key length check. It is **not**
applied here: that offset in this build holds a different comparison, and there is no
`cmp r2, r3` anywhere near the function to anchor a replacement. Leaving it out is
deliberate, since a wrong guess at a length check corrupts the parse rather than
loosening it.

## Modem firmware image verification

Modem images (`md1rom`, `md3rom`) are verified by their own path rather than through
`get_vfy_policy`. `ccci_ld_md_sec_ptr_hdr_verify` sits at `0x4C458438`, matched by
`E92D 41F0 460A 4604`, one hit, the same signature `board-merlin.c` and `board-ruby.c`
use.

It is genuinely a separate path: the function calls `0x4C417AE0`, whereas `get_vfy_policy`
resolves to `0x4C417B58`. Forcing `get_vfy_policy` to 0 does not reach it, so a modified
modem image still fails to load without this patch.

The modem currently loads fine on stock firmware and the logs show no verification
failure, so this is for robustness rather than to fix an observed problem. `merlin` and
`ruby` both carry it.

## Letting AVB tolerate verification errors

Once the spoof reports the device as locked, `avb_slot_verify` treats a rejected key, a
hash mismatch or a bad rollback index as fatal, and the boot stops. That shows up in the
log as:

```
avb_slot_verify.c : ERROR: vbmeta_a : Public key used to sign data rejected.
avb_slot_verify.c : ERROR: boot_a   : Hash of data does not match digest in descriptor.
```

`avb_slot_verify` has a gate that turns those into recoverable errors, the same mode it
already uses when a device is genuinely unlocked. On `gale` it is at `0x4C465E5A`, matched
by `F005 0301 F083 0A01 930D 9B70`, one hit:

```
0x4C465E5A  and   r3, r5, #1     ; r3 = allow_verification_error
0x4C465E5E  eor   sl, r3, #1
0x4C465E62  str   r3, [sp, #0x34]
0x4C465E64  ldr   r3, [sp, #0x1C0]
0x4C465E66  cmp   r3, #3
0x4C465E68  ite   ne
0x4C465E6A  movne r3, #0
0x4C465E6C  andeq r3, sl, #1
0x4C465E70  cbz   r3, 0x4C465E7E ; continue; otherwise falls through to
0x4C465E72  mov.w r0, #8          ; AVB_RESULT_ERROR_VERIFICATION
```

`PATCH_MEM(addr, 0xF04F, 0x0301)` replaces the `and` with `mov.w r3, #1`. Both halfwords
are written because the original is a 4-byte Thumb instruction. The `eor` then produces
`sl = 0`, so the `cbz` is always taken and error 8 is never returned.

This is `board-merlin.c`'s patch, re-derived against this image rather than assumed; the
signature, the disassembly and the post-patch encoding were all checked here. It was in
`1547fae` and reverted in `ff57e13` on the assumption that patching
`load_and_verify_vbmeta` was sufficient. Both are now applied, because they catch
different failures in different places and neither has been confirmed on this device.

Structurally invalid vbmeta is still rejected; `get_vfy_policy` above is what ungates the
boot in that case.

## Not yet implemented

- **AVB device state published to fastboot.** Separate from the cmdline above. The
  function is `0x4C42BEC0` (it starts by printing `"fastboot_init()\n"`). The
  device-state decision calls the two lock-state adapters at `0x4C42C376` and
  `0x4C42C382` and uses the results as indices into a table when publishing
  `"secure"` (`0x4C42C3AC`) and `"unlocked"` (`0x4C42C3BA`) via `fastboot_publish`.
  The control flow is mapped, but a patch has not been chosen, because forcing this
  incorrectly is worse than leaving it alone.
- **SoC-dependent base addresses.** `CONFIG_MEDIATEK_MT6768` is set, which selects the
  UART, watchdog and SEJ bases in `soc/Kconfig`.

## Build

```bash
make gale_defconfig
make -j"$(nproc)"
python3 utils/patch.py configs/xiaomi/gale_defconfig lk.img kaeru -l stageone -o gale-kaeru.bin
```

Or simply `./build.sh gale lk.img`.

## Reproducing the analysis

Addresses were derived with IDA Pro against `lk.img` loaded at file offset `0x200`
with image base `0`. Two things make this LK awkward to analyse and are worth
recording:

- **IDA cannot build string cross-references.** LK references its own strings with
  the idiom `LDR.W Rx, [PC, #imm]` followed by `ADD Rx, PC`, where the literal pool
  holds `target − comp` rather than `target`. IDA *does* annotate these as
  `LDR.W R0, =(aString - 0xNNNN)`, so the reliable technique is to parse that
  annotation, resolve the symbol name with `ida_name.get_name_ea()`, and match it
  against the string you care about. A single linear sweep over the listing resolves
  6149 references this way.
- **IDA leaves roughly 10% of the image as data**, including the region around
  `0x4C425E0C` that contains `bootstrap2`. Neither IDA's code/data classification nor
  a linear Capstone sweep can be trusted there: Capstone happily decodes data as
  instructions and invents branches — one such phantom `ldr` appeared in the `.apps`
  area, and a phantom hit in this same region was at first mistaken for "platform_init
  has no caller". Both tools are wrong in *both* directions here. The reliable
  approach is to decode each candidate offset independently with a hand-written
  decoder, then validate every callee against an address already known from the
  config. Doing exactly that is what produced `PLATFORM_INIT_CALLER`.
