# Redmi 13C (`gale`) — Porting Notes

Reference document for the `gale` port: how every offset in
`configs/xiaomi/gale_defconfig` and every signature in `board/xiaomi/board-gale.c`
was obtained, and what is still missing.

> [!CAUTION]
> Read the [kaeru wiki](https://github.com/R0rt1z2/kaeru/wiki) before flashing
> anything. Modifying a bootloader can permanently brick the device. These notes
> describe an **unverified** port: the offsets are derived from this device's own
> image, but no patched image has been built and booted yet, and two AVB-related
> patches listed under [Not yet implemented](#not-yet-implemented) are still
> missing.

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

## The load base is not what `utils/setup.py` reports

`utils/parse.py` determines the load address by scanning forward from file offset
`0x200` for the ARM instruction `e12fff10` (`bx r0`) and then reading the next word.
On this image that yields **`0x4C400020`, which is wrong**. Every address derived
that way is shifted by `+0x20`.

The real base is `0x4C400000`. Three independent proofs:

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

> When re-running `setup.sh` on this device, ignore the printed
> `CONFIG_BOOTLOADER_BASE` and use `0x4C400000`, subtracting `0x20` from every other
> address it reports.

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
| `FASTBOOT_OKAY` | `0x4C42B820` | exact |
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

`board/xiaomi/board-gale.c` follows the approach of `board-earth.c`. All nine
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
  fastboot commands keep working even though the spoofed state reads `locked`.

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

## Not yet implemented

- **AVB cmdline device state.** The function is `0x4C42BEC0` (it starts by printing
  `"fastboot_init()\n"`). The device-state decision calls the two lock-state adapters
  at `0x4C42C376` and `0x4C42C382` and uses the results as indices into a table when
  publishing `"secure"` (`0x4C42C3AC`) and `"unlocked"` (`0x4C42C3BA`) via
  `fastboot_publish`. The control flow is mapped, but a patch has not been chosen,
  because forcing this incorrectly is worse than leaving it alone.
- **`load_and_verify_vbmeta`.** `board-earth.c` patches three spots so any vbmeta
  public key is accepted. Not derived for `gale`. Consequence: on an
  SBC-enabled device the spoof may still hit *"Public key used to sign data
  rejected"*.
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
