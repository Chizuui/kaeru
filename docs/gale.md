# Redmi 13C (gale) port

**Language:** [English](./gale.md) | [Bahasa Indonesia](./gale_id-ID.md) | [简体中文](./gale_zh-CN.md)

## Scope

This port supports only Redmi 13C (`gale`) with MediaTek MT6768 LK matching all of:

```text
LK base: 0x4C400000
LK size: 0x173C00
SHA-256: 6a629f8e1bf8f605ab64e50e8af30346003590dc3cc111deb339dfb2cca68351
```

`utils/patch.py` rejects another LK revision before patching. Do not remove or change this gate for an OTA LK; re-audit that binary first.

## Build

Debian/Ubuntu dependencies:

```sh
sudo apt-get update
sudo apt-get install gcc-arm-linux-gnueabihf python3 python3-pip git make
```

Build against exact stock LK:

```sh
./build.sh gale /path/to/lk.img
```

Expected preflight output includes LK base, LK size, platform-init caller, payload destination, and a re-signed modified `lk` partition when `CONFIG_CERT_BYPASS=y`.

Do not flash as part of source validation. Keep original LK and a recovery path before any device test.

## Behavior

Spoofing stays disabled until enabled with fastboot:

```sh
fastboot oem bldr_spoof on
fastboot oem bldr_spoof status
fastboot oem bldr_spoof off
```

When enabled, normal Android boot (`BOOTMODE_NORMAL = 0`) rewrites Android boot arguments to present:

```text
androidboot.verifiedbootstate=green
androidboot.secureboot=1
androidboot.vbmeta.device_state=locked
root-of-trust lock state=1
```

Recovery, fastboot, and unknown modes are not globally forced locked. This port does not hook shared lock getter `sub_3C67C`, because that getter has consumers in policy, AVB, root-of-trust, and fastboot paths.

## Audited anchors

| Item | Runtime address | Evidence |
| --- | --- | --- |
| `CONFIG_PLATFORM_INIT_ADDRESS` | `0x4C4039DC` | Stock platform-init prologue. |
| `CONFIG_PLATFORM_INIT_CALLER` | `0x4C425E0C` | Stock `BL` to platform init; patched as payload entry. |
| direct `app()` call | `0x4C42AC04` | Unique direct `BL` to `CONFIG_APP_ADDRESS=0x4C42A3CC`. |
| cmdline buffer | `0x4C579624` | Referenced by stock cmdline producer/consumer functions. |
| `CONFIG_BOOTMODE_ADDRESS` | `0x4C5765A4` | `fastboot continue` stores `BOOTMODE_NORMAL` (`0`) here. |

Gale preflight requires exactly one match for board patch anchors and direct `app()` call anchor. It also checks LK load address and exact LK image size.

## Static-analysis boundary

IDA evidence validates this source port against stated stock LK revision. It does not prove device boot, valid AVB/vbmeta cryptographic chain, TEE or KeyMint attestation, Play Integrity result, or any Google server verdict. Those require controlled runtime testing on target hardware.
