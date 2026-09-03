# Redmi 13C（gale）移植

**语言：** [English](./gale.md) | [Bahasa Indonesia](./gale_id-ID.md) | [简体中文](./gale_zh-CN.md)

## 范围

此移植仅支持满足以下全部条件的 Redmi 13C（`gale`）MediaTek MT6768 LK：

```text
LK base: 0x4C400000
LK size: 0x173C00
SHA-256: 6a629f8e1bf8f605ab64e50e8af30346003590dc3cc111deb339dfb2cca68351
```

`utils/patch.py` 会在修改前拒绝其他 LK 修订版。不要为 OTA LK 删除或修改此 gate；应先重新审计该二进制文件。

## 构建

Debian/Ubuntu 依赖：

```sh
sudo apt-get update
sudo apt-get install gcc-arm-linux-gnueabihf python3 python3-pip git make
```

使用完全匹配的原厂 LK 构建：

```sh
./build.sh gale /path/to/lk.img
```

预检输出应包含 LK base、LK size、platform-init caller、payload destination；当 `CONFIG_CERT_BYPASS=y` 时，还应显示已重新签名的 `lk` 分区。

不要在源码验证阶段刷写。进行设备测试前，保留原始 LK 和恢复路径。

## 行为

Spoofing 默认关闭，需通过 fastboot 启用：

```sh
fastboot oem bldr_spoof on
fastboot oem bldr_spoof status
fastboot oem bldr_spoof off
```

启用后，正常 Android 启动（`BOOTMODE_NORMAL = 0`）会重写 Android boot argument，呈现：

```text
androidboot.verifiedbootstate=green
androidboot.secureboot=1
androidboot.vbmeta.device_state=locked
root-of-trust lock state=1
```

Recovery、fastboot 和未知模式不会被全局强制为 locked。此移植不 hook 共享 lock getter `sub_3C67C`，因为该 getter 被 policy、AVB、root-of-trust 和 fastboot 路径使用。

## 已审计 anchor

| 项目 | Runtime address | 证据 |
| --- | --- | --- |
| `CONFIG_PLATFORM_INIT_ADDRESS` | `0x4C4039DC` | 原厂 platform-init prologue。 |
| `CONFIG_PLATFORM_INIT_CALLER` | `0x4C425E0C` | 指向 platform init 的原厂 `BL`；被修改为 payload 入口。 |
| direct `app()` call | `0x4C42AC04` | 唯一的 direct `BL`，目标为 `CONFIG_APP_ADDRESS=0x4C42A3CC`。 |
| cmdline buffer | `0x4C579624` | 被原厂 cmdline producer/consumer 函数引用。 |
| `CONFIG_BOOTMODE_ADDRESS` | `0x4C5765A4` | `fastboot continue` 将 `BOOTMODE_NORMAL`（`0`）写入此处。 |

Gale 预检要求 board patch anchor 和 direct `app()` call anchor 都恰好匹配一次，同时检查 LK load address 和精确 LK image size。

## 静态分析边界

IDA 证据验证此源码移植针对指定原厂 LK 修订版。它不证明设备一定能启动、AVB/vbmeta 加密链有效、TEE 或 KeyMint attestation、Play Integrity 结果，或任何 Google server verdict。这些均需在目标硬件上进行受控 runtime 测试。
