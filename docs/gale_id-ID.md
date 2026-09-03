# Port Redmi 13C (gale)

**Bahasa:** [English](./gale.md) | [Bahasa Indonesia](./gale_id-ID.md) | [简体中文](./gale_zh-CN.md)

## Cakupan

Port ini hanya mendukung Redmi 13C (`gale`) dengan LK MediaTek MT6768 yang cocok dengan seluruh nilai berikut:

```text
LK base: 0x4C400000
LK size: 0x173C00
SHA-256: 6a629f8e1bf8f605ab64e50e8af30346003590dc3cc111deb339dfb2cca68351
```

`utils/patch.py` menolak revisi LK lain sebelum patch. Jangan hapus atau ubah gate ini untuk LK OTA; audit ulang binary tersebut dulu.

## Build

Dependensi Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install gcc-arm-linux-gnueabihf python3 python3-pip git make
```

Build dengan LK stok yang tepat:

```sh
./build.sh gale /path/to/lk.img
```

Output preflight harus memuat LK base, LK size, platform-init caller, payload destination, serta cert2 hash-override bypass untuk `lk` yang diubah saat `CONFIG_CERT_BYPASS=y`. Ini bukan tanda tangan valid dari vendor.

Jangan flash saat validasi source. Simpan LK asli dan jalur recovery sebelum pengujian perangkat.

## Verifikasi preloader

Preloader memuat partisi bernama sebelum menyerahkan kontrol ke LK. Untuk LK, IDA menelusuri:

```text
sub_2315C → sub_2A80C → sub_38478 → sub_38738
```

`sub_2A80C` memeriksa `img_auth_required`; saat aktif, `sub_38478` memverifikasi rantai sertifikat dan `sub_38738` memverifikasi autentikasi image. Status unlocked sendiri tidak mematikan verifikasi LK. Gale membutuhkan `CONFIG_CERT_BYPASS=y`, `CONFIG_CERT_BYPASS_MODE="override"`, dan cert2 `lk` yang dapat diparse. `utils/patch.py` menolak build jika `lk` yang diubah tidak tercakup.

## Perilaku

Spoofing tetap mati sampai diaktifkan lewat fastboot:

```sh
fastboot oem bldr_spoof on
fastboot oem bldr_spoof status
fastboot oem bldr_spoof off
```

Saat aktif, boot Android normal (`BOOTMODE_NORMAL = 0`) menulis ulang boot argument Android agar menampilkan:

```text
androidboot.verifiedbootstate=green
androidboot.secureboot=1
androidboot.vbmeta.device_state=locked
root-of-trust lock state=1
```

Recovery, fastboot, dan mode tidak dikenal tidak dipaksa menjadi locked secara global. Port ini tidak hook shared lock getter `sub_3C67C`, karena getter tersebut dipakai jalur policy, AVB, root-of-trust, dan fastboot.

## Anchor yang diaudit

| Item | Runtime address | Bukti |
| --- | --- | --- |
| `CONFIG_PLATFORM_INIT_ADDRESS` | `0x4C4039DC` | Prologue stock platform-init. |
| `CONFIG_PLATFORM_INIT_CALLER` | `0x4C425E0C` | `BL` stock ke platform init; dipatch sebagai entry payload. |
| direct `app()` call | `0x4C42AC04` | `BL` langsung unik ke `CONFIG_APP_ADDRESS=0x4C42A3CC`. |
| cmdline buffer | `0x4C579624` | Direferensikan fungsi producer/consumer cmdline stock. |
| `CONFIG_BOOTMODE_ADDRESS` | `0x4C5765A4` | `fastboot continue` menulis `BOOTMODE_NORMAL` (`0`) ke sini. |

Preflight Gale meminta tepat satu kecocokan untuk anchor patch board dan anchor direct `app()` call. Ia juga memeriksa LK load address dan ukuran image LK tepat.

## Batas analisis statis

Bukti IDA memvalidasi source port ini terhadap revisi LK stok yang disebutkan. Bukti ini tidak membuktikan perangkat pasti boot, rantai kriptografis AVB/vbmeta valid, attestation TEE atau KeyMint, hasil Play Integrity, atau verdict server Google. Semua itu perlu pengujian runtime terkontrol pada hardware target.
