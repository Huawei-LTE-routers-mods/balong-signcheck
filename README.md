Balong SignCheck
================

Balong SignCheck validates Secure Boot (a.k.a. `secuboot`) signature of Huawei LTE routers and modems based on Balong V7R11 (E3372h, E5573, E5577, E5770, E8372, etc) and V7R5 (B612s, B618s, B715s) platforms, and prints MD5 hash which should be/is programmed in efuse group0-3 for HiSilicon chip to boot in secuboot mode.

The utility accepts usbloader/M3Boot firmware partition/mtdblock0 flash image dump as input.

Example output:
```
$ ./balong_signcheck.py usbloader-5573cs-322.bin
Huawei Balong V7R11/V7R5 LTE modems firmware/usbloader signature tool
https://github.com/Huawei-LTE-routers-mods
NOTE: everything in the image is stored in little-endian, either fully or by 32 bits.

Sec_image_len: 3412
Checking Root CA…
⇒ MD5 sha256hmac: 973900451a9d22682c9067ec7a0b24f4
⇒ Found KNOWN HASH(2): E5577s/Bs .76 STC / E3372s-153 .161 Beeline / E8372s-153 .306 Zong/Warid / E8372h-608 .274 Telenor / E5573s-320 .306 Zong / E5573cs .274 Telenor

Efuse group0: 45003997
Efuse group1: 68229d1a
Efuse group2: ec67902c
Efuse group3: f4240b7a
Efuses are shown little-endian, as printed by bsp_efuse_show

Checking OEM CA…
Checking data signature with OEM CA…
⇒ All OK, hashes match, M3Boot/usbloader.bin is signed correctly
NOTE: if you loaded usbloader, this utility checks only signature of the first partition (raminit).
```
