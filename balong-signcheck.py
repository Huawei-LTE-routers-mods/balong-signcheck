#!/usr/bin/env python3

'''
Huawei Balong LTE modems firmware/usbloader signature tool, by ValdikSS <iam@valdikss.org.ru>, 2020

Huawei's Balong V7R11 Secuboot works as follows:
1. 260 byte of "\x20\x00\x00\x04" + RSA public exponent (e) + RSA public modulus (n) (the ROOT KEY)
   is hashed with SHA256-HMAC with empty key. This ROOT KEY is located at offset 580 (dec)
   from the beginning of the flash. This corresponds to "M3Boot" partition in the firmware (offset
   is also 580).
2. Hash from step 1 is hashed with MD5.
3. MD5 hash is checked against efuse groups 0-3 (each group is 32 bit).
4. If this check is successful, the OEM KEY is checked if it's signed with ROOT KEY.
   OEM KEY is stored in sec_image_len (offset 576) + 128, the signature of it is stored in
   sec_image_len + 396.
5. If the check above is successful, then full M3Boot partition data SHA256HMAC-hash is
   checked against OEM KEY-signed data (it's stored right after sec_image_len, 128 bytes).
6. If all the checks above are successful, the booting IN THE BOOTROM continues.
   There are other signature checks after the bootrom passed the execution to another file.
   All of them are the same and either use bootrom functions directly (when its memory is still
   mapped), or re-implement the exact same check.

Efuses could be printed with:
   ecall bsp_efuse_show
   dmesg

Example from E8372s-153 21.333.64.00.1456 (ZONG BOLT+):

[efuse]: efuse group0 value = 0xa4a62a27.    \
[efuse]: efuse group1 value = 0x36e38101.     | ⇒ ROOT KEY MD5 HASH (272aa6a40181e33667c9e80dae1544e5)
[efuse]: efuse group2 value = 0xde8c967.      |
[efuse]: efuse group3 value = 0xe54415ae.    /
[efuse]: efuse group4 value = 0x5b0.  \       // cust id / operator id / HUK. Value: 1456
[efuse]: efuse group5 value = 0x0.     |
[efuse]: efuse group6 value = 0x0.     | ⇒ Used in create_crypto_key_o vxworks function (possible for HWLOCK)
[efuse]: efuse group7 value = 0x0.    /
[efuse]: efuse group8 value = 0x28109d92.  \
[efuse]: efuse group9 value = 0x249.        |
[efuse]: efuse group10 value = 0x243e1920.  | ⇒ group_dieid + chipid (DRV_GET_DIEID in vxworks/linux)
[efuse]: efuse group11 value = 0xc0002c1a.  | // AES (vxworks), probably used for VSIM feature (efuseWriteAes and efuseReadAes in vxworks)
[efuse]: efuse group12 value = 0x3ff.      /
[efuse]: efuse group13 value = 0x1443f801.    // efuse_secboot_id + anti-downgrade byte (see mbb_kernel_secboot_id_check linux function)
[efuse]: efuse group14 value = 0x8b.
[efuse]: efuse group15 value = 0x18.          // boot_sel + secboot_en
'''

import sys
import hashlib
import hmac

DEBUG = False

'''
HashCalc calculates SHA256-HMAC with empty key, by 512 byte blocks, reusing previous
hash result as a key for further blocks, as does Huawei.
'''
def HashCalc(data):
    hm = b""
    hm_key = b""
    if not data:
        return False
    for i in range(0, len(data), 512):
        hm = hmac.new(hm_key, data[i:i+512], hashlib.sha256)
        hm_key = hm.digest()
    if DEBUG:
        print("HashCalc:", hm.digest().hex())
    return hm.digest()

'''
RSACalc performs RSA "encryption" in RAW format to decrypt signature data.
'''
def RSACalc(pubkey, signature):
    class pkey:
        e = int.from_bytes(pubkey[0], byteorder='little')
        n = int.from_bytes(pubkey[1], byteorder='little')
    secret_message_long = int.from_bytes(signature, byteorder='little')
    verify_long = pow(secret_message_long, pkey.e, pkey.n)
    verify_bytes = verify_long.to_bytes(32, byteorder='little')
    if DEBUG:
        print("RSACalc:", verify_bytes.hex())
    return verify_bytes

'''
data_sigcheck calculates Huawei signature and compares it against stored signed data.
'''
def data_sigcheck(data, pubkey, signature):
    hashed = HashCalc(data)
    rsa = RSACalc(pubkey, signature)
    if hashed == rsa:
        if DEBUG:
            print("data_sigcheck: hashes match!")
        return True
    else:
        if DEBUG:
            print("data_sigcheck: hashes DO NOT match!!!")
        return False


class BalongSecImage:
    class BalongNotValidImage(Exception):
        pass
    class BalongUnsupportedImage(Exception):
        pass
    class BalongSigException(Exception):
        pass

    def __init__(self, data):
        USBLOADER_LEN = 84
        SEC_IMAGE_LEN_OFFSET = 576
        SEC_IMAGE_LEN_LEN = 4
        ROOT_CA_OFFSET = 580
        ROOT_CA_LEN = 260
        OEM_CA_LEN_V7R11 = 268
        OEM_CA_LEN_V7R5 = 268 + 128
        CA_E_OFFSET = 4
        CA_N_OFFSET = 4 + 128
        CA_ELEM_LEN = 128
        SIGNATURE_LEN = 128

        self.data = data
        self.sec_image_len = None
        self.root_ca = None
        self.root_ca_e = None
        self.root_ca_n = None
        self.oem_ca = None
        self.oem_ca_e = None
        self.oem_ca_n = None
        self.data_signature = None
        self.oem_root_sign_data = None
        self.is_balong_v7r5 = False

        # Check if the image is usbloader
        if data[0:4] == b"\x00\x00\x02\x00": # usbloader
            data = data[USBLOADER_LEN:]      # strip usbloader header
            self.data = data
        if data[4708:4712] == b"Copy":
            raise self.BalongUnsupportedImage("Balong V7R11 images are not supported yet!")
        if data[1000:1004] == b"Copy":       # Check Balong V7R5 copyright message
            self.is_balong_v7r5 = True
        if data[872:876] != b"Copy" and not self.is_balong_v7r5:
            raise self.BalongNotValidImage("Not an M3Boot/mtdblock0/usbloader file!")

        self.sec_image_len = int.from_bytes(data[SEC_IMAGE_LEN_OFFSET:SEC_IMAGE_LEN_OFFSET+SEC_IMAGE_LEN_LEN], 'little')
        # This is where ROOT KEY is stored (the key from efuse group0-3)
        # 260 bytes: 4 bytes of garbage + RSA e + RSA n
        # (actually 4 bytes is the size, but it's not used anywhere)
        # ROOT KEY is RSA 1024 bit.
        self.root_ca = data[ROOT_CA_OFFSET:ROOT_CA_OFFSET+ROOT_CA_LEN]

        if not self.sec_image_len or self.root_ca == b"\x00" * ROOT_CA_LEN:
            raise self.BalongSigException("No signature found. The image is not signed (no secuboot/efuse).")
        if self.sec_image_len & 3:
            raise self.BalongSigException("sec_image_len & 3 is true, sanity check fail. The image is not signed?")
        if self.sec_image_len + 524 > 61440:
            raise self.BalongSigException("sec_image_len length > 61440, error!")

        # 128 byte DATA signature, right after the M3Boot code, signed with OEM KEY.
        self.data_signature = data[self.sec_image_len:self.sec_image_len+SIGNATURE_LEN]

        # This is where OEM KEY is stored, 268 bytes (V7R11) or 268 + 128 bytes (V7R5).
        # 4 bytes of garbage + RSA e + RSA n + 8 garbage "FF FF FF FF 00 00 00 00" bytes (+ another 128 bytes for V7R5)
        # OEM KEY is RSA 1024 bit.
        oem_ca_len = OEM_CA_LEN_V7R5 if self.is_balong_v7r5 else OEM_CA_LEN_V7R11
        self.oem_ca = data[
            self.sec_image_len+len(self.data_signature)
            :self.sec_image_len+len(self.data_signature)+oem_ca_len
            ]

        # OEM KEY signature.
        self.oem_root_sign_data = data[
            self.sec_image_len+len(self.data_signature)+len(self.oem_ca)
            :self.sec_image_len+len(self.data_signature)+len(self.oem_ca)+SIGNATURE_LEN
            ]

        # ROOT and OEM public exponent and modulus.
        self.root_ca_e = self.root_ca[CA_E_OFFSET:CA_E_OFFSET+CA_ELEM_LEN]
        self.root_ca_n = self.root_ca[CA_N_OFFSET:CA_N_OFFSET+CA_ELEM_LEN]
        self.oem_ca_e = self.oem_ca[CA_E_OFFSET:CA_E_OFFSET+CA_ELEM_LEN]
        self.oem_ca_n = self.oem_ca[CA_N_OFFSET:CA_N_OFFSET+CA_ELEM_LEN]


def main():
    print("Huawei Balong V7R11/V7R5 LTE modems firmware/usbloader signature tool")
    print("https://github.com/Huawei-LTE-routers-mods")
    print("NOTE: everything in the image is stored in little-endian, either fully or by 32 bits.")
    print()
    if len(sys.argv) != 2:
        print("Usage: {} <M3Boot.bin or mtdblock0 or usbloader.bin>".format(sys.argv[0]))
        return 1

    SEC_IMAGE_LEN_MAX = 65535

    mtdblock = open(sys.argv[1], "rb").read(SEC_IMAGE_LEN_MAX)
    try:
        bimage = BalongSecImage(mtdblock)
    except BalongSecImage.BalongNotValidImage as e:
        print(e)
        sys.exit(1)
    except BalongSecImage.BalongUnsupportedImage as e:
        print(e)
        sys.exit(2)
    except BalongSecImage.BalongSigException as e:
        print(e)
        sys.exit(3)

    # Copy data from BalongSecImage if usbloader header was stripped
    mtdblock = bimage.data
    print("Sec_image_len:", bimage.sec_image_len)
    print("Checking Root CA…")
    hm = HashCalc(bimage.root_ca)
    md5 = hashlib.md5()
    md5.update(hm)
    md5hexdigest = md5.hexdigest()
    print("⇒ MD5 sha256hmac:", md5hexdigest)
    if md5hexdigest == '272aa6a40181e33667c9e80dae1544e5':
        print("⇒ Found KNOWN HASH(1): E8372h-608 .1460 Telenor / E8372h-153 .1456 Zong / E5573Cs-322 .1456 Zong")
    elif md5hexdigest == '973900451a9d22682c9067ec7a0b24f4':
        print("⇒ Found KNOWN HASH(2): E5577s/Bs .76 STC / E3372s-153 .161 Beeline / E8372s-153 .306 Zong/Warid / E8372h-608 .274 Telenor / E5573s-320 .306 Zong / E5573cs .274 Telenor")
    elif md5hexdigest == '1cbb16c5bad8b08ead3268ef4b94c908':
        print("⇒ Found KNOWN HASH(3): E5577x / E5573x / E5572 / B618 new -sec firmware")
    else:
        print("⇒ Found UNKNOWN HASH!")

    print()
    efuses = int.from_bytes(md5.digest(), 'big').to_bytes(32, 'little').hex()
    print("Efuse group0:", efuses[24:32])
    print("Efuse group1:", efuses[16:24])
    print("Efuse group2:", efuses[8:16])
    print("Efuse group3:", efuses[0:8])
    print("Efuses are shown little-endian, as printed by bsp_efuse_show")

    print()
    print("Checking OEM CA…")

    r1 = data_sigcheck(
        (bimage.oem_ca),
        (bimage.root_ca_e, bimage.root_ca_n),
        bimage.oem_root_sign_data
    )

    print("Checking data signature with OEM CA…")

    r2 = data_sigcheck(
        mtdblock[0:bimage.sec_image_len],
        (bimage.oem_ca_e, bimage.oem_ca_n),
        bimage.data_signature
    )

    if not r1:
        print("⇒ OEM CA hashes do not match, file is NOT signed correctly!")
        return 4
    if not r2:
        print("⇒ Data signature hashes do not match, file is NOT signed correctly!")
        return 4

    print("⇒ All OK, hashes match, M3Boot/usbloader.bin is signed correctly")
    print("NOTE: if you loaded usbloader, this utility checks only signature of the first partition (raminit).")
    return 0

if __name__ == '__main__':
    sys.exit(main())
