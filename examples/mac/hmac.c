/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/alcp.h"
#include <malloc.h>
#include <stdio.h>

void
printHashAsHexString(Uint8* hash, int length)
{
    size_t i;
    for (i = 0; i < length; i++) {
        printf("%02x", hash[i]);
    }
}

int
compareArray(Uint8* a1, int a1_len, Uint8* a2, int a2_len)
{
    if (a1_len != a2_len) {
        return 1;
    }
    for (int i = 0; i < a1_len; i++) {
        if (a1[i] != a2[i]) {
            return 1;
        }
    }
    return 0;
}

static alc_mac_handle_t handle;

alc_error_t
run_hmac(const alc_mac_info_p macInfo,
         Uint8*               cipherText,
         Uint32               cipherTextLen,
         Uint8*               mac,
         Uint32               mac_size)
{

    int err = ALC_ERROR_NONE;
    err     = alcp_mac_supported(macInfo);
    if (err == ALC_ERROR_NONE) {
        handle.ch_context = malloc(alcp_mac_context_size(macInfo));
    } else {
        printf("HMAC Infomation is unsupported\n");
        return err;
    }

    char error_message[1024] = "";
    err                      = alcp_mac_request(&handle, macInfo);
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Request - %d\n", err);
        goto out;
    }
    // Update can be called multiple times with smaller chunks of the cipherText
    err = alcp_mac_update(&handle, cipherText, cipherTextLen);
    if (alcp_is_error(err)) {
        goto out;
    }
    // In Finalize code, last remaining buffer can be provided if any exists
    // with its size
    err = alcp_mac_finalize(&handle, NULL, 0);
    if (alcp_is_error(err)) {
        goto out;
    }
    err = alcp_mac_copy(&handle, mac, mac_size);
    if (alcp_is_error(err)) {
        goto out;
    }

out:
    if (alcp_is_error(err)) {
        alcp_mac_error(&handle, error_message, sizeof(error_message));
        printf("MAC Error Detail is: %s\n", error_message);
    }

    alcp_mac_finish(&handle);
    free(handle.ch_context);
    return err;
}

void
displayResults(char*  hmac_string,
               Uint8* key,
               Uint32 keylen,
               Uint8* cipherText,
               Uint32 cipherTextLen,
               Uint8* mac,
               Uint32 macLen,
               Uint8* expectedMac,
               Uint32 expectedMacLength)
{
    printf("%s", hmac_string);
    printf(" : ");
    printf("\n\t");
    printf("KEY = \t\t");
    printHashAsHexString(key, keylen);
    printf("\n\t");
    printf("CipherText = \t");
    printHashAsHexString(cipherText, cipherTextLen);
    printf("\n\t");
    printf("MAC = \t\t");
    printHashAsHexString(mac, macLen);
    printf("\n\t");
    printf("Expected MAC = \t");
    printHashAsHexString(expectedMac, expectedMacLength);
    printf("\n\t");
    if (!compareArray(mac, macLen, expectedMac, expectedMacLength)) {
        printf("MAC IS VERIFIED");
    } else {
        printf("INVALID MAC");
    }
    printf("\n");
    printf("=======================");
    printf("\n");
}

void
demo_Hmac_Sha256()
{

    alc_error_t err;
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
                    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
                    0x3c, 0x3d, 0x3e, 0x3f };
    Uint8 cipherText[] = { 0x53, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x6D, 0x65,
                           0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6F, 0x72,
                           0x20, 0x6B, 0x65, 0x79, 0x6C, 0x65, 0x6E, 0x3D, 0x62,
                           0x6C, 0x6F, 0x63, 0x6B, 0x6C, 0x65, 0x6E };

    Uint8 expectedMac[] = { 0x8b, 0xb9, 0xa1, 0xdb, 0x98, 0x06, 0xf2, 0x0d,
                            0xf7, 0xf7, 0x7b, 0x82, 0x13, 0x8c, 0x79, 0x14,
                            0xd1, 0x74, 0xd5, 0x9e, 0x13, 0xdc, 0x4d, 0x01,
                            0x69, 0xc9, 0x05, 0x7b, 0x13, 0x3e, 0x1d, 0x62 };

    const alc_key_info_t kinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt  = ALC_KEY_FMT_RAW,
                                   .algo = ALC_KEY_ALG_MAC,
                                   .len  = sizeof(key) * 8,
                                   .key  = key };

    alc_mac_info_t macinfo = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA2,
                    .dt_len = ALC_DIGEST_LEN_256,
                    .dt_mode = {.dm_sha2 = ALC_SHA2_256,},
                }
            }
        },
        .mi_keyinfo = kinfo
    };

    Uint64 mac_size = 32;
    Uint8  mac[mac_size];
    err = run_hmac(&macinfo, cipherText, sizeof(cipherText), mac, mac_size);
    if (err != ALC_ERROR_NONE) {
        printf("Error Occurred in HMAC SHA2-256\n");

    } else {

        displayResults("HMAC SHA2-256",
                       key,
                       sizeof(key),
                       cipherText,
                       sizeof(cipherText),
                       mac,
                       sizeof(mac),
                       expectedMac,
                       sizeof(expectedMac));
    }
}

void
demo_Hmac_Sha224()
{

    alc_error_t err;
    Uint8       key[] = {
        0xcf, 0x12, 0x75, 0x79, 0xd6, 0xb2, 0xb0, 0xb3, 0xa6, 0x07,
        0xa6, 0x31, 0x4b, 0xf8, 0x73, 0x30, 0x61, 0xc3, 0x2a, 0x04,
        0x35, 0x93, 0x19, 0x55, 0x27, 0x54, 0x4f, 0x87, 0x53, 0xc6,
        0x5c, 0x7a, 0x70, 0xd0, 0x58, 0x74, 0xf7, 0x18, 0x27, 0x5b,
        0x88, 0xd0, 0xfa, 0x28, 0x8b, 0xd3, 0x19, 0x98, 0x13, 0xf0
    };
    Uint8 cipherText[] = {
        0xfa, 0x7e, 0x18, 0xcc, 0x54, 0x43, 0x98, 0x1f, 0x22, 0xc0, 0xa5, 0xab,
        0xa2, 0x11, 0x79, 0x15, 0xf8, 0x9c, 0x77, 0x81, 0xc3, 0x4f, 0x61, 0xf9,
        0xf4, 0x29, 0xcb, 0x13, 0xe0, 0xfc, 0xd0, 0xce, 0x94, 0x71, 0x03, 0xbe,
        0x68, 0x4c, 0xa8, 0x69, 0xd7, 0xf1, 0x25, 0xf0, 0x8d, 0x27, 0xb3, 0xf2,
        0xc2, 0x1d, 0x59, 0xad, 0xc7, 0xab, 0x1b, 0x66, 0xde, 0xd9, 0x6f, 0x0b,
        0x4f, 0xa5, 0xf0, 0x18, 0xb8, 0x01, 0x56, 0xb7, 0xa5, 0x1c, 0xa6, 0x2b,
        0x60, 0xe2, 0xa6, 0x6e, 0x0b, 0xc6, 0x94, 0x19, 0xeb, 0xbf, 0x17, 0x85,
        0x07, 0x90, 0x76, 0x30, 0xf2, 0x4d, 0x08, 0x62, 0xe5, 0x1b, 0xec, 0x10,
        0x10, 0x37, 0xf9, 0x00, 0x32, 0x3a, 0xf8, 0x2e, 0x68, 0x9b, 0x11, 0x6f,
        0x42, 0x75, 0x84, 0x54, 0x1c, 0x8a, 0x9a, 0x51, 0xac, 0x89, 0xda, 0x1e,
        0xd7, 0x8c, 0x7f, 0x5e, 0xc9, 0xe5, 0x2a, 0x7f
    };

    Uint8 expectedMac[] = { 0x35, 0x4f, 0x87, 0xe9, 0x8d, 0x27, 0x64,
                            0x46, 0x83, 0x6e, 0xa0, 0x43, 0x0c, 0xe4,
                            0x52, 0x92, 0x72, 0xa0, 0x17, 0xc2, 0x90,
                            0x03, 0x9a, 0x9d, 0xfe, 0xa4, 0x34, 0x9b };

    const alc_key_info_t kinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt  = ALC_KEY_FMT_RAW,
                                   .algo = ALC_KEY_ALG_MAC,
                                   .len  = sizeof(key) * 8,
                                   .key  = key };

    alc_mac_info_t macinfo = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA2,
                    .dt_len = ALC_DIGEST_LEN_224,
                    .dt_mode = {.dm_sha2 = ALC_SHA2_224,},
                }
            }
        },
        .mi_keyinfo = kinfo
    };

    Uint64 mac_size = ALC_DIGEST_LEN_224 / 8;
    Uint8  mac[mac_size];
    err = run_hmac(&macinfo, cipherText, sizeof(cipherText), mac, mac_size);
    if (err != ALC_ERROR_NONE) {
        printf("Error Occurred in HMAC SHA2-224\n");

    } else {

        displayResults("HMAC SHA2-224",
                       key,
                       sizeof(key),
                       cipherText,
                       sizeof(cipherText),
                       mac,
                       sizeof(mac),
                       expectedMac,
                       sizeof(expectedMac));
    }
}

void
demo_Hmac_Sha512()
{
    alc_error_t err;
    Uint8       key[] = {
        0x57, 0xc2, 0xeb, 0x67, 0x7b, 0x50, 0x93, 0xb9, 0xe8, 0x29, 0xea, 0x4b,
        0xab, 0xb5, 0x0b, 0xde, 0x55, 0xd0, 0xad, 0x59, 0xfe, 0xc3, 0x4a, 0x61,
        0x89, 0x73, 0x80, 0x2b, 0x2a, 0xd9, 0xb7, 0x8e, 0x26, 0xb2, 0x04, 0x5d,
        0xda, 0x78, 0x4d, 0xf3, 0xff, 0x90, 0xae, 0x0f, 0x2c, 0xc5, 0x1c, 0xe3,
        0x9c, 0xf5, 0x48, 0x67, 0x32, 0x0a, 0xc6, 0xf3, 0xba, 0x2c, 0x6f, 0x0d,
        0x72, 0x36, 0x04, 0x80, 0xc9, 0x66, 0x14, 0xae, 0x66, 0x58, 0x1f, 0x26,
        0x6c, 0x35, 0xfb, 0x79, 0xfd, 0x28, 0x77, 0x4a, 0xfd, 0x11, 0x3f, 0xa5,
        0x18, 0x7e, 0xff, 0x92, 0x06, 0xd7, 0xcb, 0xe9, 0x0d, 0xd8, 0xbf, 0x67,
        0xc8, 0x44, 0xe2, 0x02
    };
    Uint8 cipherText[] = {
        0x24, 0x23, 0xdf, 0xf4, 0x8b, 0x31, 0x2b, 0xe8, 0x64, 0xcb, 0x34, 0x90,
        0x64, 0x1f, 0x79, 0x3d, 0x2b, 0x9f, 0xb6, 0x8a, 0x77, 0x63, 0xb8, 0xe2,
        0x98, 0xc8, 0x6f, 0x42, 0x24, 0x5e, 0x45, 0x40, 0xeb, 0x01, 0xae, 0x4d,
        0x2d, 0x45, 0x00, 0x37, 0x0b, 0x18, 0x86, 0xf2, 0x3c, 0xa2, 0xcf, 0x97,
        0x01, 0x70, 0x4c, 0xad, 0x5b, 0xd2, 0x1b, 0xa8, 0x7b, 0x81, 0x1d, 0xaf,
        0x7a, 0x85, 0x4e, 0xa2, 0x4a, 0x56, 0x56, 0x5c, 0xed, 0x42, 0x5b, 0x35,
        0xe4, 0x0e, 0x1a, 0xcb, 0xeb, 0xe0, 0x36, 0x03, 0xe3, 0x5d, 0xcf, 0x4a,
        0x10, 0x0e, 0x57, 0x21, 0x84, 0x08, 0xa1, 0xd8, 0xdb, 0xcc, 0x3b, 0x99,
        0x29, 0x6c, 0xfe, 0xa9, 0x31, 0xef, 0xe3, 0xeb, 0xd8, 0xf7, 0x19, 0xa6,
        0xd9, 0xa1, 0x54, 0x87, 0xb9, 0xad, 0x67, 0xea, 0xfe, 0xdf, 0x15, 0x55,
        0x9c, 0xa4, 0x24, 0x45, 0xb0, 0xf9, 0xb4, 0x2e
    };

    Uint8 expectedMac[] = { 0x33, 0xc5, 0x11, 0xe9, 0xbc, 0x23, 0x07, 0xc6,
                            0x27, 0x58, 0xdf, 0x61, 0x12, 0x5a, 0x98, 0x0e,
                            0xe6, 0x4c, 0xef, 0xeb, 0xd9, 0x09, 0x31, 0xcb,
                            0x91, 0xc1, 0x37, 0x42, 0xd4, 0x71, 0x4c, 0x06,
                            0xde, 0x40, 0x03, 0xfa, 0xf3, 0xc4, 0x1c, 0x06,
                            0xae, 0xfc, 0x63, 0x8a, 0xd4, 0x7b, 0x21, 0x90,
                            0x6e, 0x6b, 0x10, 0x48, 0x16, 0xb7, 0x2d, 0xe6,
                            0x26, 0x9e, 0x04, 0x5a, 0x1f, 0x44, 0x29, 0xd4 };

    const alc_key_info_t kinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt  = ALC_KEY_FMT_RAW,
                                   .algo = ALC_KEY_ALG_MAC,
                                   .len  = sizeof(key) * 8,
                                   .key  = key };

    alc_mac_info_t macinfo = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA2,
                    .dt_len = ALC_DIGEST_LEN_512,
                    .dt_mode = {.dm_sha2 = ALC_SHA2_512,},
                }
            }
        },
        .mi_keyinfo = kinfo
    };

    Uint64 mac_size = ALC_DIGEST_LEN_512 / 8;
    Uint8  mac[mac_size];
    err = run_hmac(&macinfo, cipherText, sizeof(cipherText), mac, mac_size);
    if (err != ALC_ERROR_NONE) {
        printf("Error Occurred in HMAC SHA2-512\n");

    } else {

        displayResults("HMAC SHA2-512",
                       key,
                       sizeof(key),
                       cipherText,
                       sizeof(cipherText),
                       mac,
                       sizeof(mac),
                       expectedMac,
                       sizeof(expectedMac));
    }
}
void
demo_Hmac_Sha3_224()
{
    alc_error_t err;
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b };
    Uint8 cipherText[] = { 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d, 0x65,
                           0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6f, 0x72,
                           0x20, 0x6b, 0x65, 0x79, 0x6c, 0x65, 0x6e, 0x3c, 0x62,
                           0x6c, 0x6f, 0x63, 0x6b, 0x6c, 0x65, 0x6e };

    Uint8 expectedMac[] = { 0x33, 0x2c, 0xfd, 0x59, 0x34, 0x7f, 0xdb,
                            0x8e, 0x57, 0x6e, 0x77, 0x26, 0x0b, 0xe4,
                            0xab, 0xa2, 0xd6, 0xdc, 0x53, 0x11, 0x7b,
                            0x3b, 0xfb, 0x52, 0xc6, 0xd1, 0x8c, 0x04 };

    const alc_key_info_t kinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt  = ALC_KEY_FMT_RAW,
                                   .algo = ALC_KEY_ALG_MAC,
                                   .len  = sizeof(key) * 8,
                                   .key  = key };

    alc_mac_info_t macinfo = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA3,
                    .dt_len = ALC_DIGEST_LEN_224,
                    .dt_mode = {.dm_sha3 = ALC_SHA3_224},
                }
            }
        },
        .mi_keyinfo = kinfo
    };

    Uint64 mac_size = ALC_DIGEST_LEN_224 / 8;
    Uint8  mac[mac_size];
    err = run_hmac(&macinfo, cipherText, sizeof(cipherText), mac, mac_size);
    if (err != ALC_ERROR_NONE) {
        printf("Error Occurred in HMAC SHA3-224\n");

    } else {

        displayResults("HMAC SHA3-224",
                       key,
                       sizeof(key),
                       cipherText,
                       sizeof(cipherText),
                       mac,
                       sizeof(mac),
                       expectedMac,
                       sizeof(expectedMac));
    }
}

void
demo_Hmac_Sha3_256()
{
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    Uint8 cipherText[] = { 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d, 0x65,
                           0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6f, 0x72,
                           0x20, 0x6b, 0x65, 0x79, 0x6c, 0x65, 0x6e, 0x3c, 0x62,
                           0x6c, 0x6f, 0x63, 0x6b, 0x6c, 0x65, 0x6e };

    Uint8 expectedMac[] = { 0x4f, 0xe8, 0xe2, 0x02, 0xc4, 0xf0, 0x58, 0xe8,
                            0xdd, 0xdc, 0x23, 0xd8, 0xc3, 0x4e, 0x46, 0x73,
                            0x43, 0xe2, 0x35, 0x55, 0xe2, 0x4f, 0xc2, 0xf0,
                            0x25, 0xd5, 0x98, 0xf5, 0x58, 0xf6, 0x72, 0x05 };

    const alc_key_info_t kinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt  = ALC_KEY_FMT_RAW,
                                   .algo = ALC_KEY_ALG_MAC,
                                   .len  = sizeof(key) * 8,
                                   .key  = key };

    alc_mac_info_t macinfo = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA3,
                    .dt_len = ALC_DIGEST_LEN_256,
                    .dt_mode = {.dm_sha3 = ALC_SHA3_256},
                }
            }
        },
        .mi_keyinfo = kinfo
    };

    Uint64      mac_size = ALC_DIGEST_LEN_256 / 8;
    Uint8       mac[mac_size];
    alc_error_t err =
        run_hmac(&macinfo, cipherText, sizeof(cipherText), mac, mac_size);
    if (err != ALC_ERROR_NONE) {
        printf("Error Occurred in HMAC SHA3-256\n");

    } else {

        displayResults("HMAC SHA3-256",
                       key,
                       sizeof(key),
                       cipherText,
                       sizeof(cipherText),
                       mac,
                       sizeof(mac),
                       expectedMac,
                       sizeof(expectedMac));
    }
}
void
demo_Hmac_Sha3_512()
{
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
                    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
                    0x3c, 0x3d, 0x3e, 0x3f };

    Uint8 cipherText[] = { 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d, 0x65,
                           0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6f, 0x72,
                           0x20, 0x6b, 0x65, 0x79, 0x6c, 0x65, 0x6e, 0x3c, 0x62,
                           0x6c, 0x6f, 0x63, 0x6b, 0x6c, 0x65, 0x6e };

    Uint8 expectedMac[] = { 0x4e, 0xfd, 0x62, 0x9d, 0x6c, 0x71, 0xbf, 0x86,
                            0x16, 0x26, 0x58, 0xf2, 0x99, 0x43, 0xb1, 0xc3,
                            0x08, 0xce, 0x27, 0xcd, 0xfa, 0x6d, 0xb0, 0xd9,
                            0xc3, 0xce, 0x81, 0x76, 0x3f, 0x9c, 0xbc, 0xe5,
                            0xf7, 0xeb, 0xe9, 0x86, 0x80, 0x31, 0xdb, 0x1a,
                            0x8f, 0x8e, 0xb7, 0xb6, 0xb9, 0x5e, 0x5c, 0x5e,
                            0x3f, 0x65, 0x7a, 0x89, 0x96, 0xc8, 0x6a, 0x2f,
                            0x65, 0x27, 0xe3, 0x07, 0xf0, 0x21, 0x31, 0x96 };

    const alc_key_info_t kinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt  = ALC_KEY_FMT_RAW,
                                   .algo = ALC_KEY_ALG_MAC,
                                   .len  = sizeof(key) * 8,
                                   .key  = key };

    alc_mac_info_t macinfo = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA3,
                    .dt_len = ALC_DIGEST_LEN_512,
                    .dt_mode = {.dm_sha3 = ALC_SHA3_512},
                }
            }
        },
        .mi_keyinfo = kinfo
    };

    Uint64      mac_size = ALC_DIGEST_LEN_512 / 8;
    Uint8       mac[mac_size];
    alc_error_t err =
        run_hmac(&macinfo, cipherText, sizeof(cipherText), mac, mac_size);
    if (err != ALC_ERROR_NONE) {
        printf("Error Occurred in HMAC SHA3-512\n");

    } else {

        displayResults("HMAC SHA3-512",
                       key,
                       sizeof(key),
                       cipherText,
                       sizeof(cipherText),
                       mac,
                       sizeof(mac),
                       expectedMac,
                       sizeof(expectedMac));
    }
}

void
demo_Hmac_Sha384()
{
    Uint8 key[] = { 0x5e, 0xab, 0x0d, 0xfa, 0x27, 0x31, 0x12, 0x60, 0xd7, 0xbd,
                    0xdc, 0xf7, 0x71, 0x12, 0xb2, 0x3d, 0x8b, 0x42, 0xeb, 0x7a,
                    0x5d, 0x72, 0xa5, 0xa3, 0x18, 0xe1, 0xba, 0x7e, 0x79, 0x27,
                    0xf0, 0x07, 0x9d, 0xbb, 0x70, 0x13, 0x17, 0xb8, 0x7a, 0x33,
                    0x40, 0xe1, 0x56, 0xdb, 0xce, 0xe2, 0x8e, 0xc3, 0xa8, 0xd9

    };

    Uint8 cipherText[] = {
        0xf4, 0x13, 0x80, 0x12, 0x3c, 0xcb, 0xec, 0x4c, 0x52, 0x7b, 0x42, 0x56,
        0x52, 0x64, 0x11, 0x91, 0xe9, 0x0a, 0x17, 0xd4, 0x5e, 0x2f, 0x62, 0x06,
        0xcf, 0x01, 0xb5, 0xed, 0xbe, 0x93, 0x2d, 0x41, 0xcc, 0x8a, 0x24, 0x05,
        0xc3, 0x19, 0x56, 0x17, 0xda, 0x2f, 0x42, 0x05, 0x35, 0xee, 0xd4, 0x22,
        0xac, 0x60, 0x40, 0xd9, 0xcd, 0x65, 0x31, 0x42, 0x24, 0xf0, 0x23, 0xf3,
        0xba, 0x73, 0x0d, 0x19, 0xdb, 0x98, 0x44, 0xc7, 0x1c, 0x32, 0x9c, 0x8d,
        0x9d, 0x73, 0xd0, 0x4d, 0x8c, 0x5f, 0x24, 0x4a, 0xea, 0x80, 0x48, 0x82,
        0x92, 0xdc, 0x80, 0x3e, 0x77, 0x24, 0x02, 0xe7, 0x2d, 0x2e, 0x9f, 0x1b,
        0xab, 0xa5, 0xa6, 0x00, 0x4f, 0x00, 0x06, 0xd8, 0x22, 0xb0, 0xb2, 0xd6,
        0x5e, 0x9e, 0x4a, 0x30, 0x2d, 0xd4, 0xf7, 0x76, 0xb4, 0x7a, 0x97, 0x22,
        0x50, 0x05, 0x1a, 0x70, 0x1f, 0xab, 0x2b, 0x70
    };

    Uint8 expectedMac[] = { 0x7c, 0xf5, 0xa0, 0x61, 0x56, 0xad, 0x3d, 0xe5,
                            0x40, 0x5a, 0x5d, 0x26, 0x1d, 0xe9, 0x02, 0x75,
                            0xf9, 0xbb, 0x36, 0xde, 0x45, 0x66, 0x7f, 0x84,
                            0xd0, 0x8f, 0xbc, 0xb3, 0x08, 0xca, 0x8f, 0x53,
                            0xa4, 0x19, 0xb0, 0x7d, 0xea, 0xb3, 0xb5, 0xf8,
                            0xea, 0x23, 0x1c, 0x5b, 0x03, 0x6f, 0x88, 0x75 };

    const alc_key_info_t kinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt  = ALC_KEY_FMT_RAW,
                                   .algo = ALC_KEY_ALG_MAC,
                                   .len  = sizeof(key) * 8,
                                   .key  = key };

    alc_mac_info_t macinfo = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA2,
                    .dt_len = ALC_DIGEST_LEN_384,
                    .dt_mode = {.dm_sha3 = ALC_SHA3_384},
                }
            }
        },
        .mi_keyinfo = kinfo
    };

    Uint64      mac_size = ALC_DIGEST_LEN_384 / 8;
    Uint8       mac[mac_size];
    alc_error_t err =
        run_hmac(&macinfo, cipherText, sizeof(cipherText), mac, mac_size);
    if (err != ALC_ERROR_NONE) {
        printf("Error Occurred in HMAC SHA2-384\n");

    } else {

        displayResults("HMAC SHA2-384",
                       key,
                       sizeof(key),
                       cipherText,
                       sizeof(cipherText),
                       mac,
                       sizeof(mac),
                       expectedMac,
                       sizeof(expectedMac));
    }
}

void
demo_Hmac_Sha3_384()
{
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f };

    Uint8 cipherText[] = { 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d, 0x65,
                           0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6f, 0x72,
                           0x20, 0x6b, 0x65, 0x79, 0x6c, 0x65, 0x6e, 0x3c, 0x62,
                           0x6c, 0x6f, 0x63, 0x6b, 0x6c, 0x65, 0x6e };

    Uint8 expectedMac[] = { 0xd5, 0x88, 0xa3, 0xc5, 0x1f, 0x3f, 0x2d, 0x90,
                            0x6e, 0x82, 0x98, 0xc1, 0x19, 0x9a, 0xa8, 0xff,
                            0x62, 0x96, 0x21, 0x81, 0x27, 0xf6, 0xb3, 0x8a,
                            0x90, 0xb6, 0xaf, 0xe2, 0xc5, 0x61, 0x77, 0x25,
                            0xbc, 0x99, 0x98, 0x7f, 0x79, 0xb2, 0x2a, 0x55,
                            0x7b, 0x65, 0x20, 0xdb, 0x71, 0x0b, 0x7f, 0x42 };

    const alc_key_info_t kinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt  = ALC_KEY_FMT_RAW,
                                   .algo = ALC_KEY_ALG_MAC,
                                   .len  = sizeof(key) * 8,
                                   .key  = key };

    alc_mac_info_t macinfo = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA3,
                    .dt_len = ALC_DIGEST_LEN_384,
                    .dt_mode = {.dm_sha3 = ALC_SHA3_384},
                }
            }
        },
        .mi_keyinfo = kinfo
    };

    Uint64      mac_size = ALC_DIGEST_LEN_384 / 8;
    Uint8       mac[mac_size];
    alc_error_t err =
        run_hmac(&macinfo, cipherText, sizeof(cipherText), mac, mac_size);
    if (err != ALC_ERROR_NONE) {
        printf("Error Occurred in HMAC SHA3-384\n");

    } else {

        displayResults("HMAC SHA3-384",
                       key,
                       sizeof(key),
                       cipherText,
                       sizeof(cipherText),
                       mac,
                       sizeof(mac),
                       expectedMac,
                       sizeof(expectedMac));
    }
}

void
demo_Hmac_Sha3_384_Reset()
{
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f };

    Uint8 cipherText[] = { 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d, 0x65,
                           0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6f, 0x72,
                           0x20, 0x6b, 0x65, 0x79, 0x6c, 0x65, 0x6e, 0x3c, 0x62,
                           0x6c, 0x6f, 0x63, 0x6b, 0x6c, 0x65, 0x6e };

    Uint8 expectedMac[] = { 0xd5, 0x88, 0xa3, 0xc5, 0x1f, 0x3f, 0x2d, 0x90,
                            0x6e, 0x82, 0x98, 0xc1, 0x19, 0x9a, 0xa8, 0xff,
                            0x62, 0x96, 0x21, 0x81, 0x27, 0xf6, 0xb3, 0x8a,
                            0x90, 0xb6, 0xaf, 0xe2, 0xc5, 0x61, 0x77, 0x25,
                            0xbc, 0x99, 0x98, 0x7f, 0x79, 0xb2, 0x2a, 0x55,
                            0x7b, 0x65, 0x20, 0xdb, 0x71, 0x0b, 0x7f, 0x42 };

    const alc_key_info_t kinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt  = ALC_KEY_FMT_RAW,
                                   .algo = ALC_KEY_ALG_MAC,
                                   .len  = sizeof(key) * 8,
                                   .key  = key };

    alc_mac_info_t macinfo = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA3,
                    .dt_len = ALC_DIGEST_LEN_384,
                    .dt_mode = {.dm_sha3 = ALC_SHA3_384},
                }
            }
        },
        .mi_keyinfo = kinfo
    };

    Uint64 mac_size = ALC_DIGEST_LEN_384 / 8;
    Uint8  mac[mac_size];

    handle.ch_context = malloc(alcp_mac_context_size(&macinfo));
    alc_error_t err   = ALC_ERROR_NONE;
    err               = alcp_mac_request(&handle, &macinfo);
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Request");
    }
    // Update can be called multiple times with smaller chunks of the cipherText
    err = alcp_mac_update(&handle, cipherText, sizeof(cipherText));
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Update\n");
    }

    // At this point if we need to we can reset and reuse with the same key
    err = alcp_mac_reset(&handle);
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Reset\n");
    }

    // Update can be called multiple times with smaller chunks of the cipherText
    err = alcp_mac_update(&handle, cipherText, sizeof(cipherText));
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Update\n");
    }

    // In Finalize code, last remaining buffer can be provided if any exists
    // with its size
    err = alcp_mac_finalize(&handle, NULL, 0);
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Finalize\n");
    }
    err = alcp_mac_copy(&handle, mac, mac_size);
    if (alcp_is_error(err)) {
        printf("Error Occurred while Copying MAC\n");
    }
    alcp_mac_finish(&handle);
    free(handle.ch_context);

    displayResults("Reset HMAC SHA3-384",
                   key,
                   sizeof(key) * 8,
                   cipherText,
                   sizeof(cipherText),
                   mac,
                   sizeof(mac),
                   expectedMac,
                   sizeof(expectedMac));
}

int
main(int argc, char const* argv[])
{
    // SHA-2 Based HMAC
    demo_Hmac_Sha224();
    demo_Hmac_Sha256();
    demo_Hmac_Sha384();
    demo_Hmac_Sha512();

    // SHA-3 BASED HMAC
    demo_Hmac_Sha3_224();
    demo_Hmac_Sha3_256();
    demo_Hmac_Sha3_384();
    demo_Hmac_Sha3_512();

    // Reset Demo
    demo_Hmac_Sha3_384_Reset();

    return 0;
}
