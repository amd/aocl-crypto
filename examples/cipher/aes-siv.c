/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* for malloc */
#include <string.h>

#include "alcp/alcp.h"

static alc_cipher_handle_t handle;
alc_key_info_t             kinfo = {};

char*
bytesToHexString(unsigned char* bytes, int length);

bool
create_demo_session(const Uint8* key_cmac,
                    const Uint8* key_ctr,
                    const Uint32 key_len)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];
    kinfo.key = key_ctr;
    kinfo.len = key_len;

    alc_cipher_aead_info_t cinfo =
    {
        // request params
        .ci_type   = ALC_CIPHER_TYPE_AES,
        .ci_mode   = ALC_AES_MODE_SIV,
        .ci_keyLen = key_len,
        // init params
        .ci_key = key_cmac,
        .ci_iv  = NULL,
        // algo params
        .ci_algo_info   = {
           .ai_siv.xi_ctr_key = &kinfo,
        },
    };

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_aead_context_size());
    // if (!ctx)
    //    return;

    /* Request a context with cipher mode and keyLen */
    err = alcp_cipher_aead_request(cinfo.ci_mode, cinfo.ci_keyLen, &handle);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        free(handle.ch_context);
        return false;
    }
    printf("request succeeded\n");

    // FIXME: alcp_cipher_aead_int() to be added here

    return true;
}

bool
encrypt_demo(const Uint8* plaintxt,
             const Uint32 len, /* Describes both 'plaintxt' and 'ciphertxt' */
             Uint8*       ciphertxt,
             const Uint8* iv,
             const Uint32 ivLen,
             const Uint8* ad,
             const Uint32 aadLen,
             Uint8*       tag,
             const Uint32 tagLen,
             const Uint8* pKey,
             const Uint32 keyLen)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    err = alcp_cipher_aead_init(&handle, pKey, keyLen, iv, ivLen);

    err = alcp_cipher_aead_set_aad(&handle, ad, aadLen);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }

    // IV is not needed for encrypt, but still should not be NullPtr
    err = alcp_cipher_aead_encrypt_update(&handle, plaintxt, ciphertxt, len);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }

    err = alcp_cipher_aead_get_tag(&handle, tag, 16);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }

    alcp_cipher_aead_finish(&handle);

    free(handle.ch_context);

    printf("encrypt succeeded\n");

    return true;
}

bool
decrypt_demo(const Uint8* ciphertxt,
             const Uint32 len,
             Uint8*       plaintxt,
             const Uint8* iv,
             const Uint32 ivLen,
             const Uint8* ad,
             const Uint32 aadLen,
             Uint8*       tag,
             const Uint32 tagLen,
             const Uint8* pKey,
             const Uint32 keyLen)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    err = alcp_cipher_aead_init(&handle, pKey, keyLen, iv, ivLen);

    err = alcp_cipher_aead_set_aad(&handle, ad, aadLen);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }

    err = alcp_cipher_aead_decrypt_update(&handle, ciphertxt, plaintxt, len);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }

    alcp_cipher_aead_finish(&handle);

    free(handle.ch_context);

    printf("decrypt succeeded\n");

    return true;
}

static Uint8* sample_plaintxt = (Uint8*)"Happy Holi from AOCL Crypto :-)!";

// clang-format off
static const Uint8 sample_key[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,// CMAC KEY
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,// CTR KEY
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
};
// clang-format on

static const Uint8 aad[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
};

Uint8        iv_buff[16];
Uint8        tag[16];
static Uint8 sample_ciphertxt[512] = {
    0,
};

#define BITS_PER_BYTE 8

int
main(void)
{
    int          size               = strlen((const char*)sample_plaintxt);
    Uint8        sample_output[512] = { 0 };
    const Uint64 key_size           = (sizeof(sample_key) * 8) / 2;

    assert(sizeof(sample_plaintxt) < sizeof(sample_output));

    // FIXME should be sent in create call. iv_buff
    if (!create_demo_session(sample_key, sample_key, key_size)) {
        return -1; // Error condtion
    }

    if (!encrypt_demo(sample_plaintxt,
                      size,
                      sample_ciphertxt,
                      iv_buff,
                      sizeof(iv_buff),
                      aad,
                      sizeof(aad),
                      tag,
                      sizeof(tag),
                      sample_key,
                      key_size)) {
        return -1;
    }

    if (!create_demo_session(sample_key, sample_key, key_size)) {
        return -1;
    }

    memcpy(iv_buff, tag, sizeof(iv_buff)); // Copy Tag to IV as its Sythetic IV.
    if (!decrypt_demo(sample_ciphertxt,
                      size,
                      sample_output,
                      iv_buff,
                      sizeof(iv_buff),
                      aad,
                      sizeof(aad),
                      tag,
                      sizeof(tag),
                      sample_key,
                      key_size)) {
        return -1;
    }

    printf("sample_output: %s\n", sample_output);
    /*
     * Complete the transaction
     */

    return 0;
}