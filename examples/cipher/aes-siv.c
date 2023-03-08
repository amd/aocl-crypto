/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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
alc_key_info_t             kinfo = {
                .type = ALC_KEY_TYPE_SYMMETRIC,
                .fmt  = ALC_KEY_FMT_RAW,
};

char*
bytesToHexString(unsigned char* bytes, int length);

void
create_demo_session(const Uint8* key_cmac,
                    const Uint8* key_ctr,
                    const Uint32 key_len)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];
    kinfo.key = key_ctr;
    kinfo.len = key_len;

    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,
        .ci_algo_info   = {
           .ai_mode = ALC_AES_MODE_SIV,
           .ai_iv   = NULL,
           .ai_siv.xi_ctr_key = &kinfo,
        },
        /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE, 
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = key_cmac,
            .len     = key_len,
        },
    };

    /*
     * Check if the current cipher is supported,
     * optional call, alcp_cipher_request() will anyway return
     * ALC_ERR_NOSUPPORT error.
     *
     * This query call is provided to support fallback mode for applications
     */
    err = alcp_cipher_supported(&cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
    printf("supported succeeded\n");
    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_context_size(&cinfo));
    // if (!ctx)
    //    return;

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
    printf("request succeeded\n");
}

void
encrypt_demo(const Uint8* plaintxt,
             const Uint32 len, /*  for both 'plaintxt' and 'ciphertxt' */
             Uint8*       ciphertxt,
             Uint8*       iv,
             const Uint8* aad,
             Uint64       aad_len)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    err = alcp_cipher_set_aad(&handle, aad, aad_len);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
    // IV is not needed for encrypt, but still should not be NullPtr
    err = alcp_cipher_set_pad_length(&handle, 0);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    err = alcp_cipher_encrypt(&handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    err = alcp_cipher_get_tag(&handle, iv, 16);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    alcp_cipher_finish(&handle);

    free(handle.ch_context);

    printf("encrypt succeeded\n");
}

void
decrypt_demo(const Uint8* ciphertxt,
             const Uint32 len, /* for both 'plaintxt' and 'ciphertxt' */
             Uint8*       plaintxt,
             const Uint8* iv,
             const Uint8* aad,
             Uint64       aad_len)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    err = alcp_cipher_set_aad(&handle, aad, aad_len);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    err = alcp_cipher_set_pad_length(&handle, 0);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    err = alcp_cipher_decrypt(&handle, ciphertxt, plaintxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    alcp_cipher_finish(&handle);

    free(handle.ch_context);

    printf("decrypt succeeded\n");
}

// static char* sample_plaintxt = "Hello World from AOCL Crypto !!!";
static Uint8* sample_plaintxt = (Uint8*)"Happy Holi from AOCL Crypto :-)!";

static const Uint8 sample_key_cmac[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
};
static const Uint8 sample_key2_ctr[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
};
static const Uint8 aad[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
};

Uint8 iv_buff[16];

#if 0
/*
 * Encrypted text of "Hello World from AOCL Crypto !!!"
 * with key = {00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f};
 * with iv = {00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f};
 */

static Uint8 cipher = {68,cc,95,fe,db,6c,0c,87,76,73,98,fc,0a,dc,f6,07,9e,33,17,75,ad,0a,eb,27,66,29,f3,9e,b6,8d,1f,05};
#else
static Uint8 sample_ciphertxt[512] = {
    0,
};
#endif

#define BITS_PER_BYTE 8

int
main(void)
{
    int   size               = strlen((const char*)sample_plaintxt);
    Uint8 sample_output[512] = { 0 };

    assert(sizeof(sample_plaintxt) < sizeof(sample_output));

    create_demo_session(
        sample_key_cmac, sample_key2_ctr, sizeof(sample_key_cmac) * 8);

    encrypt_demo(
        sample_plaintxt, size, sample_ciphertxt, iv_buff, aad, sizeof(aad));
    char* o = bytesToHexString(sample_ciphertxt, size);
    printf("CT:%s\n", o);
    free(o);

    create_demo_session(
        sample_key_cmac, sample_key2_ctr, sizeof(sample_key_cmac) * 8);

    decrypt_demo(
        sample_ciphertxt, size, sample_output, iv_buff, aad, sizeof(aad));

    printf("sample_output: %s\n", sample_output);
    /*
     * Complete the transaction
     */

    return 0;
}

char*
bytesToHexString(unsigned char* bytes, int length)
{
    char* outputHexString = malloc(sizeof(char) * ((length * 2) + 1));
    for (int i = 0; i < length; i++) {
        char chararray[2];
        chararray[0] = (bytes[i] & 0xf0) >> 4;
        chararray[1] = bytes[i] & 0x0f;
        for (int j = 0; j < 2; j++) {
            switch (chararray[j]) {
                case 0x0:
                    chararray[j] = '0';
                    break;
                case 0x1:
                    chararray[j] = '1';
                    break;
                case 0x2:
                    chararray[j] = '2';
                    break;
                case 0x3:
                    chararray[j] = '3';
                    break;
                case 0x4:
                    chararray[j] = '4';
                    break;
                case 0x5:
                    chararray[j] = '5';
                    break;
                case 0x6:
                    chararray[j] = '6';
                    break;
                case 0x7:
                    chararray[j] = '7';
                    break;
                case 0x8:
                    chararray[j] = '8';
                    break;
                case 0x9:
                    chararray[j] = '9';
                    break;
                case 0xa:
                    chararray[j] = 'a';
                    break;
                case 0xb:
                    chararray[j] = 'b';
                    break;
                case 0xc:
                    chararray[j] = 'c';
                    break;
                case 0xd:
                    chararray[j] = 'd';
                    break;
                case 0xe:
                    chararray[j] = 'e';
                    break;
                case 0xf:
                    chararray[j] = 'f';
                    break;
                default:
                    printf("%x %d\n", chararray[j], j);
            }
            outputHexString[i * 2 + j] = chararray[j];
        }
    }
    outputHexString[length * 2] = 0x0;
    return outputHexString;
}
