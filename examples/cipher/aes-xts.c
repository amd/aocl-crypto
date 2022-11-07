/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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
#include "alcp/types.h"

#ifdef DEBUG
#define ALC_PRINT(a, size)                                                     \
    for (int x = 0; x < size; x++) {                                           \
        if (x % 16 == 0)                                                       \
            printf("\n0x%x0 - ", (x / 16));                                    \
        printf(" %2x ", (a)[x]);                                               \
    }                                                                          \
    printf("\n");
#else
#define ALC_PRINT(a, size)
#endif

static alc_cipher_handle_t handle;

void
create_demo_session(const Uint8* key,
                    const Uint8* tweak_key,
                    const Uint8* iv,
                    const Uint32 key_len)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    alc_key_info_t kinfo = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .key  = tweak_key,
        .len  = key_len,
    };

    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,

        .ci_algo_info = {
            .ai_mode = ALC_AES_MODE_XTS,
            .ai_iv   = iv,
            .ai_xts = {
                .xi_tweak_key = &kinfo,
            }
        },
            /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE, 
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = key,
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
             const Uint8* iv)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    err = alcp_cipher_encrypt(&handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    printf("encrypt succeeded\n");
}

void
decrypt_demo(const Uint8* ciphertxt,
             const Uint32 len, /* for both 'plaintxt' and 'ciphertxt' */
             Uint8*       plaintxt,
             const Uint8* iv)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    err = alcp_cipher_decrypt(&handle, ciphertxt, plaintxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    printf("decrypt succeeded\n");
}

// static char* sample_plaintxt = "Hello World from AOCL Crypto !!!";
static char* sample_plaintxt =
    "A paragraph is a series of sentences that are organized and coherent, and "
    "are all related to a single topic. Almost every piece of writing you do "
    "that is longer than a few sentences should be organized into paragraphs.";

static const Uint8 sample_key[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
};

static const Uint8 sample_tweak_key[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xf, 0xf,
};

static const Uint8 sample_iv[] = {
    0xf, 0x0, 0xe, 0x1, 0xd, 0x2, 0xc, 0x3,
    0xb, 0x4, 0xa, 0x5, 0x9, 0x6, 0x8, 0x7,
};

#if 0
/*
 * Encrypted text of "Hello World from AOCL Crypto !!!"
 * with key = {00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f};
 * with iv = {00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f};
 */

static Uint8 cipher = {68,cc,95,fe,db,6c,0c,87,76,73,98,fc,0a,dc,f6,07,9e,33,17,75,ad,0a,eb,27,66,29,f3,9e,b6,8d,1f,05};
#else
static Uint8 sample_ciphertxt[1000] = {
    0,
};
#endif

#define BITS_PER_BYTE 8

int
alloc_and_test()
{
    void *    plaintxt, *ciphertxt, *output;
    const int keylen = 256, keylen_bytes = keylen / 8,
              keylen_words = keylen / sizeof(Uint32) * BITS_PER_BYTE;

    Uint8  key[keylen_bytes];
    Uint32 iv[] = {
        0x1,
        0x2,
        0x3,
        0x4,
    };

    assert(keylen_words == sizeof(iv));

    /* TODO: get this through command line */
    int buf_len = 1024 * 1024; /* Length of 1 buffer */
    int num_buf = 1;           /* number of buffers of length 'buf_len' */

    plaintxt = calloc(buf_len, num_buf);
    if (!plaintxt)
        goto out;

    ciphertxt = calloc(buf_len, num_buf);
    if (!ciphertxt)
        goto free_plaintxt_out;

    output = calloc(buf_len, num_buf);
    if (!output)
        goto free_ciphertxt_out;

free_ciphertxt_out:
    free(ciphertxt);

free_plaintxt_out:
    free(plaintxt);

out:
    return 0;
}

int
main(void)
{
    Uint8 sample_output[1000] = { 0 };

    int pt_size = strlen(sample_plaintxt);
    assert(sizeof(sample_plaintxt) < sizeof(sample_output));

    create_demo_session(
        sample_key, sample_tweak_key, sample_iv, sizeof(sample_key) * 8);

#ifdef DEBUG
    printf("plain text with size %d: \n", pt_size);
    ALC_PRINT(((Uint8*)sample_plaintxt), pt_size);
#endif
    encrypt_demo(sample_plaintxt,
                 pt_size, /* len of 'plaintxt' and 'ciphertxt' */
                 sample_ciphertxt,
                 sample_iv);
#ifdef DEBUG
    printf("cipher text with size: %d \n", pt_size);
    ALC_PRINT(((Uint8*)&sample_ciphertxt), pt_size);
#endif
    decrypt_demo(sample_ciphertxt, pt_size, sample_output, sample_iv);
#ifdef DEBUG
    printf("out text with size %d: \n", pt_size);
    ALC_PRINT(((Uint8*)&sample_output), pt_size);
#endif
    printf("sample_output: %s\n", sample_output);
    /*
     * Complete the transaction
     */
    alcp_cipher_finish(&handle);

    free(handle.ch_context);

    return 0;
}

/*  LocalWords:  decrypt Crypto AOCL
 */
