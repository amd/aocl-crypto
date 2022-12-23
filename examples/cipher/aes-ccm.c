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

static alc_cipher_handle_t handle;

char*
bytesToHexString(unsigned char* bytes, int length);

void
create_demo_session(const Uint8* key, const Uint8* iv, const Uint32 key_len)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    /*
    const alc_key_info_t kinfo = {
        .type    = ALC_KEY_TYPE_SYMMETRIC,
        .fmt     = ALC_KEY_FMT_RAW,
        .key     = key,
        .len     = key_len,
    };
    */
    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,
        .ci_algo_info   = {
           .ai_mode = ALC_AES_MODE_CCM,
           .ai_iv   = iv,
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

static Uint8* sample_plaintxt =
    (Uint8*)"Happy and Fantastic Diwali from AOCL Crypto !!";

static const Uint8 sample_key[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
};

static const Uint8 sample_iv[] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9 };

static const Uint8* sample_ad = (Uint8*)"Hello World, this is a sample AAD, "
                                        "there can be a large value for AAD";

static Uint8 sample_ciphertxt[512] = {
    0,
};

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

/* CCM: Authenticated Encryption demo */
void
aclp_aes_ccm_encrypt_demo(
    const Uint8* plaintxt,
    const Uint32 len, /* Describes both 'plaintxt' and 'ciphertxt' */
    Uint8*       ciphertxt,
    const Uint8* iv,
    const Uint32 ivLen,
    const Uint8* ad,
    const Uint32 adLen,
    Uint8*       tag,
    const Uint32 tagLen)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    // set tag length
    err = alcp_cipher_set_tag_length(&handle, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // CCM init
    err = alcp_cipher_set_iv(&handle, ivLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable ccm encrypt init \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // Additional Data
    err = alcp_cipher_set_aad(&handle, ad, adLen);
    if (alcp_is_error(err)) {
        printf("Error: unable ccm add data processing \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // CCM encrypt
    err = alcp_cipher_encrypt_update(&handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // get tag
    err = alcp_cipher_get_tag(&handle, tag, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
}

/* CCM: Authenticated Decryption demo */
void
aclp_aes_ccm_decrypt_demo(const Uint8* ciphertxt,
                          const Uint32 len,
                          Uint8*       plaintxt,
                          const Uint8* iv,
                          const Uint32 ivLen,
                          const Uint8* ad,
                          const Uint32 adLen,
                          Uint8*       tag,
                          const Uint32 tagLen)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];
    Uint8       tagDecrypt[16];

    // set tag length
    err = alcp_cipher_set_tag_length(&handle, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // GCM init
    err = alcp_cipher_set_iv(&handle, ivLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm decrypt init \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // Additional Data
    err = alcp_cipher_set_aad(&handle, ad, adLen);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm add data processing \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // GCM decrypt
    err = alcp_cipher_decrypt_update(&handle, ciphertxt, plaintxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // get tag
    err = alcp_cipher_get_tag(&handle, tagDecrypt, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    char* hex_tagDecrypt = bytesToHexString(tagDecrypt, 14);
    printf("TAG Decrypt:%s\n", hex_tagDecrypt);
    free(hex_tagDecrypt);

    bool isTagMatched = true;

    for (int i = 0; i < tagLen; i++) {
        if (tagDecrypt[i] != tag[i]) {
            isTagMatched = isTagMatched & false;
        }
    }

    if (isTagMatched == false) {
        printf("\n tag mismatched, input encrypted data is not trusthworthy ");
        memset(plaintxt, 0, len);
    }
}

int
main(void)
{
    Uint8 sample_output[512]    = { 0 };
    Uint8 sample_tag_output[17] = { 0 };

    assert(sizeof(sample_plaintxt) < sizeof(sample_output));

    create_demo_session(sample_key, sample_iv, sizeof(sample_key) * 8);

    aclp_aes_ccm_encrypt_demo(sample_plaintxt,
                              strlen((const char*)sample_plaintxt),
                              sample_ciphertxt,
                              sample_iv,
                              sizeof(sample_iv),
                              sample_ad,
                              strlen((const char*)sample_ad),
                              sample_tag_output,
                              14);

    int size = strlen((const char*)sample_plaintxt);

    char* hex_sample_output = bytesToHexString(
        sample_ciphertxt, strlen((const char*)sample_plaintxt));
    char* hex_sample_input =
        bytesToHexString(sample_plaintxt, strlen((const char*)sample_plaintxt));
    char* hex_sample_tag_output = bytesToHexString(sample_tag_output, 14);

    printf("PlainTextOut :%s\n", hex_sample_input);
    printf("CipherTextOut:%s\n", hex_sample_output);
    printf("          TAG:%s\n", hex_sample_tag_output);

    free(hex_sample_output);
    free(hex_sample_input);
    free(hex_sample_tag_output);

    aclp_aes_ccm_decrypt_demo(sample_ciphertxt,
                              size,
                              sample_output,
                              sample_iv,
                              sizeof(sample_iv),
                              sample_ad,
                              strlen((const char*)sample_ad),
                              sample_tag_output,
                              14);

    printf("sample_output: %s\n", sample_output);

    // /*
    //  * Complete the transaction
    //  */
    alcp_cipher_finish(&handle);

    free(handle.ch_context);

    return 0;
}

/*  LocalWords:  decrypt Crypto AOCL
 */

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
