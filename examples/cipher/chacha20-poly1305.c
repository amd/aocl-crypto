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
#include "alcp/alcp.h"
#include <stdio.h>
#include <stdlib.h> // For malloc
#include <string.h> // for memset
char*
bytesToHexString(unsigned char* bytes, int length);

static alc_cipher_handle_t handle;
int
create_demo_session(const Uint8* key,
                    const Uint8* iv,
                    Uint64       iv_length,
                    const Uint32 key_len)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    alc_cipher_aead_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_CHACHA20_POLY1305,
        .ci_algo_info   = {
           .ai_mode = ALC_AES_MODE_NONE,
           .ai_iv   = iv,
           .iv_length =iv_length
           
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
    err = alcp_cipher_aead_supported(&cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }
    printf("supported succeeded\n");
    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_aead_context_size(&cinfo));
    if (!handle.ch_context)
        return -1;

    /* Request a context with cinfo */
    err = alcp_cipher_aead_request(&cinfo, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }
    printf("request succeeded\n");
    return 0;
}

int
alcp_chacha20_poly1305_encrypt_demo(
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
    err = alcp_cipher_aead_set_tag_length(&handle, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, ad, adLen);
    if (alcp_is_error(err)) {
        printf("Error: unable Chacha20-Poly1305 add data processing \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // Chacha20-Poly1305 encrypt
    err =
        alcp_cipher_aead_encrypt_update(&handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // get tag. Once Tag is obtained encrypt_update cannot be called again and
    // will return an error.
    err = alcp_cipher_aead_get_tag(&handle, tag, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    return ALC_ERROR_NONE;
}

int
alcp_chacha20_poly1305_decrypt_demo(
    const Uint8* ciphertxt,
    const Uint32 len, /* Describes both 'plaintxt' and 'ciphertxt' */
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
    err = alcp_cipher_aead_set_tag_length(&handle, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, ad, adLen);
    if (alcp_is_error(err)) {
        printf("Error: unable Chacha20-Poly1305 add data processing \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // Chacha20-Poly1305 decrypt
    err =
        alcp_cipher_aead_decrypt_update(&handle, ciphertxt, plaintxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // get tag
    err = alcp_cipher_aead_get_tag(&handle, tagDecrypt, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    char* hex_tagDecrypt = bytesToHexString(tagDecrypt, tagLen);
    printf("TAG Decrypt:%s\n", hex_tagDecrypt);
    free(hex_tagDecrypt);

    bool isTagMatched = true;

    for (int i = 0; i < tagLen; i++) {
        if (tagDecrypt[i] != tag[i]) {
            isTagMatched = isTagMatched & false;
        }
    }

    if (isTagMatched == false) {
        printf("\n Tag mismatched, input encrypted data is not trusthworthy\n");
        memset(plaintxt, 0, len);
        return -1;
    } else {
        printf("\n Encrypt and Decrypt Tag is matched.\n");
    }

    return 0;
}

static Uint8 sample_plaintxt[] =
    "Happy and Fantastic Diwali from AOCL Crypto !!";

static Uint8 sample_ciphertxt[sizeof(sample_plaintxt)] = {
    0,
};

// Key Size has to be 256 bits
static const Uint8 sample_key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
                                    0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
                                    0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94,
                                    0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
                                    0x9c, 0x9d, 0x9e, 0x9f };

// IV Size has to be 96 bits
static const Uint8 sample_iv[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                                   0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

// Additional data
static const Uint8 sample_ad[] = "Hello World, this is a sample AAD, "
                                 "there can be a large value for AAD";

int
main(int argc, char const* argv[])
{
    int   retval                = 0;
    Uint8 sample_tag_output[16] = {};
    Uint8 decrypted_plaintext[sizeof(sample_plaintxt)];
    retval = create_demo_session(
        sample_key, sample_iv, sizeof(sample_iv) * 8, sizeof(sample_key) * 8);
    if (retval != 0)
        goto out;

    retval = alcp_chacha20_poly1305_encrypt_demo(sample_plaintxt,
                                                 sizeof(sample_plaintxt),
                                                 sample_ciphertxt,
                                                 sample_iv,
                                                 sizeof(sample_iv),
                                                 sample_ad,
                                                 sizeof(sample_ad),
                                                 sample_tag_output,
                                                 sizeof(sample_tag_output));
    if (retval != 0)
        goto out;
    char* plaintext_hex_string =
        bytesToHexString(sample_plaintxt, sizeof(sample_plaintxt));

    printf("PlaintextOut:%s\n", plaintext_hex_string);

    free(plaintext_hex_string);

    char* ciphertext_hex_string =
        bytesToHexString(sample_ciphertxt, sizeof(sample_ciphertxt));

    printf("CiphertextOut:%s\n", ciphertext_hex_string);

    free(ciphertext_hex_string);

    char* tag_hex_string =
        bytesToHexString(sample_tag_output, sizeof(sample_tag_output));
    printf("Encrypt TAG :%s\n", tag_hex_string);
    free(tag_hex_string);

    alcp_cipher_aead_finish(&handle);
    free(handle.ch_context);

    retval = create_demo_session(
        sample_key, sample_iv, sizeof(sample_iv) * 8, sizeof(sample_key) * 8);
    if (retval != 0)
        goto out;
    retval = alcp_chacha20_poly1305_decrypt_demo(sample_ciphertxt,
                                                 sizeof(sample_ciphertxt),
                                                 decrypted_plaintext,
                                                 sample_iv,
                                                 sizeof(sample_iv),
                                                 sample_ad,
                                                 sizeof(sample_ad),
                                                 sample_tag_output,
                                                 sizeof(sample_tag_output));

    if (retval != 0)
        goto out;

    printf("sample_output: %s\n", decrypted_plaintext);
    alcp_cipher_aead_finish(&handle);

    free(handle.ch_context);

    return 0;

out:
    return -1;
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
