/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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
BytesToHexString(unsigned char* bytes, int length);

static alc_cipher_handle_t handle;
int
CreateDemoSession(const Uint8* key,
                  const Uint8* iv,
                  Uint64       ivLength,
                  const Uint32 keyLen)
{
    alc_error_t err;

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_aead_context_size());
    if (!handle.ch_context)
        return -1;

    /* Request a context with cipher mode and keyLen */
    err = alcp_cipher_aead_request(ALC_CHACHA20_POLY1305, keyLen, &handle);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        printf("Error: unable to request \n");
        return -1;
    }
    printf("request succeeded\n");
    return 0;
}

int
AlcpChacha20Poly1305EncryptDemo(
    const Uint8* plaintxt,
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

    err = alcp_cipher_aead_init(&handle, pKey, keyLen, iv, ivLen);
    if (alcp_is_error(err)) {
        printf("Error: unable init \n");
        return -1;
    }

    // set tag length
    err = alcp_cipher_aead_set_tag_length(&handle, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        return -1;
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, ad, aadLen);
    if (alcp_is_error(err)) {
        printf("Error: unable Chacha20-Poly1305 add data processing \n");
        return -1;
    }

    // Chacha20-Poly1305 encrypt
    err = alcp_cipher_aead_encrypt(&handle, plaintxt, ciphertxt, len);
    if (alcp_is_error(err)) {
        printf("Error: unable encrypt \n");
        return -1;
    }

    // get tag. Once Tag is obtained encrypt_update cannot be called again and
    // will return an error.
    err = alcp_cipher_aead_get_tag(&handle, tag, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        return -1;
    }

    return ALC_ERROR_NONE;
}

int
AlcpChacha20Poly1305DecryptDemo(const Uint8* ciphertxt,
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

    Uint8 tag_decrypt[16];

    err = alcp_cipher_aead_init(&handle, pKey, keyLen, iv, ivLen);
    if (alcp_is_error(err)) {
        printf("Error: unable init \n");
        return -1;
    }

    // set tag length
    err = alcp_cipher_aead_set_tag_length(&handle, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        return -1;
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, ad, aadLen);
    if (alcp_is_error(err)) {
        printf("Error: unable Chacha20-Poly1305 add data processing \n");
        return -1;
    }

    // FIXME: init call needs to be added to set key and iv.

    // Chacha20-Poly1305 decrypt
    err = alcp_cipher_aead_decrypt(&handle, ciphertxt, plaintxt, len);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        return -1;
    }

    // get tag
    err = alcp_cipher_aead_get_tag(&handle, tag_decrypt, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        return -1;
    }

    char* p_hex_tag_decrypt = BytesToHexString(tag_decrypt, tagLen);
    printf("TAG Decrypt:%s\n", p_hex_tag_decrypt);
    free(p_hex_tag_decrypt);

    bool is_tag_matched = true;

    for (int i = 0; i < tagLen; i++) {
        if (tag_decrypt[i] != tag[i]) {
            is_tag_matched = is_tag_matched & false;
        }
    }

    if (is_tag_matched == false) {
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
static const Uint8 cSampleKey[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
                                    0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
                                    0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94,
                                    0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
                                    0x9c, 0x9d, 0x9e, 0x9f };

// IV Size has to be 96 bits
static const Uint8 cSampleIv[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                                   0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

// Additional data
static const Uint8 cSampleAd[] = "Hello World, this is a sample AAD, "
                                 "there can be a large value for AAD";

int
main(int argc, char const* argv[])
{
    int   retval                = 0;
    Uint8 sample_tag_output[16] = {};
    Uint8 decrypted_plaintext[sizeof(sample_plaintxt)];
    retval = CreateDemoSession(
        cSampleKey, cSampleIv, sizeof(cSampleIv) * 8, sizeof(cSampleKey) * 8);
    if (retval != 0)
        goto out;

    retval = AlcpChacha20Poly1305EncryptDemo(sample_plaintxt,
                                             sizeof(sample_plaintxt),
                                             sample_ciphertxt,
                                             cSampleIv,
                                             sizeof(cSampleIv),
                                             cSampleAd,
                                             sizeof(cSampleAd),
                                             sample_tag_output,
                                             sizeof(sample_tag_output),
                                             cSampleKey,
                                             sizeof(cSampleKey) * 8);
    if (retval != 0)
        goto out;
    char* p_plaintext_hex_string =
        BytesToHexString(sample_plaintxt, sizeof(sample_plaintxt));

    printf("PlaintextOut:%s\n", p_plaintext_hex_string);

    free(p_plaintext_hex_string);

    char* p_ciphertext_hex_string =
        BytesToHexString(sample_ciphertxt, sizeof(sample_ciphertxt));

    printf("CiphertextOut:%s\n", p_ciphertext_hex_string);

    free(p_ciphertext_hex_string);

    char* p_tag_hex_string =
        BytesToHexString(sample_tag_output, sizeof(sample_tag_output));
    printf("Encrypt TAG :%s\n", p_tag_hex_string);
    free(p_tag_hex_string);

    alcp_cipher_aead_finish(&handle);
    free(handle.ch_context);

    retval = CreateDemoSession(
        cSampleKey, cSampleIv, sizeof(cSampleIv) * 8, sizeof(cSampleKey) * 8);
    if (retval != 0)
        goto out;
    retval = AlcpChacha20Poly1305DecryptDemo(sample_ciphertxt,
                                             sizeof(sample_ciphertxt),
                                             decrypted_plaintext,
                                             cSampleIv,
                                             sizeof(cSampleIv),
                                             cSampleAd,
                                             sizeof(cSampleAd),
                                             sample_tag_output,
                                             sizeof(sample_tag_output),
                                             cSampleKey,
                                             sizeof(cSampleKey) * 8);

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
BytesToHexString(unsigned char* bytes, int length)
{
    char* p_output_hex_string = malloc(sizeof(char) * ((length * 2) + 1));
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
            p_output_hex_string[i * 2 + j] = chararray[j];
        }
    }
    p_output_hex_string[length * 2] = 0x0;
    return p_output_hex_string;
}
