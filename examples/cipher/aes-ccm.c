/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#define MULTI_UPDATE_ENABLED 0
#define BITS_PER_BYTE        8
#define BITS_PER_BYTE        8

static alc_cipher_handle_t handle = { NULL };

// Session Helpers
/**
 * @brief Deallocate handle and set to nullpointer
 */
void
deallocate_handle()
{
    if (handle.ch_context != NULL) {
        free(handle.ch_context);
        handle.ch_context = NULL;
    }
}

/**
 * @brief Finish and Deallocate the handle
 */
void
close_demo_session()
{
    alcp_cipher_aead_finish(&handle);
    deallocate_handle();
}

/**
 * @brief In case of an error, return -1 after deallocating handle.
 * @return -1
 */
int
close_demo_session_exit()
{
    // Finish and deallocate the handle
    close_demo_session();
    return -1;
}

/**
 * @brief Creates demosession given keylen
 * @param key_len  Length of key in bytes
 * @return 0 if success
 */
int
create_demo_session(const alc_key_len_t keyLen)
{
    alc_error_t err;

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_aead_context_size());
    if (!handle.ch_context)
        return -1;

    /* Request a context with cipher mode and keyLen */
    err = alcp_cipher_aead_request(ALC_AES_MODE_CCM, keyLen, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        return close_demo_session_exit();
    }

    printf("Request Succeeded\n");
    return 0;
}

// Print Helpers

void
printHexString(const char* info, const unsigned char* bytes, int length);

// Here its a 48 Byte plaintext message
static Uint8 sample_plaintxt[] =
    "Happy and Fantastic Diwali from AOCL Crypto !!!!";

static Uint8 sample_key[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
};

static Uint8 sample_iv[] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9 };

static const Uint8* sample_ad = (Uint8*)"Hello World, this is a sample AAD, "
                                        "there can be a large value for AAD";
/* CCM: Authenticated Encryption demo */
int
aclp_aes_ccm_encrypt_demo(
    const Uint8* plaintxt,
    Uint32       len, /* Describes both 'plaintxt' and 'ciphertxt' */
    Uint8*       ciphertxt,
    const Uint8* iv,
    Uint32       ivLen,
    const Uint8* ad,
    Uint32       aadLen,
    Uint8*       tag,
    Uint32       tagLen,
    const Uint8* pKey,
    Uint32       keyLen)
{
    alc_error_t err      = ALC_ERROR_NONE;
    int         retval   = 0;
    const int   cErrSize = 256;
    Uint8       err_buf[cErrSize];

    // Create session for encryption
    retval = create_demo_session(sizeof(sample_key) * 8);
    if (retval != 0) {
        return close_demo_session_exit();
    }

    // set tag length
    err = alcp_cipher_aead_set_tag_length(&handle, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, cErrSize);
        return close_demo_session_exit();
    }

#if MULTI_UPDATE_ENABLED
    err = alcp_cipher_aead_set_ccm_plaintext_length(&handle, len);
    if (alcp_is_error(err)) {
        printf("Error: unable setting plaintext Length \n");
        alcp_error_str(err, err_buf, err_size);
        return close_demo_session_exit();
        return close_demo_session_exit();
    }
#endif

    // CCM init
    err = alcp_cipher_aead_init(&handle, pKey, keyLen, iv, ivLen);
    if (alcp_is_error(err)) {
        printf("Error: unable ccm encrypt init \n");
        alcp_error_str(err, err_buf, cErrSize);
        return close_demo_session_exit();
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, ad, aadLen);
    if (alcp_is_error(err)) {
        printf("Error: unable ccm add data processing \n");
        alcp_error_str(err, err_buf, cErrSize);
        return close_demo_session_exit();
    }
#if MULTI_UPDATE_ENABLED

    // CCM encrypt
    err = alcp_cipher_aead_encrypt(&handle, plaintxt, ciphertxt, len - 16);
    if (alcp_is_error(err)) {
        printf("Error: unable encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return close_demo_session_exit();
        return close_demo_session_exit();
    }

    err = alcp_cipher_aead_encrypt(
        &handle, plaintxt + (len - 16), ciphertxt + (len - 16), 16);
    if (alcp_is_error(err)) {
        printf("Error: unable encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return close_demo_session_exit();
        return close_demo_session_exit();
    }
#else
    err = alcp_cipher_aead_encrypt(&handle, plaintxt, ciphertxt, len);
    if (alcp_is_error(err)) {
        printf("Error: unable encrypt \n");
        alcp_error_str(err, err_buf, cErrSize);
        return close_demo_session_exit();
    }
#endif

    // get tag
    err = alcp_cipher_aead_get_tag(&handle, tag, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, cErrSize);
        return close_demo_session_exit();
    }

    printf("Encrypt succeeded\n");

    // Close the encrypt session
    close_demo_session();
    return 0;
}

/* CCM: Authenticated Decryption demo */
int
aclp_aes_ccm_decrypt_demo(const Uint8* ciphertxt,
                          Uint32       len,
                          Uint8*       plaintxt,
                          const Uint8* iv,
                          Uint32       ivLen,
                          const Uint8* ad,
                          Uint32       aadLen,
                          Uint8*       tag,
                          Uint32       tagLen,
                          const Uint8* pKey,
                          Uint32       keyLen)
{
    alc_error_t err      = ALC_ERROR_NONE;
    int         retval   = 0;
    const int   cErrSize = 256;
    Uint8       err_buf[cErrSize];
    Uint8       tag_decrypt[16];

    // Create session for decrypt
    retval = create_demo_session(sizeof(sample_key) * 8);
    if (retval != 0) {
        return close_demo_session_exit();
    }

    // Set Tag Length
    err = alcp_cipher_aead_set_tag_length(&handle, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, cErrSize);
        return close_demo_session_exit();
    }

#if MULTI_UPDATE_ENABLED
    // set plaintext length only after key and iv has both set with init
    err = alcp_cipher_aead_set_ccm_plaintext_length(&handle, len);
    if (alcp_is_error(err)) {
        printf("Error: unable setting Plaintext Length \n");
        alcp_error_str(err, err_buf, err_size);
        return close_demo_session_exit();
    }
#endif

    // ccm init
    err = alcp_cipher_aead_init(&handle, pKey, keyLen, iv, ivLen);
    if (alcp_is_error(err)) {
        printf("Error: unable ccm decrypt init \n");
        alcp_error_str(err, err_buf, cErrSize);
        return close_demo_session_exit();
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, ad, aadLen);
    if (alcp_is_error(err)) {
        printf("Error: unable ccm add data processing \n");
        alcp_error_str(err, err_buf, cErrSize);
        return close_demo_session_exit();
    }

    // CCM decrypt
#if MULTI_UPDATE_ENABLED
    // Decrypt can be called multiple times in case of multi-update
    err = alcp_cipher_aead_decrypt(&handle, ciphertxt, plaintxt, 16);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return close_demo_session_exit();
    }

    err = alcp_cipher_aead_decrypt(
        &handle, ciphertxt + 16, plaintxt + 16, len - 16);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return close_demo_session_exit();
    }
#else
    // Decrypt can be called only single time in case of single-update
    err = alcp_cipher_aead_decrypt(&handle, ciphertxt, plaintxt, len);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, cErrSize);
        return close_demo_session_exit();
    }
#endif

    // Get Tag
    err = alcp_cipher_aead_get_tag(&handle, tag_decrypt, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, cErrSize);
        return close_demo_session_exit();
    }

    printHexString("TAG Decrypt ", tag_decrypt, 14);

    bool is_tag_matched = true;

    // FIXME: Tag verification has to be done inside the library
    for (int i = 0; i < tagLen; i++) {
        if (tag_decrypt[i] != tag[i]) {
            is_tag_matched = is_tag_matched & false;
        }
    }

    if (is_tag_matched == false) {
        printf("\n tag mismatched, input encrypted data is not trusthworthy ");
        memset(plaintxt, 0, len);
        return close_demo_session_exit();
    }

    printf("Decrypt Succeeded\n");

    // Close the decrypt session
    close_demo_session();
    return 0;
}

int
main(void)
{
    int          retval                = 0;
    int          pt_size               = 0;
    Uint8        sample_output[512]    = { 0 };
    Uint8        sample_tag_output[17] = { 0 };
    static Uint8 sample_ciphertxt[512] = { 0 };

    assert(sizeof(sample_plaintxt) <= sizeof(sample_output));

    // Size of the plaintext
    pt_size = strlen((const char*)sample_plaintxt);

    // Do the encryption without padding
    retval = aclp_aes_ccm_encrypt_demo(sample_plaintxt,
                                       pt_size,
                                       sample_ciphertxt,
                                       sample_iv,
                                       sizeof(sample_iv),
                                       sample_ad,
                                       strlen((const char*)sample_ad),
                                       sample_tag_output,
                                       14,
                                       sample_key,
                                       sizeof(sample_key) * 8);

    // In case of an error no point in continuing with decryption
    if (retval != 0) {
        return retval;
    }

    // Print plaintext, ciphertext and tag
    printHexString("PlainTextOut ", sample_plaintxt, pt_size);
    printHexString("CipherTextOut", sample_ciphertxt, pt_size);
    printHexString("          TAG", sample_tag_output, 14);

    // Do the decryption
    // Without padding PT Len is same as CT Len
    retval = aclp_aes_ccm_decrypt_demo(sample_ciphertxt,
                                       pt_size,
                                       sample_output,
                                       sample_iv,
                                       sizeof(sample_iv),
                                       sample_ad,
                                       strlen((const char*)sample_ad),
                                       sample_tag_output,
                                       14,
                                       sample_key,
                                       sizeof(sample_key) * 8);

    // In case of an error no point in printing decrypted message
    if (retval != 0) {
        return retval;
    }

    printf("sample_output: %s\n", sample_output);
    return retval;
}

void
printHexString(const char* info, const unsigned char* bytes, int length)
{
    char* p_hex_string = malloc(sizeof(char) * ((length * 2) + 1));
    for (int i = 0; i < length; i++) {
        char chararray[2];
        chararray[0] = (bytes[i] & 0xf0) >> 4;
        chararray[1] = bytes[i] & 0x0f;
        for (int j = 0; j < 2; j++) {
            if (chararray[j] >= 0xa) {
                chararray[j] = 'a' + chararray[j] - 0xa;
            } else {
                chararray[j] = '0' + chararray[j] - 0x0;
            }
            p_hex_string[i * 2 + j] = chararray[j];
        }
    }
    p_hex_string[length * 2] = 0x0;
    printf("%s:%s\n", info, p_hex_string);
    free(p_hex_string);
}
