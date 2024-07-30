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

#include <alcp/alcp.h>

#define BITS_PER_BYTE 8

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
create_demo_session(Uint32 key_len)
{
    alc_error_t err;

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_aead_context_size());

    // Memory allocation failure checking
    if (!handle.ch_context) {
        printf("Error: Memory Allocation Failed!\n");
        return close_demo_session_exit();
    }

    // Request a cipher session with AES mode and key
    err = alcp_cipher_aead_request(ALC_AES_MODE_SIV, key_len, &handle);
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

int
encrypt_demo(const Uint8* plaintxt,
             Uint32       len, /* Describes both 'plaintxt' and 'ciphertxt' */
             Uint8*       ciphertxt,
             const Uint8* iv,
             Uint32       iv_len,
             const Uint8* ad,
             Uint32       aadLen,
             Uint8*       tag,
             Uint32       tag_len,
             const Uint8* pKey,
             Uint32       key_len)
{
    alc_error_t err    = ALC_ERROR_NONE;
    int         retval = 0;

    retval = create_demo_session(key_len);
    if (retval != 0) {
        return close_demo_session_exit(); // Error condtion
    }

    // FIXME: Try making IV nullptr
    err = alcp_cipher_aead_init(&handle, pKey, key_len, iv, iv_len);
    if (alcp_is_error(err)) {
        printf("Error: Unable to init \n");
        return close_demo_session_exit();
    }

    err = alcp_cipher_aead_set_aad(&handle, ad, aadLen);
    if (alcp_is_error(err)) {
        printf("Error: Unable to Encrypt \n");
        return close_demo_session_exit();
    }

    err = alcp_cipher_aead_encrypt(&handle, plaintxt, ciphertxt, len);
    if (alcp_is_error(err)) {
        printf("Error: Unable to Encrypt \n");
        return close_demo_session_exit();
    }

    err = alcp_cipher_aead_get_tag(&handle, tag, 16);
    if (alcp_is_error(err)) {
        printf("Error: Unable to get Tag \n");
        return close_demo_session_exit();
    }

    printf("Encrypt succeeded\n");

    // Close the encrypt session
    close_demo_session();

    return 0;
}

bool
decrypt_demo(const Uint8* ciphertxt,
             Uint32       len,
             Uint8*       plaintxt,
             const Uint8* iv,
             Uint32       iv_len,
             const Uint8* ad,
             Uint32       aadLen,
             Uint8*       tag,
             Uint32       tag_len,
             const Uint8* pKey,
             Uint32       key_len)
{
    alc_error_t err    = ALC_ERROR_NONE;
    int         retval = 0;

    // Request a demo session with cipher mode as ALC_AES_MODE_SIV, and
    // initialize it
    retval = create_demo_session(key_len);
    if (retval != 0) {
        return close_demo_session_exit();
    }

    // Initialize the session handle with proper key and iv.
    // Iv passed here is the tag generated from encrypt call.
    err = alcp_cipher_aead_init(&handle, pKey, key_len, iv, iv_len);
    if (alcp_is_error(err)) {
        printf("Error: Unable to init \n");
        return close_demo_session_exit();
    }

    err = alcp_cipher_aead_set_aad(&handle, ad, aadLen);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        return close_demo_session_exit();
    }

    // Decrypt the ciphertext with the initialized key and iv
    err = alcp_cipher_aead_decrypt(&handle, ciphertxt, plaintxt, len);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        return close_demo_session_exit();
    }

    printf("Decrypt Succeeded\n");

    // Close the decrypt session
    close_demo_session();
    return 0;
}

static Uint8 sample_plaintxt[] = "Happy Holi from AOCL Crypto :-)!";

// clang-format off
static Uint8 sample_key[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,// CMAC KEY
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,// CTR KEY
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
};
// clang-format on

static Uint8 aad[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
};

int
main(void)
{
    int          retval                = 0;
    int          pt_size               = 0;
    Uint8        sample_output[512]    = { 0 };
    Uint8        iv_buff[16]           = { 0 };
    Uint8        tag[16]               = { 0 };
    const Uint64 cKeySize              = (sizeof(sample_key) * 8) / 2;
    static Uint8 sample_ciphertxt[512] = { 0 };

    assert(sizeof(sample_plaintxt) <= sizeof(sample_output));

    pt_size = strlen((const char*)sample_plaintxt);

    // Encrypt the plaintext into ciphertext, get synthetic iv as tag and
    // end the demo session
    retval = encrypt_demo(sample_plaintxt,
                          pt_size,
                          sample_ciphertxt,
                          iv_buff,
                          sizeof(iv_buff),
                          aad,
                          sizeof(aad),
                          tag,
                          sizeof(tag),
                          sample_key,
                          cKeySize);

    // Make sure the encryption process was successfull
    if (retval != 0) {
        return -1; // Error condtion
    }

    // Print plaintext, ciphertext and tag
    printHexString("    PlainText", sample_plaintxt, pt_size);
    printHexString("CipherTextOut", sample_ciphertxt, pt_size);
    printHexString("          TAG", tag, 16);

    // Tag from encryption is the synthetic iv for decryption
    memcpy(iv_buff, tag, sizeof(iv_buff)); // Copy Tag to IV as its Sythetic IV.

    retval = decrypt_demo(sample_ciphertxt,
                          pt_size,
                          sample_output,
                          iv_buff,
                          sizeof(iv_buff),
                          aad,
                          sizeof(aad),
                          tag,
                          sizeof(tag),
                          sample_key,
                          cKeySize);

    // In case of an error no point in printing decrypted message
    if (retval != 0) {
        return -1;
    }

    printf("sample_output: %s\n", sample_output);
    return 0;
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
