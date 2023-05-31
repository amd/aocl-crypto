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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h> /* for malloc */
#include <string.h>

#include <alcp/alcp.h>

static inline void
dump_hex(Uint8* value, size_t size)
{
    printf("{ ");
    for (int i = 0; i < size; i++) {
        printf("0x%02x", *value);
        value++;
        if (i != (size - 1)) {
            printf(", ");
        } else {
            printf(" }");
        }
    }
    printf("\n");
}

void
create_demo_session(alc_cipher_handle_p handle,
                    const Uint8*        key,
                    const Uint8*        iv,
                    const alc_key_len_t cKeyLen)
{
    alc_error_t err;
    const int   cErrSize = 256;
    Uint8       err_buf[cErrSize];

    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = key,
            .len     = cKeyLen,
        },
        .ci_algo_info   = {
           .ai_mode = ALC_AES_MODE_CFB,
           .ai_iv   = iv,
        },
    };

    /*
     * Check if the current cipher is supported,
     * optional call, alcp_cipher_request() will anyway return
     * ALC_ERROR_NOT_SUPPORTED error.
     *
     * This query call is provided to support fallback mode for applications
     */
    err = alcp_cipher_supported(&cinfo);
    if (alcp_is_error(err)) {
        printf("Error: Not Supported \n");
        goto out;
    }
    printf("Support succeeded\n");

    /*
     * Application is expected to allocate for context
     */
    handle->ch_context = malloc(alcp_cipher_context_size(&cinfo));

    // Memory allocation failure checking
    if (handle->ch_context == NULL) {
        printf("Error: Memory Allocation Failed!\n");
        exit(-1);
    }

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, handle);
    if (alcp_is_error(err)) {
        printf("Error: Unable to Request \n");
        goto out;
    }
    printf("Request Succeeded\n");
    return;

    // Incase of error, program execution will come here
out:
    alcp_error_str(err, err_buf, cErrSize);
    printf("%s\n", err_buf);
    return;
}

void
encrypt_demo(alc_cipher_handle_p handle,
             const Uint8*        plaintxt,
             const Uint32        len, /*  for both 'plaintxt' and 'ciphertxt' */
             Uint8*              ciphertxt,
             const Uint8*        iv)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    err = alcp_cipher_encrypt(handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: Unable to Encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        printf("%s\n", err_buf);
        return;
    }

    printf("Encrypt succeeded\n");
}

void
decrypt_demo(alc_cipher_handle_p handle,
             const Uint8*        ciphertxt,
             const Uint32        len, /* for both 'plaintxt' and 'ciphertxt' */
             Uint8*              plaintxt,
             const Uint8*        iv)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    err = alcp_cipher_decrypt(handle, ciphertxt, plaintxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: Unable to Decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        printf("%s\n", err_buf);
        return;
    }

    printf("Decrypt Succeeded\n");
}

// Plain text to encrypt, it should be 128bits (16bytes) multiple.
// 128bits is the block size for AES
static Uint8* sample_plaintxt =
    (Uint8*)"Happy and Fantastic New Year from AOCL Crypto !!";

// Key can be 128bits, 192bits, 256bits. Currently its 128bits
static const Uint8 sample_key[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
};

// IV must be 128 bits
static const Uint8 sample_iv[] = {
    0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
};

// Buffer to write encrypted message into
// It should have size greater than or equal to plaintext as there is no padding
static Uint8 sample_ciphertxt[512] = {
    0,
};

int
main(void)
{
    // Buffer to write plain text into.
    // It should have size greater than or equal to the plaintext.
    Uint8     sample_output[512] = { 0 };
    const int cPlaintextSize     = strlen((const char*)sample_plaintxt);
    const int cCiphertextSize    = cPlaintextSize; // No padding

    printf("Input Text: %s\n", sample_plaintxt);

    // Create the handle, this handle will be used for encrypt and decrypt
    // operations
    alc_cipher_handle_t handle;
    create_demo_session(&handle, sample_key, sample_iv, ALC_KEY_LEN_128);

    // Encrypt the plaintext into the ciphertext
    encrypt_demo(&handle,
                 sample_plaintxt,
                 cPlaintextSize, /* len of 'plaintxt' and 'ciphertxt' */
                 sample_ciphertxt,
                 sample_iv);

    printf("CipherText:");
    dump_hex(sample_ciphertxt, cCiphertextSize);

    // Decrypt the ciphertext into the plaintext.
    decrypt_demo(
        &handle, sample_ciphertxt, cCiphertextSize, sample_output, sample_iv);
    printf("Decrypted Text: %s\n", sample_output);

    /*
     * Complete the transaction
     */
    alcp_cipher_finish(&handle);

    // Free the memory allocated by create_demo_session.
    free(handle.ch_context);

    return 0;
}

/*  LocalWords:  decrypt Crypto AOCL
 */
