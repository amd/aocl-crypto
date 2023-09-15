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

int
create_demo_session(alc_cipher_handle_p handle,
                    const Uint8*        key,
                    const Uint8*        iv,
                    Uint64              ivlength,
                    const alc_key_len_t cKeyLen)
{
    alc_error_t err;
    const int   cErrSize = 256;
    Uint8       err_buf[cErrSize];

    alc_cipher_info_t cinfo = {
      .ci_type = ALC_CIPHER_TYPE_CHACHA20, // Using Chacha20 Stream Cipher
      .ci_key_info =
          {
              .type = ALC_KEY_TYPE_SYMMETRIC,
              .fmt = ALC_KEY_FMT_RAW,
              .key = key,
              .len = cKeyLen,
          },
      .ci_algo_info = {
          .ai_iv = iv, // For Chacha20, IV has to be a combination of counter 32
                       // bits in little endian) followed by nonce(96 bits).
                       // Counter will get incremented internally for each 64
                       // bytes of input message
          .iv_length = ivlength // For Chacha20, IV length must be 128 bits
      }};

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
        goto out;
    }

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, handle);
    if (alcp_is_error(err)) {
        printf("Error: Unable to Request \n");
        goto out;
    }
    printf("Request Succeeded\n");
    return 0;

// Incase of error, program execution will come here
out:
    alcp_error_str(err, err_buf, cErrSize);
    printf("%s\n", err_buf);
    return -1;
}

int
encrypt_demo(alc_cipher_handle_p handle,
             const Uint8*        iv,
             const Uint8*        plaintxt,
             const Uint32        len, /*  for both 'plaintxt' and 'ciphertxt' */
             Uint8*              ciphertxt)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    err = alcp_cipher_encrypt(handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: Unable to Encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        printf("%s\n", err_buf);
        return -1;
    }

    printf("Encrypt succeeded\n");
    return 0;
}

int
decrypt_demo(alc_cipher_handle_p handle,
             const Uint8*        iv,
             const Uint8*        ciphertxt,
             const Uint32        len, /* for both 'plaintxt' and 'ciphertxt' */
             Uint8*              plaintxt)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    err = alcp_cipher_decrypt(handle, ciphertxt, plaintxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: Unable to Decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        printf("%s\n", err_buf);
        return -1;
    }

    printf("Decrypt Succeeded\n");
    return 0;
}

// Plain text to encrypt, it can be any size since Chacha20 is a stream cipher.
static Uint8 sample_plaintxt[] =
    "Happy and Fantastic New Year from AOCL Crypto !!";

// Chacha20 Key needs to be 256 bits
static const Uint8 sample_key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                                    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                                    0x1c, 0x1d, 0x1e, 0x1f };

// IV must be 128 bits and should be a combination of Counter (32 bits) and
// Nonce (96 bits). Counter Should be in Little Endian order. For example, in
// the below IV, counter=0x00000001,nonce=0x0000004a0000000000000000
static const Uint8 iv[16] = {
    1, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0, 0, 0, 0, 0
};

// Buffer to write encrypted message into
// It should have size greater than or equal to plaintext as there is no padding
static Uint8 sample_ciphertxt[sizeof(sample_plaintxt)];
int
main(void)
{
    int retval = 0;
    // Buffer to write plain text into.
    // It should have size greater than or equal to the plaintext.
    Uint8        sample_output[512] = { 0 };
    const int    cPlaintextSize     = strlen((const char*)sample_plaintxt);
    const int    cCiphertextSize    = cPlaintextSize; // No padding
    const Uint64 ivlen              = sizeof(iv) * 8;
    const Uint64 keylen             = sizeof(sample_key) * 8;

    printf("Input Text: %s\n", sample_plaintxt);

    // Create the handle, this handle will be used for encrypt and decrypt
    // operations
    alc_cipher_handle_t handle;
    retval = create_demo_session(&handle, sample_key, iv, ivlen, keylen);
    if (retval != 0)
        goto out;

    // Encrypt the plaintext into the ciphertext
    retval =
        encrypt_demo(&handle,
                     iv,
                     sample_plaintxt,
                     cPlaintextSize, /* len of 'plaintxt' and 'ciphertxt' */
                     sample_ciphertxt);
    if (retval != 0)
        goto out;
    printf("CipherText:");
    dump_hex(sample_ciphertxt, cCiphertextSize);

    // Decrypt the ciphertext into the plaintext.
    retval = decrypt_demo(
        &handle, iv, sample_ciphertxt, cCiphertextSize, sample_output);
    if (retval != 0)
        goto out;
    printf("Decrypted Text: %s\n", sample_output);

    /*
     * Complete the transaction
     */
    alcp_cipher_finish(&handle);

    // Free the memory allocated by create_demo_session.
    free(handle.ch_context);

    return 0;
out:
    return -1;
}

/*  LocalWords:  decrypt Crypto AOCL
 */
