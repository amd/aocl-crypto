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
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alcp/rsa.h"

// RSA Public key
static const Uint8 Modulus[] = {
    0xef, 0x4f, 0xa2, 0xcd, 0x00, 0xea, 0x99, 0xeb, 0x12, 0xa8, 0x3a, 0x1b,
    0xc5, 0x5d, 0x49, 0x04, 0x18, 0xcd, 0x96, 0x69, 0xc9, 0x28, 0x2c, 0x36,
    0x40, 0x9a, 0x15, 0x40, 0x05, 0x6b, 0x35, 0x6f, 0x89, 0x76, 0xf3, 0xb9,
    0xe3, 0xac, 0x4d, 0x2a, 0xe4, 0xba, 0xd9, 0x6e, 0xb8, 0xa4, 0x05, 0x0b,
    0xc5, 0x8e, 0xdf, 0x15, 0x33, 0xfc, 0x81, 0x2b, 0xb5, 0xf4, 0x3a, 0x0b,
    0x67, 0x2d, 0x7d, 0x7c, 0x41, 0x8c, 0xc0, 0x46, 0x93, 0x7d, 0xe9, 0x95,
    0x90, 0x1e, 0xdd, 0xc0, 0xf4, 0xfc, 0x23, 0x90, 0xbb, 0x14, 0x73, 0x5e,
    0xcc, 0x86, 0x45, 0x6a, 0x9c, 0x15, 0x46, 0x92, 0xf3, 0xac, 0x24, 0x8f,
    0x0c, 0x28, 0x25, 0x17, 0xb1, 0xb8, 0x3f, 0xa5, 0x9c, 0x61, 0xbd, 0x2c,
    0x10, 0x7a, 0x5c, 0x47, 0xe0, 0xa2, 0xf1, 0xf3, 0x24, 0xca, 0x37, 0xc2,
    0x06, 0x78, 0xa4, 0xad, 0x0e, 0xbd, 0x72, 0xeb
};

static const Uint64 PublicKeyExponent = 0x10001;

#define ALCP_PRINT_TEXT(I, L, S)                                               \
    printf("%s\n", S);                                                         \
    for (int x = 0; x < L; x++) {                                              \
        printf(" %02x", *(I + x));                                             \
    }                                                                          \
    printf("\n\n");

static alc_error_t
create_demo_session(alc_rsa_handle_t* s_rsa_handle)
{
    alc_error_t err;

    Uint64 size           = alcp_rsa_context_size(KEY_SIZE_1024);
    s_rsa_handle->context = malloc(size);

    err = alcp_rsa_request(KEY_SIZE_1024, s_rsa_handle);

    return err;
}

static alc_error_t
Rsa_encrypt_demo(alc_rsa_handle_t* ps_rsa_handle)
{
    alc_error_t err;
    Uint8*      text        = NULL;
    Uint8*      pub_key_mod = NULL;
    Uint8*      enc_text    = NULL;

    Uint64 size = sizeof(Modulus);

    err =
        alcp_rsa_set_publickey(ps_rsa_handle, PublicKeyExponent, Modulus, size);
    if (err != ALC_ERROR_NONE) {
        printf("\n setting of publc key failed");
        return err;
    }

    Uint64 size_key = alcp_rsa_get_key_size(ps_rsa_handle);

    if (size_key == 0) {
        printf("\nkey size fetch failed");
        return ALC_ERROR_INVALID_SIZE;
    }

    text = malloc(sizeof(Uint8) * size_key);
    memset(text, 0x31, sizeof(Uint8) * size_key);

    ALCP_PRINT_TEXT(text, size_key, "text_peer")

    pub_key_mod = malloc(sizeof(Uint8) * size_key);
    memset(pub_key_mod, 0, sizeof(Uint8) * size_key);

    Uint64 public_exponent;

    err = alcp_rsa_get_publickey(
        ps_rsa_handle, &public_exponent, pub_key_mod, size_key);

    if (err != ALC_ERROR_NONE) {
        printf("\n publickey fetch failed");
        goto free_pub_key_mod;
    }

    // Encrypt text by using public key
    enc_text = malloc(sizeof(Uint8) * size_key);
    memset(enc_text, 0, sizeof(Uint8) * size_key);

    err = alcp_rsa_publickey_encrypt(ps_rsa_handle,
                                     ALCP_RSA_PADDING_NONE,
                                     pub_key_mod,
                                     size_key,
                                     public_exponent,
                                     text,
                                     size_key,
                                     enc_text);
    if (err != ALC_ERROR_NONE) {
        printf("\n public key encrypt failed\n");
        goto free_enc_text;
    }

    ALCP_PRINT_TEXT(enc_text, size_key, "enc_text")

free_enc_text:
    free(enc_text);
free_pub_key_mod:
    free(pub_key_mod);
    free(text);

    return err;
}

int
main(void)
{
    alc_rsa_handle_t s_rsa_handle;
    alc_error_t      err = create_demo_session(&s_rsa_handle);
    if (alcp_is_error(err)) {
        return -1;
    }
    err = Rsa_encrypt_demo(&s_rsa_handle);
    if (alcp_is_error(err)) {
        return -1;
    }
    alcp_rsa_finish(&s_rsa_handle);
    free(s_rsa_handle.context);
    return 0;
}
