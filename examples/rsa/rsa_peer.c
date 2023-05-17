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

#define ALCP_PRINT_TEXT(I, L, S)                                               \
    printf("%s\n", S);                                                         \
    for (int x = 0; x < L; x++) {                                              \
        printf(" %02x", *(I + x));                                             \
    }                                                                          \
    printf("\n");

static alc_error_t
create_demo_session(alc_rsa_handle_t* s_rsa_handle)
{
    alc_error_t err;

    Uint64 size           = alcp_rsa_context_size();
    s_rsa_handle->context = malloc(size);

    err = alcp_rsa_request(s_rsa_handle);

    return err;
}

static alc_error_t
Rsa_demo(alc_rsa_handle_t* ps_rsa_handle_peer1,
         alc_rsa_handle_t* ps_rsa_handle_peer2)
{
    alc_error_t err;
    Uint8*      text_peer_1        = NULL;
    Uint8*      text_peer_2        = NULL;
    Uint8*      pub_key_mod_peer_2 = NULL;
    Uint8*      pub_key_mod_peer_1 = NULL;
    Uint8*      enc_text_peer_1    = NULL;
    Uint8*      dec_text_peer_1    = NULL;
    Uint8*      dec_text_peer_2    = NULL;
    Uint8*      enc_text_peer_2    = NULL;

    /* Peer 1 */

    Uint64 size_key_peer_1 = alcp_rsa_get_key_size(ps_rsa_handle_peer1);

    if (size_key_peer_1 == 0) {
        printf("\n peer1 key size fetch failed");
        return ALC_ERROR_INVALID_SIZE;
    }

    text_peer_1 = malloc(sizeof(Uint8) * size_key_peer_1);
    memset(text_peer_1, 0x31, sizeof(Uint8) * size_key_peer_1);

    ALCP_PRINT_TEXT(text_peer_1, size_key_peer_1, "text_peer_1")

    printf("\n");

    pub_key_mod_peer_1 = malloc(sizeof(Uint8) * size_key_peer_1);
    memset(pub_key_mod_peer_1, 0, sizeof(Uint8) * size_key_peer_1);

    Uint64 public_exponent_peer_1;

    err = alcp_rsa_get_publickey(ps_rsa_handle_peer1,
                                 &public_exponent_peer_1,
                                 pub_key_mod_peer_1,
                                 size_key_peer_1);

    if (err != ALC_ERROR_NONE) {
        printf("\n peer1 publickey fetch failed");
        goto free_pub_mod_peer_1;
    }

    /* Peer 2 */
    Uint64 size_key_peer_2 = alcp_rsa_get_key_size(ps_rsa_handle_peer2);

    if (size_key_peer_2 == 0) {
        printf("\n peer2 key size fetch failed");
        err = ALC_ERROR_INVALID_SIZE;
        goto free_pub_mod_peer_1;
    }

    text_peer_2 = malloc(sizeof(Uint8) * size_key_peer_2);
    memset(text_peer_2, 0x01, sizeof(Uint8) * size_key_peer_2);

    pub_key_mod_peer_2 = malloc(sizeof(Uint8) * size_key_peer_2);
    memset(pub_key_mod_peer_2, 0, sizeof(Uint8) * size_key_peer_2);

    Uint64 public_exponent_peer_2;
    err = alcp_rsa_get_publickey(ps_rsa_handle_peer2,
                                 &public_exponent_peer_2,
                                 pub_key_mod_peer_2,
                                 size_key_peer_2);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer2 publickey fetch failed");
        goto free_pub_mod_peer_2;
    }

    // Encrypt text by peer1 using public key of peer 2
    enc_text_peer_1 = malloc(sizeof(Uint8) * size_key_peer_2);
    memset(enc_text_peer_1, 0, sizeof(Uint8) * size_key_peer_2);

    err = alcp_rsa_publickey_encrypt(ps_rsa_handle_peer1,
                                     ALCP_RSA_PADDING_NONE,
                                     pub_key_mod_peer_2,
                                     size_key_peer_2,
                                     public_exponent_peer_2,
                                     text_peer_1,
                                     size_key_peer_1,
                                     enc_text_peer_1);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer1 publc key encrypt failed");
        goto free_enc_text_peer_1;
    }

    ALCP_PRINT_TEXT(enc_text_peer_1, size_key_peer_1, "enc_text_peer_1")
    printf("\n");

    // Decrypt by peer2
    dec_text_peer_2 = malloc(sizeof(Uint8) * size_key_peer_2);
    memset(dec_text_peer_2, 0, sizeof(Uint8) * size_key_peer_2);

    err = alcp_rsa_privatekey_decrypt(ps_rsa_handle_peer2,
                                      ALCP_RSA_PADDING_NONE,
                                      enc_text_peer_1,
                                      size_key_peer_2,
                                      dec_text_peer_2);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer2 private key decryption failed");
        goto free_dec_text_peer_2;
    }

    if (memcmp(dec_text_peer_2, text_peer_1, size_key_peer_2) == 0) {
        err = ALC_ERROR_NONE;
    } else {
        printf("\n decrypted text not matching the original text");
        goto free_dec_text_peer_2;
    }

    ALCP_PRINT_TEXT(dec_text_peer_2, size_key_peer_2, "dec_text_peer_2")
    printf("\n");

    printf("###################################################################"
           "###################################################################"
           "\n\n");

    ALCP_PRINT_TEXT(text_peer_2, size_key_peer_2, "text_peer_2")
    printf("\n");
    // Encrypt text by peer2 using public key of peer 1
    enc_text_peer_2 = malloc(sizeof(Uint8) * size_key_peer_1);
    memset(enc_text_peer_2, 0, sizeof(Uint8) * size_key_peer_1);

    err = alcp_rsa_publickey_encrypt(ps_rsa_handle_peer2,
                                     ALCP_RSA_PADDING_NONE,
                                     pub_key_mod_peer_1,
                                     size_key_peer_1,
                                     public_exponent_peer_1,
                                     text_peer_2,
                                     size_key_peer_2,
                                     enc_text_peer_2);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer2 publc key encrypt failed");
        goto free_enc_text_peer_2;
    }
    ALCP_PRINT_TEXT(enc_text_peer_2, size_key_peer_2, "enc_text_peer_2")
    printf("\n");
    // Decrypt by peer1
    dec_text_peer_1 = malloc(sizeof(Uint8) * size_key_peer_1);
    memset(dec_text_peer_1, 0, sizeof(Uint8) * size_key_peer_1);

    err = alcp_rsa_privatekey_decrypt(ps_rsa_handle_peer1,
                                      ALCP_RSA_PADDING_NONE,
                                      enc_text_peer_2,
                                      size_key_peer_1,
                                      dec_text_peer_1);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer1 private key decryption failed");
        goto free_dec_text_peer_1;
    }

    ALCP_PRINT_TEXT(dec_text_peer_1, size_key_peer_1, "dec_text_peer_1")

    if (memcmp(dec_text_peer_1, text_peer_2, size_key_peer_1) == 0) {
        err = ALC_ERROR_NONE;
    } else {
        printf("\n decrypted text not matching the original text");
    }

free_dec_text_peer_1:
    free(dec_text_peer_1);
free_enc_text_peer_2:
    free(enc_text_peer_2);
free_dec_text_peer_2:
    free(dec_text_peer_2);
free_enc_text_peer_1:
    free(enc_text_peer_1);
free_pub_mod_peer_2:
    free(pub_key_mod_peer_2);
    free(text_peer_2);
free_pub_mod_peer_1:
    free(pub_key_mod_peer_1);
    free(text_peer_1);

    return err;
}

int
main(void)
{
    alc_rsa_handle_t s_rsa_handle_peer1;
    alc_error_t      err = create_demo_session(&s_rsa_handle_peer1);
    if (alcp_is_error(err)) {
        return -1;
    }
    alc_rsa_handle_t s_rsa_handle_peer2;

    err = create_demo_session(&s_rsa_handle_peer2);
    if (alcp_is_error(err)) {
        return -1;
    }
    err = Rsa_demo(&s_rsa_handle_peer1, &s_rsa_handle_peer2);
    if (alcp_is_error(err)) {
        return -1;
    }

    alcp_rsa_finish(&s_rsa_handle_peer1);
    free(s_rsa_handle_peer1.context);

    alcp_rsa_finish(&s_rsa_handle_peer2);
    free(s_rsa_handle_peer2.context);
    return 0;
}
