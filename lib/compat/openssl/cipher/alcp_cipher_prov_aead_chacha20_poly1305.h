/*
 * Copyright (C) 2026, Advanced Micro Devices. All rights reserved.
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

#pragma once

#include "provider/alcp_provider.h"

#define NO_TLS_PAYLOAD_LENGTH  ((size_t)-1)
#define CHACHA20_POLY1305_KEYLEN 32
#define CHACHA20_POLY1305_BLKLEN 1
#define CHACHA20_POLY1305_IVLEN  12
#define CHACHA20_POLY1305_MAX_IVLEN 12
#define CHACHA20_POLY1305_TAGLEN 16
#define CHACHA20_POLY1305_MODE   0
#define CHACHA20_POLY1305_FLAGS  (PROV_CIPHER_FLAG_AEAD \
                                  | PROV_CIPHER_FLAG_CUSTOM_IV)

/* ChaCha20-Poly1305 provider context. */
typedef struct alcp_prov_chacha20_poly1305_ctx_st
{
    /* ALCP cipher handle — must be first for consistent casting */
    alc_cipher_handle_t handle;

    /* Provider interface fields */
    unsigned int enc : 1;
    unsigned int iv_set : 1;

    size_t keylen;
    size_t ivlen;

    unsigned char oiv[CHACHA20_POLY1305_IVLEN]; /* original IV from einit */
    unsigned char iv[CHACHA20_POLY1305_IVLEN];  /* working IV */
    unsigned char key[CHACHA20_POLY1305_KEYLEN]; /* stored key for dupctx re-init */

    /* ChaCha20-Poly1305 specific fields */
    unsigned char tag[CHACHA20_POLY1305_TAGLEN];
    unsigned char tls_aad[CHACHA20_POLY1305_TAGLEN]; /* 13 bytes used, 16 allocated */
    unsigned int  nonce[CHACHA20_POLY1305_IVLEN / 4]; /* IV as 3x uint32 */

    size_t   tag_len;
    size_t   tls_payload_length;
    size_t   tls_aad_pad_sz;

    unsigned int aad : 1;
    unsigned int mac_inited : 1;
    unsigned int key_set : 1;
} __attribute__((aligned(64))) ALCP_PROV_CHACHA20_POLY1305_CTX;

extern const OSSL_DISPATCH ALCP_prov_chacha20poly1305_functions[];
