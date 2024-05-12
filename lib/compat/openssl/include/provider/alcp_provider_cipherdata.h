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

#ifndef ALCP_PROVIDER_CIPHERDATA_H
#define ALCP_PROVIDER_CIPHERDATA_H 2

#include <openssl/core.h>
#include <openssl/evp.h>

#include <alcp/alcp.h>
#include <alcp/cipher.h>

typedef struct _alc_cipher_ccm_data
{
    Uint32 isLenSet : 1;
    size_t l, m;
    Uint32 isTagSet;
} _alc_cipher_ccm_data_t;

// ALCP provider generic Cipher data
typedef struct _alc_cipher_generic_data
{
    Uint8 oiv_buff[AES_BLOCK_SIZE];

    Uint32 updated : 1; /* Set to 1 during update for one shot ciphers */
    Uint32 variable_keylength : 1;
    Uint32 inverse_cipher     : 1; /* set to 1 to use inverse cipher */
    Uint32 use_bits : 1;   /* Set to 0 for cfb1 to use bits instead of bytes */
    Uint32 tlsversion;     /* If TLS padding is in use the TLS version number */
    Uint8* tlsmac;         /* tls MAC extracted from the last record */
    Int32  alloced;        /* Whether the tlsmac data has been allocated or
                            * points into the user buffer. */
    size_t tlsmacsize;     /* Size of the TLS MAC */
    Int32  removetlspad;   /* Whether TLS padding should be removed or not */
    size_t removetlsfixed; /* Length of the fixed size data to remove when
                            * processing TLS data (equals mac size plus
                            * IV size if applicable) */
    Uint32 num;            /* number of iv bytes */
    size_t blocksize;
    size_t bufsz; /* Number of bytes in buf */

} _alc_cipher_generic_data_t;

// ALCP provider Cipher data
typedef struct _alc_prov_cipher_data
{
    alc_cipher_mode_t mode;

    // iv info
    const Uint8* pIv;
    Uint8        iv_buff[MAX_CIPHER_IV_SIZE];
    Uint64       ivLen;

    // key info
    const Uint8* pKey;
    Uint32       keyLen_in_bytes;

    Uint32 ivState;
    Uint32 isKeySet;
    Uint32 enc : 1;         /*! Set to 1 if we are encrypting or 0 otherwise */
    Uint32 pad : 1;         /*! Whether padding should be used or not */
    Uint64 tls_enc_records; /*! Number of TLS records encrypted */
    Uint32 iv_gen_rand : 1; /*! No IV was specified, so generate a rand IV */
    Uint32 iv_gen      : 1; /*! It is OK to generate IVs */

    // aead params
    Uint64 tagLength;
    Uint64 tls_aad_len;
    Uint32 tls_aad_pad_sz;

    Uint8 buf[AES_BLOCK_SIZE]; /*! buffer to store partial blocks */

    _alc_cipher_generic_data_t generic;
    _alc_cipher_ccm_data_t     ccm;

} alc_prov_cipher_data_t;

#endif /* ALCP_PROVIDER_CIPHERDATA_H */
