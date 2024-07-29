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

#ifndef _OPENSSL_ALCP_PROVIDER_H
#define _OPENSSL_ALCP_PROVIDER_H 2

#include <alcp/alcp.h>
#include <alcp/cipher.h>
#include <alcp/digest.h>
#include <openssl/core.h>
#include <openssl/evp.h>
#include <string.h>

#include "debug.h"

#include "cipher/alcp_cipher_prov.h"
#include "provider/alcp_names.h"
#include "provider/alcp_provider_cipherdata.h"
#include "provider/config.h"

#if defined(WIN32) || defined(WIN64)
#define strcasecmp _stricmp
#endif

#define AES_MAXNR 14

typedef struct alcp_aes_key_st
{
    Uint64 rd_key[4 * (AES_MAXNR + 1)];
    Int32  rounds;
} ALCP_AES_KEY;

typedef struct alcp_prov_cipher_ctx_st
{
    alc_cipher_handle_t    handle;
    alc_prov_cipher_data_t prov_cipher_data; /* cipher params */
    OSSL_LIB_CTX*          libctx;           /* needed for rand calls */
} ALCP_PROV_CIPHER_CTX;

typedef struct alcp_prov_aes_ctx_st
{
    ALCP_PROV_CIPHER_CTX base; /* must be first entry in struct */
    // key memory to be aligned
    ALCP_AES_KEY ks;
} ALCP_PROV_AES_CTX;

extern const OSSL_ALGORITHM ALC_prov_ciphers[];
extern const OSSL_ALGORITHM ALC_prov_digests[];
extern const OSSL_ALGORITHM ALC_prov_macs[];
extern const OSSL_ALGORITHM ALC_prov_rng[];
extern const OSSL_ALGORITHM alc_prov_asym_ciphers[];
extern const OSSL_ALGORITHM alc_prov_signature[];
extern const OSSL_ALGORITHM alc_prov_keymgmt[];

struct _alc_prov_ctx
{
    const OSSL_CORE_HANDLE* ap_core_handle;
    OSSL_LIB_CTX*           libctx;
    BIO_METHOD*             corebiometh;
};
typedef struct _alc_prov_ctx alc_prov_ctx_t, *alc_prov_ctx_p;
typedef void (*fptr_t)(void);

#endif /* _OPENSSL_ALCP_PROV_H */
