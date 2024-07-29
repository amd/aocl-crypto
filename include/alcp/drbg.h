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

#ifndef _ALCP_DRBG_H_
#define _ALCP_DRBG_H_ 2
#include "alcp/digest.h"
#include "alcp/rng.h"
#include <stddef.h>

EXTERN_C_BEGIN

typedef enum _alc_drbg_type
{
    ALC_DRBG_HMAC,
    ALC_DRBG_CTR
} alc_drbg_type_t;

typedef struct _alc_hmac_drbg_info
{
    alc_digest_info_t digest_info;
} alc_hmac_drbg_info_t, *alc_hmac_drbg_info_p;

typedef struct _alc_ctr_drbg_info
{
    Uint64 di_keysize;
    bool   use_derivation_function;
} alc_ctr_drbg_info_t, *alc_ctr_drbg_info_p;

typedef struct _alc_custom_rng_info
{
    Uint8* entropy;
    Uint64 entropylen;
    Uint8* nonce;
    Uint64 noncelen;

} alc_custom_rng_info_t, *alc_custom_rng_info_p;

typedef struct _alc_rng_source_info
{
    bool custom_rng;

    union
    {
        alc_rng_info_t rng_info;
        alc_custom_rng_info_t
            custom_rng_info; // Used for Testing purposes. Not pure Random but
                             // allows to provide custom entropy and nonce
    } di_sourceinfo;

} alc_rng_source_info_t, *alc_rng_source_info_p;

typedef struct _alc_drbg_info_t
{
    alc_drbg_type_t di_type;
    union
    {
        alc_hmac_drbg_info_t hmac_drbg;
        alc_ctr_drbg_info_t  ctr_drbg;
    } di_algoinfo;

    alc_rng_source_info_t di_rng_sourceinfo;

    Uint64 max_entropy_len;
    Uint64 max_nonce_len;

    // any other common fields that are needed

} alc_drbg_info_t, *alc_drbg_info_p;

typedef void                alc_drbg_context_t;
typedef alc_drbg_context_t* alc_drbg_context_p;

typedef struct alc_drbg_handle
{
    alc_drbg_context_p ch_context;
} alc_drbg_handle_t, *alc_drbg_handle_p, AlcDrbgHandle;

ALCP_API_EXPORT alc_error_t
alcp_drbg_supported(const alc_drbg_info_p pcDrbgInfo);

ALCP_API_EXPORT Uint64
alcp_drbg_context_size(const alc_drbg_info_p pDrbgInfo);

ALCP_API_EXPORT alc_error_t
alcp_drbg_request(alc_drbg_handle_p     pDrbgHandle,
                  const alc_drbg_info_p pDrbgInfo);

// FIXME: To be verified whether personalization string should be exposed
ALCP_API_EXPORT alc_error_t
alcp_drbg_initialize(alc_drbg_handle_p pDrbgHandle,
                     int               cSecurityStrength,
                     Uint8*            personalization_string,
                     Uint64            personalization_string_length);

ALCP_API_EXPORT alc_error_t
alcp_drbg_randomize(alc_drbg_handle_p pDrbgHandle,
                    Uint8             p_Output[],
                    const size_t      cOutputLength,
                    int               cSecurityStrength,
                    const Uint8       cAdditionalInput[],
                    const size_t      cAdditionalInputLength);

ALCP_API_EXPORT alc_error_t
alcp_drbg_finish(alc_drbg_handle_p pDrbgHandle);

EXTERN_C_END

#endif
