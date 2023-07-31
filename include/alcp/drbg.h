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

#ifndef _ALCP_DRBG_H_
#define _ALCP_DRBG_H_ 2
#include "alcp/cipher.h"
EXTERN_C_BEGIN

typedef enum _alc_drbg_type
{
    ALC_DRBG_HMAC,
    ALC_DRBG_CTR
} alc_drbg_type_t;

typedef struct _alc_hmacdrbg_info
{
} alc_hmacdrbg_info_t, *alc_hmacdrbg_info_p;

typedef struct _alc_ctrdrbg_info
{
    Uint64 di_keysize;
} alc_ctrdrbg_info_t, *alc_ctrdrbg_info_p;

typedef struct _alc_drbg_info_t
{
    alc_drbg_type_t di_type;
    union
    {
        alc_hmacdrbg_info_t hmac_drbg;
        alc_ctrdrbg_info_t  ctr_drbg;
    } di_algoinfo;

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

EXTERN_C_END

#endif