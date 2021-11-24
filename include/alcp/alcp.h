/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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

#ifndef _ALCP_ALCP_H_
#define _ALCP_ALCP_H_ 2

#include "macros.h"

#include "types.h"

#include "error.h"

#include "key.h"

#include "cipher.h"

#include "digest.h"

#include "mac.h"

#include "rng.h"


/**
 * Version to be printed as : AOCL Crypto   1.0 (0xabcdef) 
 *                           `-----------' `-'-'----------'
 *                              Name        M m  git ver
 */
typedef struct _alc_version {
    int          major;    /* M in above        */
    int          minor;    /* m in above        */
    unsigned int revision; /* git version above */
    const char*  date;     /* e.g. "Jul 20 99"  */
} alc_version_t;

typedef struct _alc_ctx
{
    union _alcp_ctx_t
    {
        alc_cipher_ctx_t cipher_ctx;
        // alc_digest_ctx_t digest_ctx;
        // alc_rng_ctx_t rng_ctx;

    } ctx;

    void* custom_ctx;

} alc_ctx_t;

typedef struct _alc_info
{
    union
    {
        alc_cipher_info_t* cipher_info;
        // alc_digest_info_t *digest_info;
        // alc_rng_info_t  *rng_info;
    } info;

    void* custom_info;
} alc_info_t;

typedef struct _alc_mode_data
{
    union
    {
        alc_cipher_mode_data_t* cipher_data;
        // alc_digest_mode_data_t *digest_data;
        // alc_rng_mode_data_t *mode_data;
    } data;

    void* custom_data;

} alc_mode_data_t;

#endif /* _ALCP_ALCP_H_ */
