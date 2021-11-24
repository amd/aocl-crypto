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
#ifndef _ALCP_CIPHER_H_
#define _ALCP_CIPHER_H_ 2

#include "alcp/error.h"
#include "alcp/key.h"
#include "alcp/macros.h"

EXTERN_C_BEGIN

typedef enum
{
    ALC_CIPHER_TYPE_NONE = 0,

    ALC_CIPHER_TYPE_AES,
    ALC_CIPHER_TYPE_DES,

    ALC_CIPHER_TYPE_MAX,
} alc_cipher_type_t;

typedef enum _alc_aes_mode
{
    ALC_AES_MODE_NONE = 0,

    ALC_AES_MODE_ECB,
    ALC_AES_MODE_CBC,
    ALC_AES_MODE_CTR,
    ALC_AES_MODE_CFB,
    ALC_AES_MODE_XTR,

    ALC_AES_MODE_MAX,
} alc_aes_mode_t;

typedef struct _alc_aes_mode_data_t
{
    alc_aes_mode_t mode; /* Mode eg: ALC_AES_MODE_CFB */
    uint8_t*       iv;   /* Initialization Vector */
} alc_aes_mode_data_t;

typedef union _alc_cipher_mode_data
{
    alc_aes_mode_data_t aes;
    // alc_des_mode_data_t des;
} alc_cipher_mode_data_t;

typedef struct _alc_cipher_info
{
    alc_cipher_type_t      type;
    alc_key_info_t         keyinfo;
    alc_cipher_mode_data_t data;
} alc_cipher_info_t;

typedef void* alc_cipher_ctx_t;

/**
 * \brief
 * \notes
 * \params
 */
alc_error_t
alcp_cipher_supported(const alc_cipher_info_t* cinfo);

/**
 * \brief
 * \notes
 * \params
 */
uint64_t
alcp_cipher_ctx_size(const alc_cipher_info_t* cinfo);

/**
 * \brief
 * \notes
 * \params
 */
alc_error_t
alcp_cipher_request(const alc_cipher_info_t* cinfo, alc_cipher_ctx_t* ctx);

/**
 * \brief
 * \notes
 * \params
 */
alc_error_t
alcp_cipher_encrypt(const alc_cipher_ctx_t* ctx,
                    const uint8_t*          plaintxt,
                    uint8_t*                ciphertxt,
                    uint64_t                len);

/**
 * \brief
 * \notes
 * \params
 */
alc_error_t
alcp_cipher_decrypt(const alc_cipher_ctx_t* ctx,
                    const uint8_t*          ciphertxt,
                    uint8_t*                plaintxt,
                    uint64_t                len);

/**
 * \brief
 * \notes
 * \params
 */
void
alcp_cipher_finish(const alc_cipher_ctx_t* ctx);

EXTERN_C_END

#endif /* _ALCP_CIPHER_H_ */
