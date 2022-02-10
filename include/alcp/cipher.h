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

typedef enum _alc_cipher_type
{
    ALC_CIPHER_TYPE_NONE = 0,

    ALC_CIPHER_TYPE_AES,
    ALC_CIPHER_TYPE_DES,
    ALC_CIPHER_TYPE_3DES,
    ALC_CIPHER_TYPE_TWOFISH,
    ALC_CIPHER_TYPE_SERPENT,

    ALC_CIPHER_TYPE_MAX,
} alc_cipher_type_t;

typedef enum _alc_aes_mode
{
    ALC_AES_MODE_NONE = 0,

    ALC_AES_MODE_ECB,
    ALC_AES_MODE_CBC,
    ALC_AES_MODE_OFB,
    ALC_AES_MODE_CTR,
    ALC_AES_MODE_CFB,
    ALC_AES_MODE_XTR,

    ALC_AES_MODE_MAX,
} alc_aes_mode_t;

typedef struct _alc_aes_info_t
{
    alc_aes_mode_t       mode; /* Mode eg: ALC_AES_MODE_CFB */
    const uint8_t*       iv;   /* Initialization Vector */
} alc_aes_info_t, *alc_aes_info_p;

typedef union _alc_cipher_mode_data
{
    alc_aes_info_t aes;
    // alc_des_info_t des;
} alc_cipher_data_t, *alc_cipher_data_p;

typedef struct _alc_cipher_info
{
    alc_cipher_type_t cipher_type;
    alc_key_info_t    key_info;
    alc_cipher_data_t mode_data;
} alc_cipher_info_t, *alc_cipher_info_p;

/**
 * \brief
 *
 * \notes
 */
typedef void                  alc_cipher_context_t;
typedef alc_cipher_context_t* alc_cipher_context_p;

/**
 * \brief
 * \notes
 */
typedef struct _alc_cipher_handle
{
    alc_cipher_context_p context;
} alc_cipher_handle_t, *alc_cipher_handle_p;

/**
 * \brief       Allows to check if a given algorithm is supported
 * \notes       This API is provided to allow application to make decision on
 *              fallback mechanism
 * \params pCipherInfo The information about the cipher algorithm and modes
 *                     as described by alc_cipher_info_t
 */
alc_error_t
alcp_cipher_supported(const alc_cipher_info_p pCipherInfo);

/**
 * \brief       Gets the size of the context for a session described by
 *              pCipherInfo
 * \notes       alcp_cipher_supported() should be called first to
 *              know if the given cipher/key length configuration is valid.
 *
 * \param pCipherInfo Description of the requested cipher session
 * \return      size > 0 if valid session is found, size otherwise
 */
uint64_t
alcp_cipher_context_size(const alc_cipher_info_p pCipherInfo);

/**
 * \brief    Allows caller to request for a cipher as described by
 *           pCipherInfo
 * \notes    Error needs to be checked for each call,
 *           only upon returned is ALC_ERROR_NONE, ctx to be considered
 *           valid.
 * \param    pCipherInfo    Description of the cipher session
 * \param    pCipherHandle  Session handle for future encrypt decrypt
 *                          operation
 * \return   Error described by alc_error_t
 */
alc_error_t
alcp_cipher_request(const alc_cipher_info_p pCipherInfo,
                    alc_cipher_handle_p     pCipherHandle);

/**
 * \brief    Allows caller to request for a cipher as described by
 *           pCipherInfo
 * \notes    Error needs to be checked for each call,
 *           only upon returned is ALC_ERROR_NONE, ctx to be considered
 *           valid.
 * \param    pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * \param    pPlainText    Pointer to Plain Text
 * \param    pCipherText   Pointer to Cipher Text
 * \param    len           Length of cipher/plain text
 * \return   Error described by alc_error_t
 */
alc_error_t
alcp_cipher_encrypt(const alc_cipher_handle_p pCipherHandle,
                    const uint8_t*            pPlainText,
                    uint8_t*                  pCipherText,
                    uint64_t                  len,
                    const uint8_t*            pIv);

/**
 * \brief    Allows caller to request for a cipher as described by
 *           pCipherInfo
 * \notes    Error needs to be checked for each call,
 *           only upon returned is ALC_ERROR_NONE, pCipherHandle
 *           is valid.
 * \param[in]    pCipherHandle    Session handle for future encrypt decrypt
 *                         operation
 * \param[in]    pPlainText    Pointer to Plain Text
 * \param[out]   pCipherText   Pointer to Cipher Text
 * \param[in]    pKey          Pointer to Key
 * \param[in]    pIv           Pointer to Initialization Vector
 * \param[in]    len           Length of cipher/plain text
 * \return   Error described by alc_error_t
 */
alc_error_t
alcp_cipher_decrypt(const alc_cipher_handle_p pCipherHandle,
                    const uint8_t*            pCipherText,
                    uint8_t*                  pPlainText,
                    uint64_t                  len,
                    const uint8_t*            pIv);

/**
 * \brief       Free resources that was allotted by alcp_cipher_request
 * \notes       alcp_cipher_request() should be called first to know if the
 *              given cipher/key length configuration is valid.
 *
 * \param pCipherInfo Description of the requested cipher session
 * \return            None
 */
void
alcp_cipher_finish(const alc_cipher_handle_p pCipherHandle);

EXTERN_C_END

#endif /* _ALCP_CIPHER_H_ */
