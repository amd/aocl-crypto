/*
 * Copyright (C) 2021-2023, Advanced Micro Devices. All rights reserved.
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

typedef enum _alc_cipher_mode
{
    ALC_AES_MODE_NONE = 0,

    ALC_AES_MODE_ECB,
    ALC_AES_MODE_CBC,
    ALC_AES_MODE_OFB,
    ALC_AES_MODE_CTR,
    ALC_AES_MODE_CFB,
    ALC_AES_MODE_XTS,
    ALC_AES_MODE_GCM,
    ALC_AES_MODE_CCM,
    ALC_AES_MODE_SIV,

    ALC_AES_MODE_MAX,
} alc_cipher_mode_t;

typedef enum _alc_aes_ctrl
{
    ALC_AES_CTRL_NONE = 0,

    ALC_AES_CTRL_SET_IV_LEN,
    ALC_AES_CTRL_GET_IV_LEN,
    ALC_AES_CTRL_SET_AD_LEN,
    ALC_AES_CTRL_GET_AD_LEN,
    ALC_AES_CTRL_SET_TAG_LEN,
    ALC_AES_CTRL_GET_TAG,

    ALC_AES_CTRL_MAX,
} alc_aes_ctrl_t;

/**
 * \brief  Mode specific inforamtion, for XTS it is the secondary key
 *         for GCM it is nounce etc.
 *
 * \notes
 */
typedef union _alc_cipher_mode_xts_info
{
    alc_key_info_t* xi_tweak_key;
} alc_cipher_mode_xts_info_t, *alc_cipher_mode_xts_info_p;

typedef struct _alc_cipher_mode_gcm_info
{
    // FIXME: C do not support empty structures, populate with actual ones
    char dummy;
} alc_cipher_mode_gcm_info_t, *alc_cipher_mode_gcm_info_p;

typedef struct _alc_cipher_mode_siv_info
{
    const alc_key_info_t* xi_ctr_key;
} alc_cipher_mode_siv_info_t, alc_cipher_mode_siv_info_p;

/**
 * \brief  Algorithm specific info,
 *
 * \notes
 */
typedef struct _alc_cipher_algo_info
{
    alc_cipher_mode_t ai_mode; /* Mode: ALC_AES_MODE_CFB etc */
    const Uint8*      ai_iv;   /* Initialization Vector */
    union
    {
        alc_cipher_mode_xts_info_t ai_xts;
        alc_cipher_mode_gcm_info_t ai_gcm;
        alc_cipher_mode_siv_info_t ai_siv;
    };

} alc_cipher_algo_info_t, *alc_cpher_algo_info_p;

/**
 * \brief  The opaque type of a cipher context, comes from the library
 *
 * \notes
 */
typedef struct _alc_cipher_info
{
    alc_cipher_type_t      ci_type; /* Type: ALC_CIPHER_AES etc */
    alc_key_info_t         ci_key_info;
    alc_cipher_algo_info_t ci_algo_info; /* mode specific data */
} alc_cipher_info_t, *alc_cipher_info_p;

/**
 * \brief  The opaque type of a cipher context, comes from the library
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
    alc_cipher_context_p ch_context;
} alc_cipher_handle_t, *alc_cipher_handle_p, AlcCipherHandle;

/**
 * \brief       Allows to check if a given algorithm is supported
 * \notes       This API is provided to allow application to make decision on
 *              fallback mechanism
 * \params pCipherInfo The information about the cipher algorithm and modes
 *                     as described by alc_cipher_info_t
 * \return              alc_error_t
 */
ALCP_API_EXPORT alc_error_t
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
ALCP_API_EXPORT Uint64
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
ALCP_API_EXPORT alc_error_t
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
 * \param[in]    pPlainText    Pointer to Plain Text
 * \param[out]   pCipherText   Pointer to Cipher Text
 * \param[in]    pKey          Pointer to Key
 * \param[in]    pIv           Pointer to Initialization Vector
 * \param[in]    len           Length of cipher/plain text
 * \return   Error described by alc_error_t
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_encrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pPlainText,
                    Uint8*                    pCipherText,
                    Uint64                    len,
                    const Uint8*              pIv);

/**
 * \brief    Allows caller to request for a cipher as described by
 *           pCipherInfo
 * \notes    Error needs to be checked for each call,
 *           only upon returned is ALC_ERROR_NONE, ctx to be considered
 *           valid.
 * \param    pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * \param[in]    pInput    Pointer to Input data (plainText or additional data)
 * \param[out]   pOutput   Pointer to output data (cipherText or Tag)
 * \param[in]    len       Length of input or output data
 * \param[in]    pIv       Pointer to Initialization Vector
 * \return   Error described by alc_error_t
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_encrypt_update(const alc_cipher_handle_p pCipherHandle,
                           const Uint8*              pInput,
                           Uint8*                    pOutput,
                           Uint64                    len,
                           const Uint8*              pIv);

/**
 * \brief    Allows caller to request for a cipher as described by
 *           pCipherInfo
 * \notes    Error needs to be checked for each call,
 *           only upon returned is ALC_ERROR_NONE, ctx to be considered
 *           valid.
 * \param    pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * \param[in]    pInput    Pointer to Input data (CipherText or additional data)
 * \param[out]   pOutput   Pointer to output data (PlainText or Tag)
 * \param[in]    len       Length of input or output data
 * \param[in]    pIv       Pointer to Initialization Vector
 * \return   Error described by alc_error_t
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_decrypt_update(const alc_cipher_handle_p pCipherHandle,
                           const Uint8*              pInput,
                           Uint8*                    pOutput,
                           Uint64                    len,
                           const Uint8*              pIv);

/**
 * \brief Allows caller to set the IV/Nonce
 *
 * \param pCipherHandle Session handle for encrypt/decrypt operation
 * \param[in] len  Length in bytes of IV/Nonce
 * \param[in] pIv  IV/Nonce
 * \return Error described by alc_error_t
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_set_iv(const alc_cipher_handle_p pCipherHandle,
                   Uint64                    len,
                   const Uint8*              pIv);

/**
 * @brief Allows caller to set padded bytes in the input.
 * @param pCipherHandle Session handle for encrypt/decrypt operation
 * @param len           Length of bytes which are padded
 * @return
 */
alc_error_t
alcp_cipher_set_pad_length(const alc_cipher_handle_p pCipherHandle, Uint64 len);

/**
 * \brief Allows caller to set the Additonal Data for Tag Generation
 *
 * \param pCipherHandle Session handle for encrypt/decrypt operation
 * \param[in] pInput    Additonal Data in Bytes
 * \param[in] len       Length in bytes of Additional Data
 * \return Error described by alc_error_t
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_set_aad(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pInput,
                    Uint64                    len);

/**
 * \brief Allows caller to set the get a copy of Tag
 *
 * \param pCipherHandle Session handle for encrypt/decrypt operation
 * \param[out] pOutput  Byte addressible memory to write tag into
 * \param[in] len       Length in bytes of Tag in bytes
 * \return Error described by alc_error_t
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_get_tag(const alc_cipher_handle_p pCipherHandle,
                    Uint8*                    pOutput,
                    Uint64                    len);

/**
 * \brief Allows caller to set the set tag size
 *
 * \param pCipherHandle Session handle for encrypt/decrypt operation
 * \param[in] len       Length in bytes of Tag in bytes
 * \return Error described by alc_error_t
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_set_tag_length(const alc_cipher_handle_p pCipherHandle, Uint64 len);

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
ALCP_API_EXPORT alc_error_t
alcp_cipher_decrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pCipherText,
                    Uint8*                    pPlainText,
                    Uint64                    len,
                    const Uint8*              pIv);

/**
 * \brief       Free resources that was allotted by alcp_cipher_request
 * \notes       alcp_cipher_request() should be called first to know if the
 *              given cipher/key length configuration is valid.
 *
 * \param[in]    pCipherHandle    Session handle for future encrypt decrypt
 *                         operation
 * \return            None
 */
ALCP_API_EXPORT void
alcp_cipher_finish(const alc_cipher_handle_p pCipherHandle);

EXTERN_C_END

#endif /* _ALCP_CIPHER_H_ */
