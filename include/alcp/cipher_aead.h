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
#ifndef _ALCP_CIPHER_AEAD_H_
#define _ALCP_CIPHER_AEAD_H_ 2

#include "alcp/cipher.h"
#include "alcp/error.h"
#include "alcp/key.h"
#include "alcp/macros.h"

EXTERN_C_BEGIN

/**
 * @defgroup cipher Cipher API
 * @brief
 * Cipher is a cryptographic technique used to
 * secure information by transforming message into a cryptic form that can only
 * be read by those with the key to decipher it.
 *  @{
 */

/**
 * @brief  Stores special info needed for GCM mode.
 *
 * @note Currently not in use
 *
 * @struct alc_cipher_mode_gcm_info_t
 */
typedef struct _alc_cipher_aead_mode_gcm_info
{
    // FIXME: C do not support empty structures, populate with actual ones
    char dummy;
} alc_cipher_aead_mode_gcm_info_t, *alc_cipher_aead_mode_gcm_info_p;

/**
 * @brief  Stores special info needed for SIV mode.
 *
 * @param xi_ctr_key   holds the info about secondary key for SIV
 *
 * @struct alc_cipher_mode_siv_info_t
 */
typedef struct _alc_cipher_aead_mode_siv_info
{
    const alc_key_info_t* xi_ctr_key;
} alc_cipher_aead_mode_siv_info_t, alc_cipher_aead_mode_siv_info_p;

/**
 *
 * @brief  Stores algorithm specific info for cipher.
 * @param ai_mode Specific which Mode of AES to be used @ref alcp_cipher_mode_t
 * @param ai_iv Initialization Vector
 * @param ai_gcm, ai_siv, optional param for Some Specific Mode of AES only one
 * param can be present at a time
 * @param alc_cipher_aead_algo_info_t AEAD algo info
 */
typedef struct _alc_cipher_aead_algo_info
{
    alc_cipher_mode_t ai_mode; /* Mode: ALC_AES_MODE_CFB etc */
    const Uint8*      ai_iv;   /* Initialization Vector */
    Uint64            iv_length;
    union
    {
        alc_cipher_aead_mode_gcm_info_t ai_gcm;
        alc_cipher_aead_mode_siv_info_t ai_siv;
    };
} alc_cipher_aead_algo_info_t, *alc_cpher_aead_algo_info_p;

/**
 *
 * @brief  Opaque cipher context, populated from the library.
 *
 * @param ci_type   Specify which cipher type to be used for encrypt and decrypt
 * @param ci_key_info  store the info related to key
 * @param ci_algo_info Algorithm specific info is stored
 *
 * @struct  alc_cipher_info_t
 *
 */
typedef struct _alc_cipher_aead_info
{
    alc_cipher_type_t           ci_type; /*! Type: ALC_CIPHER_AES etc */
    alc_key_info_t              ci_key_info;
    alc_cipher_aead_algo_info_t ci_algo_info; /*! mode specific data */
} alc_cipher_aead_info_t, *alc_cipher_aead_info_p;

/**
 * @brief  Opaque type of a cipher context, comes from the library.
 *
 * @typedef void alc_cipher_context_t
 */
typedef void                  alc_cipher_context_t;
typedef alc_cipher_context_t* alc_cipher_context_p;

/**
 *
 * @brief Handle for maintaining session.
 *
 * @param alc_cipher_context_p pointer to the user allocated context of the
 * cipher
 *
 * @struct alc_cipher_handle_t
 *
 */
typedef struct _alc_cipher_aead_handle
{
    alc_cipher_context_p ch_context;
} alc_cipher_aead_handle_t, *alc_cipher_aead_handle_p;

/**
 *
 * @brief  Check if a given algorithm is supported.
 *
 * @parblock <br> &nbsp;
 * <b>This AEAD API needs to be called before any other AEAD API is called to
 * know if AEAD cipher that is being request is supported or not </b>
 * @endparblock
 *
 * @note       This AEAD API is provided to allow application to make decision
 * on fallback mechanism
 * @param [in] pCipherInfo  The information about the cipher algorithm and modes
 *                     as described by alc_cipher_info_t
 * @return              ALC_ERROR_NONE
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_supported(const alc_cipher_aead_info_p pCipherInfo);

/**
 * @brief       Gets the size of the context for a session described by
 *              pCipherInfo
 * @parblock <br> &nbsp;
 * <b>This AEAD API should be called before @ref alcp_cipher_aead_request to
 * identify the memory to be allocated for context </b>
 * @endparblock
 * @note       alcp_cipher_aead_supported should be called first to
 *              know if the given cipher/key length configuration is valid.
 *
 * @param [in] pCipherInfo Description of the requested cipher session
 * @return      Size of Context
 */
ALCP_API_EXPORT Uint64
alcp_cipher_aead_context_size(const alc_cipher_aead_info_p pCipherInfo);

/**
 * @brief    Request for populating handle with algorithm specified by
 * pCipherInfo.
 *
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_supported is
 * called
 * </b>
 * @endparblock
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, ctx
 * to be considered valid.
 * @param [in]   pCipherInfo    Description of the cipher session
 * @param [out]   pCipherHandle    Library populated session handle for future
 * cipher operations.
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_aead_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_request(const alc_cipher_aead_info_p pCipherInfo,
                         alc_cipher_handle_p          pCipherHandle);

/**
 * @brief    Encrypt plain text and write it to cipher text with provided
 * handle.
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request is called
 * and at the end of session call @ref alcp_cipher_aead_finish</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, ctx to be
 * considered valid.
 * @note    Please check examples for the mode to check prefered API, it can
 * either be @ref alcp_cipher_aead_encrypt or @ref
 * alcp_cipher_aead_encrypt_update
 * @param [in]   pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    pIv           Pointer to Initialization Vector
 * @param[in]    len           Length of cipher/plain text
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_aead_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_encrypt(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pPlainText,
                         Uint8*                    pCipherText,
                         Uint64                    len,
                         const Uint8*              pIv);

/**
 * @brief    AEAD encryption of plain text and write it to cipher text with
 * provided handle.
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request is called
 * and at the end of session call @ref alcp_cipher_aead_finish</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, ctx to be
 * considered valid.
 * @note    Please check examples for the mode to check prefered API, it can
 * either be @ref alcp_cipher_aead_encrypt or @ref
 * alcp_cipher_aead_encrypt_update
 * @param [in]   pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pInput    Pointer to Input data (plainText or additional data)
 * @param[out]   pOutput   Pointer to output data (cipherText or Tag)
 * @param[in]    len       Length of input or output data
 * @param[in]    pIv       Pointer to Initialization Vector
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_aead_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_encrypt_update(const alc_cipher_handle_p pCipherHandle,
                                const Uint8*              pInput,
                                Uint8*                    pOutput,
                                Uint64                    len,
                                const Uint8*              pIv);

/**
 * @brief    AEAD decryption of cipher text and write it to plain text with
 * provided handle.
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request is called
 * and at the end of session call @ref alcp_cipher_aead_finish</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, ctx to be
 *          considered valid.
 * @note    Please check examples for the mode to check prefered API, it can
 * either be @ref alcp_cipher_aead_decrypt or @ref
 * alcp_cipher_aead_decrypt_update
 * @param [in]   pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pInput    Pointer to Input data (CipherText or additional
 * data)
 * @param[out]   pOutput   Pointer to output data (PlainText or Tag)
 * @param[in]    len       Length of input or output data
 * @param[in]    pIv       Pointer to Initialization Vector
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_aead_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_decrypt_update(const alc_cipher_handle_p pCipherHandle,
                                const Uint8*              pInput,
                                Uint8*                    pOutput,
                                Uint64                    len,
                                const Uint8*              pIv);

/**
 * @brief    Decryption of cipher text and write it to plain text with provided
 * handle.
 * @parblock <br> &nbsp;
 * <b>This AEAD API should be called only after @ref alcp_cipher_aead_request.
 * API is meant to be used with CCM mode, it needs to be called before
 * @ref alcp_cipher_aead_set_iv.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, pCipherHandle
 *           is valid.
 * @note    Please check examples for the mode to check prefered API, it can
 * either be @ref alcp_cipher_aead_decrypt or @ref
 * alcp_cipher_aead_decrypt_update
 * @param[in]    pCipherHandle    Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    pIv           Pointer to Initialization Vector
 * @param[in]    len           Length of cipher/plain text
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_aead_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_decrypt(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pCipherText,
                         Uint8*                    pPlainText,
                         Uint64                    len,
                         const Uint8*              pIv);

/**
 * @brief AEAD set the IV/Nonce.
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request is called.
 * It should be called after @ref alcp_cipher_aead_set_tag_length for CCM mode.
 * For GCM mode should be called before @ref alcp_cipher_aead_set_aad</b>
 * @endparblock
 * @param [in] pCipherHandle Session handle for encrypt/decrypt operation
 * @param[in] len  Length in bytes of IV/Nonce
 * @param[in] pIv  IV/Nonce
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_aead_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_set_iv(const alc_cipher_handle_p pCipherHandle,
                        Uint64                    len,
                        const Uint8*              pIv);

/**
 * @brief AEAD set Additonal Data for the Tag Generation.
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request. For
 * SIV there should only be one call to this AEAD API and for others like GCM
 * and CCM mode, this has to be called after @ref alcp_cipher_aead_set_iv. For
 * SIV, this has to be called immediately after @ref alcp_cipher_aead_request,
 * also IV of SIV needs to be passed into this AEAD API as the last call.</b>
 * @endparblock
 * @param[in] pCipherHandle Session handle for encrypt/decrypt operation
 * @param[in] pInput    Additional Data in Bytes
 * @param[in] len       Length in bytes of Additional Data
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_aead_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_set_aad(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pInput,
                         Uint64                    len);

/**
 * @brief AEAD get a copy of Tag generated.
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request is called
 * and at the end of session call, just before @ref alcp_cipher_aead_finish </b>
 * @endparblock
 * @param[in] pCipherHandle Session handle for encrypt/decrypt operation
 * @param[out] pOutput  Byte addressable memory to write tag into
 * @param[in] len       Length in bytes of Tag in bytes
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_aead_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_get_tag(const alc_cipher_handle_p pCipherHandle,
                         Uint8*                    pOutput,
                         Uint64                    len);

/**
 * @brief AEAD set the tag length.
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request is called.
 * It's meant for CCM mode, should be called before @ref
 * alcp_cipher_aead_set_iv.</b>
 * @endparblock
 * @param[in] pCipherHandle Session handle for encrypt/decrypt operation
 * @param[in] len       Length in bytes of Tag in bytes
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_aead_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_set_tag_length(const alc_cipher_handle_p pCipherHandle,
                                Uint64                    len);

/**
 * FIXME: Need to fix return type of API
 * @brief       Release resources allocated by alcp_cipher_aead_request.
 * @parblock <br> &nbsp;
 * <b>This AEAD API is called to free resources so should be called to free the
 * session</b>
 * @endparblock
 * @note       alcp_cipher_aead_finish to be called at the end of the
 * transaction, context will be unusable after this call.
 *
 * @param[in]    pCipherHandle    Session handle for future encrypt decrypt
 *                         operation
 * @return            None
 */
ALCP_API_EXPORT void
alcp_cipher_aead_finish(const alc_cipher_handle_p pCipherHandle);

/**
 * @brief   Get a copy of the error string for cipher operations.
 * @parblock <br> &nbsp;
 * <b> This AEAD API is called to get the error string. It should be called
 * after
 * @ref alcp_cipher_aead_request and before @ref alcp_cipher_aead_finish </b>
 * @endparblock
 * @param [in] pCipherHandle Session handle for cipher operation
 * @param [out] pBuff  Destination Buffer to which Error String will be copied
 * @param [in] size    Length of the Buffer.
 *
 * @return alc_error_t Error code to validate the Handle
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_error(alc_cipher_handle_p pCipherHandle,
                       Uint8*              pBuff,
                       Uint64              size);

EXTERN_C_END

#endif /* _ALCP_CIPHER_AEAD_H_ */

/**
 * @}
 */
