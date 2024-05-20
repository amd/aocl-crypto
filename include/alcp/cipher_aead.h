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
 * @param ai_iv Initialization Vector
 * @param ai_gcm, ai_siv, optional param for Some Specific Mode of AES only one
 * param can be present at a time
 * @param alc_cipher_aead_algo_info_t AEAD algo info
 */
typedef struct _alc_cipher_aead_algo_info
{

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
 * @param ci_type Specify which cipher type (request param)
 * @param ci_mode Specify which cipher mode (request param)
 * @param ci_keyLen Specify key length in bits (request param)
 * @param ci_key key data (init param)
 * @param ci_iv  Initialization Vector (init param)
 * @param ci_algo_info Algorithm specific info is stored
 *
 * @struct  alc_cipher_info_t
 *
 */
typedef struct _alc_cipher_aead_info
{
    // request params
    alc_cipher_type_t ci_type;   /*! Type: ALC_CIPHER_AES etc */
    alc_cipher_mode_t ci_mode;   /*! Mode: ALC_AES_MODE_GCM etc */
    Uint64            ci_keyLen; /*! Key length in bits */

    // init params
    const Uint8* ci_key;   /*! key data */
    const Uint8* ci_iv;    /*! Initialization Vector */
    Uint64       ci_ivLen; /*! Initialization Vector length */

    // algo params
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
 * @brief       Gets the size of the context for a session described by
 *              pCipherInfo
 * @parblock <br> &nbsp;
 * <b>This AEAD API should be called before @ref alcp_cipher_aead_request to
 * identify the memory to be allocated for context </b>
 * @endparblock
 *
 * @return      Size of Context
 */
ALCP_API_EXPORT Uint64
alcp_cipher_aead_context_size(void);

/**
 * @brief    Request for populating handle with algorithm specified by
 * cipher mode and key length info.
 *
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_context_size is
 * called
 * </b>
 * @endparblock
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, ctx
 * to be considered valid.
 * @param [in]    cipherMode       cipher mode to be set
 * @param [in]    keyLen           key length in bits
 * @param [out]   pCipherHandle    Library populated session handle for future
 * cipher operations.
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_request(const alc_cipher_mode_t cipherMode,
                         const Uint64            keyLen,
                         alc_cipher_handle_p     pCipherHandle);

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
 * @param [in]   pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pInput    Pointer to Input data (plainText or additional data)
 * @param[out]   pOutput   Pointer to output data (cipherText or Tag)
 * @param[in]    len       Length of input or output data
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_encrypt_update(const alc_cipher_handle_p pCipherHandle,
                                const Uint8*              pInput,
                                Uint8*                    pOutput,
                                Uint64                    len);

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
 * @param [in]   pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pInput    Pointer to Input data (CipherText or additional
 * data)
 * @param[out]   pOutput   Pointer to output data (PlainText or Tag)
 * @param[in]    len       Length of input or output data
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_decrypt_update(const alc_cipher_handle_p pCipherHandle,
                                const Uint8*              pInput,
                                Uint8*                    pOutput,
                                Uint64                    len);

/**
 * @brief  Cipher aead init.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_request is
 * called.</b>
 * @endparblock
 * @param [in] pCipherHandle Session handle for encrypt operation
 * @param[in] pKey  Key
 * @param[in] keyLen  key Length in bits
 * @param[in] pIv  IV/Nonce
 * @param[in] ivLen  iv Length in bits
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_init(const alc_cipher_handle_p pCipherHandle,
                      const Uint8*              pKey,
                      Uint64                    keyLen,
                      const Uint8*              pIv,
                      Uint64                    ivLen);

/**
 * @brief AEAD set Additonal Data for the Tag Generation.
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request. For
 * SIV there should only be one call to this AEAD API and for others like GCM
 * and CCM mode, this has to be called after @ref alcp_cipher_aead_init. For
 * SIV, this has to be called immediately after @ref alcp_cipher_aead_request,
 * also IV of SIV needs to be passed into this AEAD API as the last call.</b>
 * @endparblock
 * @param[in] pCipherHandle Session handle for encrypt/decrypt operation
 * @param[in] pInput    Additional Data in Bytes
 * @param[in] len       Length in bytes of Additional Data
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str
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
 * @param[in] tagLen       Length in bytes of Tag in bytes
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_get_tag(const alc_cipher_handle_p pCipherHandle,
                         Uint8*                    pOutput,
                         Uint64                    tagLen);

/**
 * @brief AEAD set the tag length.
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request is called.
 * It's meant for CCM mode, should be called before @ref
 * alcp_cipher_aead_init.</b>
 * @endparblock
 * @param[in] pCipherHandle Session handle for encrypt/decrypt operation
 * @param[in] tagLen       Length in bytes of Tag in bytes
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_set_tag_length(const alc_cipher_handle_p pCipherHandle,
                                Uint64                    tagLen);

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

EXTERN_C_END

#endif /* _ALCP_CIPHER_AEAD_H_ */

/**
 * @}
 */
