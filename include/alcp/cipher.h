/*
 * Copyright (C) 2021-2024, Advanced Micro Devices. All rights reserved.
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

/**
 * @defgroup cipher Cipher API
 * @brief
 * Cipher is a cryptographic technique used to
 * secure information by transforming message into a cryptic form that can only
 * be read by those with the key to decipher it.
 *  @{
 */

/**
 *
 * @brief Specify which type of cipher to be used.
 *
 * @typedef enum alc_cipher_type_t
 *
 */
typedef enum _alc_cipher_type
{
    ALC_CIPHER_TYPE_NONE = 0,

    ALC_CIPHER_TYPE_AES,
    ALC_CIPHER_TYPE_DES,
    ALC_CIPHER_TYPE_3DES,
    ALC_CIPHER_TYPE_TWOFISH,
    ALC_CIPHER_TYPE_SERPENT,
    ALC_CIPHER_TYPE_CHACHA20,
    ALC_CIPHER_TYPE_CHACHA20_POLY1305,
    ALC_CIPHER_TYPE_MAX,
} alc_cipher_type_t;

/**
 * @brief Specify which Mode of AES to be used for encrypt and decrypt.
 *
 * @typedef enum  alc_cipher_mode_t
 */
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
// FIXME: Below typedef is not used, need to remove or use it.
/**
 *
 * @brief Set control flags supported by cipher algorithms.
 *
 * @typedef enum  alc_aes_ctrl_t
 *
 * @note Currently not in use
 */
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
 *
 * @brief  Stores algorithm specific info for cipher.
 * @param ai_mode Specific which Mode of AES to be used @ref alcp_cipher_mode_t
 * @param ai_iv Initialization Vector
 * @param ai_xts optional param for Some Specific Mode of AES only one param can
 * be present at a time
 * @param alc_cipher_algo_info_t cipher algo
 * @param alc_cipher_mode_t cipher mode
 */
typedef struct _alc_cipher_algo_info
{

    Uint64 dummy;
} alc_cipher_algo_info_t, *alc_cpher_algo_info_p;

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
typedef struct _alc_cipher_info
{
    // request params
    alc_cipher_type_t ci_type;   /*! Type: ALC_CIPHER_AES etc */
    alc_cipher_mode_t ci_mode;   /*! Mode: ALC_AES_MODE_CTR etc */
    Uint64            ci_keyLen; /*! Key length in bits */

    // init params
    const Uint8* ci_key;   /*! key data */
    const Uint8* ci_iv;    /*! Initialization Vector */
    Uint64       ci_ivLen; /*! Initialization Vector length */

    // algo params
    // alc_cipher_algo_info_t ci_algo_info; /*! mode specific data */

} alc_cipher_info_t, *alc_cipher_info_p;

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
typedef struct _alc_cipher_handle
{
    alc_cipher_context_p ch_context;
} alc_cipher_handle_t, *alc_cipher_handle_p, AlcCipherHandle;

/**
 * @brief       Gets the size of the context for a session described by
 *              pCipherInfo
 * @parblock <br> &nbsp;
 * <b>This API should be called before @ref alcp_cipher_request to identify the
 * memory to be allocated for context </b>
 * @endparblock
 *
 * @return      Size of Context
 */
ALCP_API_EXPORT Uint64
alcp_cipher_context_size(void);

/**
 * @brief    Request for populating handle with algorithm specified by
 * cipher mode and key Length.
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_context_size is called </b>
 * @endparblock
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, ctx
 * to be considered valid.
 * @param [in]    cipherMode       cipher mode to be set
 * @param [in]    keyLen           key length in bits
 * @param [out]   pCipherHandle    Library populated session handle for future
 * cipher operations.
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_request(const alc_cipher_mode_t cipherMode,
                    const Uint64            keyLen,
                    alc_cipher_handle_p     pCipherHandle);

/**
 * @brief  Cipher init.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_request is
 * called.</b>
 * @endparblock
 * @param [in] pCipherHandle Session handle for cipher operation
 * @param[in] pKey  Key
 * @param[in] keyLen  key Length in bits
 * @param[in] pIv  IV/Nonce
 * @param[in] ivLen  iv Length in bits
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_aead_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_init(const alc_cipher_handle_p pCipherHandle,
                 const Uint8*              pKey,
                 Uint64                    keyLen,
                 const Uint8*              pIv,
                 Uint64                    ivLen);

/**
 * @brief    Encrypt plain text and write it to cipher text with provided
 * handle.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_request is called and at the
 * end of session call @ref alcp_cipher_finish</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, ctx to be
 * considered valid.
 * @param [in]   pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    len           Length of cipher/plain text
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_encrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pPlainText,
                    Uint8*                    pCipherText,
                    Uint64                    len);

/**
 * @brief    Decryption of cipher text and write it to plain text with
 * provided handle.
 * @parblock <br> &nbsp;
 * <b>This API should be called only after @ref alcp_cipher_request.
 * API is meant to be used with CBC,CTR,CFB,OFB,XTS mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, pCipherHandle
 *           is valid.
 * @param[in]    pCipherHandle    Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    len           Length of cipher/plain text
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_decrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pCipherText,
                    Uint8*                    pPlainText,
                    Uint64                    len);

/**
 * @brief    Encrypt plain text and write it to cipher text with provided
 * handle.
 * @parblock <br> &nbsp;
 * <b>This XTS specific API should be called only after @ref
 * alcp_cipher_request and alcp_cipher_init . API is meant to be used with XTS
 * mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, ctx to be
 * considered valid.
 * @note    XTS: Argument currCipherTextLen should be multiple of 16bytes unless
 * it's the last call. Also last call if there is a paritial block, both partial
 * and a complete block has to be included in the last call to this function.
 * @param [in]   pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    currPlainTextLen Length of the given plaintext
 * @param[in]    startBlockNum Start block number of given plaintext
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_blocks_encrypt(const alc_cipher_handle_p pCipherHandle,
                           const Uint8*              pPlainText,
                           Uint8*                    pCipherText,
                           Uint64                    currPlainTextLen,
                           Uint64                    startBlockNum);

/**
 * @brief    Decryption of cipher text and write it to plain text with
 * provided handle.
 * @parblock <br> &nbsp;
 * <b>This XTS specific API should be called only after @ref
 * alcp_cipher_request and alcp_cipher_init. API is meant to be used with XTS
 * mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, pCipherHandle
 *           is valid.
 * @note    XTS: Argument currCipherTextLen should be multiple of 16bytes unless
 * it's the last call. Also last call if there is a partial block, both partial
 * and a complete block has to be included in the last call to this function.
 * @param[in]    pCipherHandle    Session handle for future encrypt decrypt
 * operation
 * @param[out]    pPlainText    Pointer to Plain Text
 * @param[in]    pCipherText   Pointer to Cipher Text
 * @param[in]    startBlockNum    Start block number of given plaintext
 * @param[in]    currCipherTextLen    Length of the given Cipher Text
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_blocks_decrypt(const alc_cipher_handle_p pCipherHandle,
                           const Uint8*              pCipherText,
                           Uint8*                    pPlainText,
                           Uint64                    currCipherTextLen,
                           Uint64                    startBlockNum);

/**
 * FIXME: Need to fix return type of API
 * @brief       Release resources allocated by alcp_cipher_request.
 * @parblock <br> &nbsp;
 * <b>This API is called to free resources so should be called to free the
 * session</b>
 * @endparblock
 * @note       alcp_cipher_finish to be called at the end of the transaction,
 * context will be unusable after this call.
 *
 * @param[in]    pCipherHandle    Session handle for future encrypt decrypt
 *                         operation
 * @return            None
 */
ALCP_API_EXPORT void
alcp_cipher_finish(const alc_cipher_handle_p pCipherHandle);

/**
 * @brief   Get a copy of the error string for cipher operations.
 * @parblock <br> &nbsp;
 * <b> This API is called to get the error string. It should be called after
 * @ref alcp_cipher_request and before @ref alcp_cipher_finish </b>
 * @endparblock
 * @param [in] pCipherHandle Session handle for cipher operation
 * @param [out] pBuff  Destination Buffer to which Error String will be copied
 * @param [in] size    Length of the Buffer.
 *
 * @return alc_error_t Error code to validate the Handle
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_error(alc_cipher_handle_p pCipherHandle, Uint8* pBuff, Uint64 size);

EXTERN_C_END

#endif /* _ALCP_CIPHER_H_ */

/**
 * @}
 */
