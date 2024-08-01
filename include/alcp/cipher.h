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

#include <stddef.h>

#include "alcp/error.h"
#include "alcp/key.h"
#include "alcp/macros.h"

EXTERN_C_BEGIN

/**
 * @defgroup cipher Cipher API
 * @brief
 * Cipher is a cryptographic technique used to
 * secure information by transforming message into a cryptic form that can
 * only be read by those with the key to decipher it.
 *  @{
 */

/**
 * @brief Specify which Mode of AES to be used for encrypt and decrypt.
 *
 * @typedef enum  alc_cipher_mode_t
 */
typedef enum _alc_cipher_mode
{
    ALC_AES_MODE_NONE = 0,

    // aes ciphers
    ALC_AES_MODE_ECB,
    ALC_AES_MODE_CBC,
    ALC_AES_MODE_OFB,
    ALC_AES_MODE_CTR,
    ALC_AES_MODE_CFB,
    ALC_AES_MODE_XTS,
    // non-aes ciphers
    ALC_CHACHA20,
    // aes aead ciphers
    ALC_AES_MODE_GCM,
    ALC_AES_MODE_CCM,
    ALC_AES_MODE_SIV,
    // non-aes aead ciphers
    ALC_CHACHA20_POLY1305,

    ALC_AES_MODE_MAX,

} alc_cipher_mode_t;

typedef struct _alc_cipher_data
{
    Uint32 alcp_keyLen_in_bytes;
} alc_cipher_data_t;

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
} alc_cipher_handle_t, *alc_cipher_handle_p;

/**
 * @brief       Gets the size of the context for a session
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
 * @note     Error needs to be checked for each call.
 *           Valid only if @ref alcp_is_error (ret) is false
 * @param [in]    cipherMode       cipher mode to be set
 * @param [in]    keyLen           key length in bits
 * @param [out]   pCipherHandle    Library populated session handle for future
 * cipher operations.
 * @return   &nbsp; Error Code for the API called.
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
 * is not ALC_ERROR_NONE then an error has occurred and handle will be invalid
 * for future operations
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
 * <b>This API can be called after @ref alcp_cipher_request and before  @ref
 * alcp_cipher_finish</b> <b>API is meant to be used with CBC,CTR,CFB,OFB,XTS
 * mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param [in]   pCipherHandle Session handle for future encrypt/decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    datalen           Length of cipher/plain text
 * @return   &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_encrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pPlainText,
                    Uint8*                    pCipherText,
                    Uint64                    datalen);

/**
 * @brief    Decrypt the cipher text and write it to plain text with
 * provided handle.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_request and before  @ref
 * alcp_cipher_finish</b> <b>API is meant to be used with CBC,CTR,CFB,OFB,XTS
 * mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param[in]    pCipherHandle    Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    datalen           Length of cipher/plain text
 * @return   &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_decrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pCipherText,
                    Uint8*                    pPlainText,
                    Uint64                    datalen);

/**
 * @brief       Release resources allocated by alcp_cipher_request.
 * @parblock <br> &nbsp;
 * <b>This API is called to free the session resources</b>
 * @endparblock
 * @note       alcp_cipher_finish has to be called at the end of the
 * transaction. Context will be unusable after this call.
 *
 * @param[in]    pCipherHandle    Session handle for future encrypt/decrypt
 *                         operation
 * @return            None
 */
ALCP_API_EXPORT void
alcp_cipher_finish(const alc_cipher_handle_p pCipherHandle);

EXTERN_C_END

#endif /* _ALCP_CIPHER_H_ */

/**
 * @}
 */
