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
 * @brief       Gets the size of the context for a session
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
 *           valid only if @ref alcp_is_error (ret) is false
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
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request and before
 * @ref alcp_cipher_aead_finish</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param [in]   pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pInput    Pointer to plainText
 * @param[out]   pOutput   Pointer to cipherText
 * @param[in]    len       Length of plainText/cipherText
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_encrypt(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pInput,
                         Uint8*                    pOutput,
                         Uint64                    len);

/**
 * @brief    AEAD decryption of cipher text and write it to plain text with
 * provided handle.
 * @parblock <br> &nbsp;
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request and before
 * @ref alcp_cipher_aead_finish</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param [in]   pCipherHandle Session handle for future encrypt/decrypt
 *                         operation
 * @param[in]    pInput    Pointer to CipherText
 * @param[out]   pOutput   Pointer to PlainText
 * @param[in]    len       Length of PlainText/CipherText
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_decrypt(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pInput,
                         Uint8*                    pOutput,
                         Uint64                    len);

/**
 * @brief  Cipher aead init.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_aead_request is
 * called. For SIV decrypt, the IV passed should be the tag generated by
 * @ref alcp_cipher_aead_get_tag during encrypt call.</b>
 * @endparblock
 * @param [in] pCipherHandle Session handle for future encrypt/decrypt
 *                         operation
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
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_init.</b>
 *
 * @endparblock
 * @param[in] pCipherHandle Session handle for encrypt/decrypt operation
 * @param[in] pInput    Additional Data in Bytes
 * @param[in] len       Length in bytes of Additional Data
 * @return   &nbsp; Error Code for the API called. If @ref alc_error_t
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
 * <b>This AEAD API can be called after @ref alcp_cipher_aead_request and
 * before @ref alcp_cipher_aead_finish </b>
 * @endparblock
 * @param[in] pCipherHandle Session handle for encrypt/decrypt operation
 * @param[out] pOutput  Byte addressable memory to write tag into
 * @param[in] tagLen    Length of Tag in bytes
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
 * <b>This AEAD API is meant specifically for CCM and have to be called after
 * @ref alcp_cipher_aead_request and before @ref alcp_cipher_aead_init </b>
 * @endparblock
 * @param[in] pCipherHandle Session handle for encrypt/decrypt operation
 * @param[in] tagLen       Length of Tag in bytes
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_set_tag_length(const alc_cipher_handle_p pCipherHandle,
                                Uint64                    tagLen);

/**
 * @brief AEAD set the total plaintext length which is to be encrypted for CCM
 * mode
 * @parblock <br> &nbsp;
 * <b>This AEAD API is meant specifically for CCM and have to be called after
 * @ref alcp_cipher_aead_request and before @ref alcp_cipher_aead_init </b>
 * @endparblock
 * @param[in] pCipherHandle Session handle for encrypt/decrypt operation
 * @param[in] plaintextLength       Length in bytes of plaintext in bytes
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_aead_set_ccm_plaintext_length(
    const alc_cipher_handle_p pCipherHandle, Uint64 plaintextLength);

/**
 * @brief       Release resources allocated by alcp_cipher_aead_request.
 * @parblock <br> &nbsp;
 * <b>This AEAD API is called to free session resources </b>
 * @endparblock
 * @note       Need to be called at the end of the
 * transaction, context will be unusable after this call.
 *
 * @param[in]    pCipherHandle    Session handle for the completed
 * encrypt/decrypt operations whose resources has to be freed.
 * @return            None
 */
ALCP_API_EXPORT void
alcp_cipher_aead_finish(const alc_cipher_handle_p pCipherHandle);

EXTERN_C_END

#endif /* _ALCP_CIPHER_AEAD_H_ */

/**
 * @}
 */
