/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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
#ifndef _ALCP_CIPHER_SEGMENT_H_
#define _ALCP_CIPHER_SEGMENT_H_ 2

#include "alcp/cipher.h"

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
 * @brief  Cipher Segment init.
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
alcp_cipher_segment_init(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pKey,
                         Uint64                    keyLen,
                         const Uint8*              pIv,
                         Uint64                    ivLen);

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
 * @return   &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_segment_request(const alc_cipher_mode_t cipherMode,
                            const Uint64            keyLen,
                            alc_cipher_handle_p     pCipherHandle);

/**
 * @brief    Encrypt plain text and write it to cipher text with provided
 * handle.
 * @parblock <br> &nbsp;
 * <b>This XTS specific API should be called only after @ref
 * alcp_cipher_segment_request and alcp_cipher_segment_init. API is meant to be
 * used with XTS mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 *
 * @note    XTS: Argument currPlainTextLen should be multiple of 16bytes unless
 * it's the last call. By the last call,if there is a paritial block, both
 * partial and a complete block has to be included in the last call to this
 * function.
 * @param [in]   pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    currPlainTextLen Length of the given plaintext
 * @param[in]    startBlockNum Start block number of given plaintext
 * @return   &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_segment_encrypt_xts(const alc_cipher_handle_p pCipherHandle,
                                const Uint8*              pPlainText,
                                Uint8*                    pCipherText,
                                Uint64                    currPlainTextLen,
                                Uint64                    startBlockNum);

/**
 * @brief    Decryption of cipher text and write it to plain text with
 * provided handle.
 * @parblock <br> &nbsp;
 * <b>This XTS specific API should be called only after @ref
 * alcp_cipher_segment_init. API is meant to be used with XTS mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @note    XTS: Argument currCipherTextLen should be multiple of 16bytes unless
 * it's the last call. By the last call,if there is a paritial block, both
 * partial and a complete block has to be included in the last call to this
 * function.
 *
 * @param[in]    pCipherHandle    Session handle for future encrypt decrypt
 * operation
 * @param[out]    pPlainText    Pointer to Plain Text
 * @param[in]    pCipherText   Pointer to Cipher Text
 * @param[in]    startBlockNum    Start block number of given plaintext
 * @param[in]    currCipherTextLen    Length of the given Cipher Text
 * @return   &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_segment_decrypt_xts(const alc_cipher_handle_p pCipherHandle,
                                const Uint8*              pCipherText,
                                Uint8*                    pPlainText,
                                Uint64                    currCipherTextLen,
                                Uint64                    startBlockNum);

/**
 * @brief       Release resources allocated by alcp_cipher_request.
 * @parblock <br> &nbsp;
 * <b>This API is called to free the session resources</b>
 * @endparblock
 * @note       alcp_cipher_finish to be called at the end of the transaction.
 * Context will be unusable after this call.
 *
 * @param[in]    pCipherHandle    Session handle for completed encrypt/decrypt
 * operations whose resources has to be freed.
 * @return            None
 */

ALCP_API_EXPORT void
alcp_cipher_segment_finish(const alc_cipher_handle_p pCipherHandle);

EXTERN_C_END

#endif /* _ALCP_CIPHER_SEGMENT_H_ */

/**
 * @}
 */
