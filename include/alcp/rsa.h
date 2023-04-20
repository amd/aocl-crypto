/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
#ifndef _ALCP_RSA_H_
#define _ALCP_RSA_H_ 2

#include "alcp/error.h"
#include "alcp/macros.h"

EXTERN_C_BEGIN
/**
 * @defgroup rsa RSA API
 * @brief
 * RSA algorithm is a public-key cryptosystem.
 * In a public-key cryptosystem, the encryption key is public and decryption key
 * is private.
 * RSA algorithm involves key generation, encryption / decryption and signature.
 * @{
 */

/**
 * @brief Store info about paddign used for encryption / decryption
 *
 * @typedef enum alc_rsa_padding
 */
typedef enum
{
    ALCP_RSA_PKCS1_PADDING,
    ALCP_RSA_PKCS1_OAEP_PADDING,
    ALCP_RSA_PADDING_NONE
} alc_rsa_padding;

/**
 * @brief Store Context for the future operation of RSA
 *
 */
typedef void               alc_rsa_context_t;
typedef alc_rsa_context_t* alc_rsa_context_p;

/**
 * @brief Handler used for RSA context handling
 *
 * @param context pointer to the context of the RSA
 *
 * @struct alc_rsa_handle_t
 */
typedef struct _alc_rsa_handle
{
    alc_rsa_context_p context;
} alc_rsa_handle_t, *alc_rsa_handle_p;

/**
 * @brief       Returns the context size of the interaction
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request only otherwise
 * Context will be empty </b>
 * @endparblock
 *
 * @note        @ref alcp_rsa_supported() should be called first to
 *              know if the rsa is supported
 *
 *
 * @return      Size of Context
 */
ALCP_API_EXPORT Uint64
alcp_rsa_context_size();

/**
 * @brief       Allows to check if RSA is supported
 *
 * @parblock <br> &nbsp;
 * <b>This API needs to be called before any other API is called to
 * know if RSA is supported or not </b>
 * @endparblock
 *
 * @note        alcp_rsa_supported() should be called to
 *              know if the if RSA is supported.
 *
 * @return   &nbsp; Error Code for the API called . if alc_error_t
 * is not zero then @ref alcp_error_str needs to be called to know about error
 * occured
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_supported();

/**
 * @brief       Request a handle for rsa for a configuration
 *              as pointed by p_ec_info_p
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_supported is called and at the
 * end of session call @ref alcp_ec_finish</b>
 * @endparblock
 *
 * @note        alcp_rsa_supported() should be called first to
 *              know if the RSA algorithm is supported.
 *
 *
 * @param [in] pRsaHandle The handle returned by the Library
 *
 * @return   &nbsp; Error Code for the API called . if alc_error_t
 * is not zero then @ref alcp_error_str needs to be called to know about error
 * occured
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_request(alc_rsa_handle_p pRsaHandle);

/**
 * @brief Function encrypts text using using public key
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request
 * @endparblock
 *
 * @note  ALCP_RSA_PADDING_NONE is only supported as
 *        padding scheme. This has following limitations
 *         - textSize should equal to the modulus/private_key size
 *         - pText absolute value should be less than modulus
 *
 * @param [in]  pRsaHandle         - Handler of the Context for the session
 * @param [in]  pad                - padding scheme for rsa encryption
 * @param [in]  pPublicKeyMod      - public key modulus
 * @param [in]  pPublicKeyModSize  - public key modulus size
 * @param [in]  publicKeyExp       - public key exponent
 * @param [in]  pText              - pointer to raw bytes
 * @param [in]  textSize           - size of raw bytes
 * @param [out] pEncText           - pointer to encrypted bytes
 * bytes

 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occured
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_publickey_encrypt(const alc_rsa_handle_p pRsaHandle,
                           alc_rsa_padding        pad,
                           const Uint8*           pPublicKeyMod,
                           Uint64                 pPublicKeyModSize,
                           Uint64                 publicKeyExp,
                           const Uint8*           pText,
                           Uint64                 textSize,
                           Uint8*                 pEncText);

/**
 * @brief Function compute secret key with publicKey from remotePeer and
 * local privatekey.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request and the
 * before the session call @ref alcp_rsa_finish</b>
 * @endparblock
 *
 * @note  ALCP_RSA_PADDING_NONE is only supported as
 *        padding scheme
 *
 * @param [in]  pRsaHandle - Handler of the Context for the session
 * @param [in]  pad        - padding scheme to be used for rsa decrytion
 * @param [in]  pEncText   - pointer to encrypted bytes
 * @param [in]  encSize    - pointer to encrypted bytes
 * @param [out] pText      - pointer to decrypted bytes
 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occured
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_privatekey_decrypt(const alc_rsa_handle_p pRsaHandle,
                            alc_rsa_padding        pad,
                            const Uint8*           pEncText,
                            Uint64                 encSize,
                            Uint8*                 pText);

/**
 * @brief Function fetches public key from handle
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request
 * @endparblock
 * @param [in]    pRsaHandle - Handler of the Context for the session
 * @param [out]   pPublicKey - pointer to public exponent
 * @param [out]   pModulus   - pointer to modulus
 * @param [out]   keySize    - size of modulus

 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occured
 */

ALCP_API_EXPORT alc_error_t
alcp_rsa_get_publickey(const alc_rsa_handle_p pRsaHandle,
                       Uint64*                publicKey,
                       Uint8*                 pModulus,
                       Uint64                 keySize);

/**
 * @brief       Fetches key size
 * @parblock <br> &nbsp;
 * <b>This API is called fetch the key size
 * session</b>
 * @endparblock
 *
 * @note       This size is used to allocate the modulus to be then used in
 * alcp_rsa_get_publickey
 *
 * @param [in] pRsaHandle - Handler of the Context for the session
 *
 * @return      modulus/private_key size
 */
ALCP_API_EXPORT Uint64
alcp_rsa_get_key_size(const alc_rsa_handle_p pRsaHandle);

/**
 * @brief       Performs any cleanup actions
 *
 * @parblock <br> &nbsp;
 * <b>This API is called to free resources so should be called to free the
 * session</b>
 * @endparblock
 *
 * @note       Must be called to ensure memory allotted (if any) is cleaned.
 *
 * @param [in] pRsaHandle The handle that was returned as part of call
 *                       together alcp_rsa_request(), once this function
 *                       is called. The handle will not be valid for future
 *
 * @return      None
 */
ALCP_API_EXPORT void
alcp_rsa_finish(const alc_rsa_handle_p pRsaHandle);

EXTERN_C_END
#endif /* _ALCP_RSA_H_ */

/**
 * @}
 */