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
#ifndef _ALCP_RSA_H_
#define _ALCP_RSA_H_ 2

#include "alcp/digest.h"
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
 * @brief Store info about padding used for encryption / decryption
 *
 * @typedef enum alc_rsa_padding
 */
typedef enum
{
    ALCP_RSA_PADDING_OAEP,
    ALCP_RSA_PADDING_NONE
} alc_rsa_padding;

/**
 * @brief Store info about supported RSA key sizes
 *
 * @typedef enum alc_rsa_key_size
 */
typedef enum
{
    KEY_SIZE_1024 = 1024,
    KEY_SIZE_2048 = 2048,
    KEY_SIZE_UNSUPPORTED
} alc_rsa_key_size;

/**
 * @brief Store Context for the future operation of RSA
 *
 */
typedef void               alc_rsa_context_t;
typedef alc_rsa_context_t* alc_rsa_context_p;

/**
 * @brief Handle for maintaining session.
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
 *
 * @param [in]  keySize     - RSA key size
 *
 * @return      Size of Context
 */
ALCP_API_EXPORT Uint64
alcp_rsa_context_size(const alc_rsa_key_size keySize);

/**
 * @brief       Request a handle for rsa for a configuration
 *              as pointed by p_ec_info_p
 *
 * @note        Only 1024 and 2048 key size supported
 *
 * @param [in]  keySize         - Supported key size
 * @param [out] pRsaHandle      - Library populated session handle for future
 * rsa operations.
 *
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str needs to be called to know
 * about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_request(const alc_rsa_key_size keySize, alc_rsa_handle_p pRsaHandle);

/**
 * @brief Function encrypts text using using public key
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request</b>
 * @endparblock
 *
 * @param [in]  pRsaHandle         - Handler of the Context for the session
 * @param [in]  pad                - padding scheme for rsa encryption
 * @param [in]  pText              - pointer to raw bytes
 * @param [in]  textSize           - size of raw bytes
 * @param [out] pEncText           - pointer to encrypted bytes
 * bytes

 * @note  ALCP_RSA_PADDING_NONE is only supported as
 *        padding scheme. This has following limitations
 *         - textSize should equal to the modulus/private_key size
 *         - pText absolute value should be less than modulus
 *
 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_publickey_encrypt(const alc_rsa_handle_p pRsaHandle,
                           alc_rsa_padding        pad,
                           const Uint8*           pText,
                           Uint64                 textSize,
                           Uint8*                 pEncText);

/**
 * @brief Function encrypts text using using public key and oaep padding
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request</b>
 * @endparblock
 *
 * @param [in]  pRsaHandle         - Handler of the Context for the session
 * @param [in]  pText              - pointer to raw bytes
 * @param [in]  textSize           - size of raw bytes
 * @param [in]  label              - pointer to label
 * @param [in]  labelSize          - size of label
 * @param [in]  pSeed              - random seed of size hashlen
 * @param [out] pEncText           - pointer to encrypted bytes
 * bytes

 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_publickey_encrypt_oaep(const alc_rsa_handle_p pRsaHandle,
                                const Uint8*           pText,
                                Uint64                 textSize,
                                const Uint8*           label,
                                Uint64                 labelSize,
                                const Uint8*           pSeed,
                                Uint8*                 pEncText);

/**
 * @brief Function adds the digest algorithm to be used in oaep padding
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request</b>
 * @endparblock
 *
 * @param [in]  pRsaHandle         - Handler of the Context for the session
 * @param [in]  digestInfo         - Description of the digest

 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_add_digest_oaep(const alc_rsa_handle_p  pRsaHandle,
                         const alc_digest_info_p digestInfo);

/**
 * @brief Function adds the digest algorithm for mask generation in oaep padding
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request</b>
 * @endparblock
 *
 * @param [in]  pRsaHandle         - Handler of the Context for the session
 * @param [in]  digestInfo         - Description of the digest

 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_add_mgf_oaep(const alc_rsa_handle_p  pRsaHandle,
                      const alc_digest_info_p digestInfo);

/**
 * @brief Function decrypts encrypted text using private key.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request and the
 * before the session call @ref alcp_rsa_finish</b>
 * @endparblock
 *
 * @note  ALCP_RSA_PADDING_NONE is only supported as
 *        padding scheme. This has following limitations
 *         - textSize should equal to the modulus/private_key size
 *         - pText absolute value should be less than modulus
 *
 * @param [in]  pRsaHandle - Handler of the Context for the session
 * @param [in]  pad        - padding scheme to be used for rsa decrytion
 * @param [in]  pEncText   - pointer to encrypted bytes
 * @param [in]  encSize    - pointer to encrypted bytes
 * @param [out] pText      - pointer to decrypted bytes
 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_privatekey_decrypt(const alc_rsa_handle_p pRsaHandle,
                            alc_rsa_padding        pad,
                            const Uint8*           pEncText,
                            Uint64                 encSize,
                            Uint8*                 pText);

/**
 * @brief Function decrypts encrypted text using private key and OAEP padding
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request and the
 * before the session call @ref alcp_rsa_finish</b>
 * @endparblock
 *
 *
 * @param [in]  pRsaHandle - Handler of the Context for the session
 * @param [in]  pEncText   - pointer to encrypted bytes
 * @param [in]  encSize    - size of encrypted bytes
 * @param [in]  label      - pointer to label
 * @param [in]  labelSize  - sizeof label
 * @param [out] pText      - pointer to decrypted text
 * @param [out] textSize   - pointer to size of decrypted text
 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_privatekey_decrypt_oaep(const alc_rsa_handle_p pRsaHandle,
                                 const Uint8*           pEncText,
                                 Uint64                 encSize,
                                 const Uint8*           label,
                                 Uint64                 labelSize,
                                 Uint8*                 pText,
                                 Uint64*                textSize);

/**
 * @brief Function fetches public key from handle
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request</b>
 * @endparblock
 * @param [in]    pRsaHandle - Handler of the Context for the session
 * @param [out]   pPublicKey - pointer to public exponent
 * @param [out]   pModulus   - pointer to modulus
 * @param [out]   keySize    - size of modulus

 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */

/**
 * @brief Function signs text using private key and PSS padding
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request and the
 * before the session call @ref alcp_rsa_finish</b>
 * @endparblock
 *
 *
 * @param [in]  pRsaHandle  - Handler of the Context for the session
 * @param [in]  check       - Verify the signed message to prevent fault attack
 * @param [in]  pText       - pointer to input text
 * @param [in]  textSize    - size of input text
 * @param [in]  salt        - pointer to salt
 * @param [in]  saltSize    - size of salt
 * @param [out] pSignedBuff - pointer to signed text
 *
 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_privatekey_sign_pss(const alc_rsa_handle_p pRsaHandle,
                             bool                   check,
                             const Uint8*           pText,
                             Uint64                 textSize,
                             const Uint8*           salt,
                             Uint64                 saltSize,
                             Uint8*                 pSignedBuff);

/**
 * @brief Function verifies text using public key and PSS padding
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request and the
 * before the session call @ref alcp_rsa_finish</b>
 * @endparblock
 *
 *
 * @param [in] pRsaHandle  - Handler of the Context for the session
 * @param [in] pText       - pointer to input text
 * @param [in] textSize    - size of input text
 * @param [in] pSignedBuff - pointer to signed text
 *
 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_publickey_verify_pss(const alc_rsa_handle_p pRsaHandle,
                              const Uint8*           pText,
                              Uint64                 textSize,
                              const Uint8*           pSignedBuff);

/**
 * @brief Function signs text using private key and PKCS1-v1_5 padding
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request and the
 * before the session call @ref alcp_rsa_finish</b>
 * @endparblock
 *
 *
 * @param [in]  pRsaHandle  - Handler of the Context for the session
 * @param [in]  check       - Verify the signed message to prevent fault attack
 * @param [in]  pText       - pointer to input text
 * @param [in]  textSize    - size of input text
 * @param [out] pSignedBuff - pointer to signed text
 *
 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_privatekey_sign_pkcs1v15(const alc_rsa_handle_p pRsaHandle,
                                  bool                   check,
                                  const Uint8*           pText,
                                  Uint64                 textSize,
                                  Uint8*                 pSignedBuff);

/**
 * @brief Function verifies text using public key and PKCS1-v1_5 padding
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request and the
 * before the session call @ref alcp_rsa_finish</b>
 * @endparblock
 *
 *
 * @param [in] pRsaHandle  - Handler of the Context for the session
 * @param [in] pText       - pointer to input text
 * @param [in] textSize    - size of input text
 * @param [in] pSignedBuff - pointer to signed text
 *
 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_publickey_verify_pkcs1v15(const alc_rsa_handle_p pRsaHandle,
                                   const Uint8*           pText,
                                   Uint64                 textSize,
                                   const Uint8*           pSignedBuff);

/**
 * @brief Function fetches public key from handle
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request</b>
 * @endparblock
 * @param [in]    pRsaHandle - Handler of the Context for the session
 * @param [out]   pPublicKey - pointer to public exponent
 * @param [out]   pModulus   - pointer to modulus
 * @param [out]   keySize    - size of modulus

 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */

ALCP_API_EXPORT alc_error_t
alcp_rsa_get_publickey(const alc_rsa_handle_p pRsaHandle,
                       Uint64*                pPublicKey,
                       Uint8*                 pModulus,
                       Uint64                 keySize);

/**
 * @brief Function sets the public key inside the handle
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request</b>
 * @endparblock
 * @param [in]   pRsaHandle - Handler of the Context for the session
 * @param [in]   exponent   - public key exponent
 * @param [in]   pModulus   - pointer to modulus
 * @param [in]   size       - size of modulus

 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */

ALCP_API_EXPORT alc_error_t
alcp_rsa_set_publickey(const alc_rsa_handle_p pRsaHandle,
                       Uint64                 exponent,
                       const Uint8*           pModulus,
                       Uint64                 size);

/**
 * @brief Function sets the private key inside the handle
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rsa_request</b>
 * @endparblock
 * @param [in]   pRsaHandle - handler of the Context for the session
 * @param [in]   dp         - pointer to first exponent
 * @param [in]   dq         - pointer to second exponent
 * @param [in]   p          - pointer to first modulus
 * @param [in]   q          - pointer to second modulus
 * @param [in]   qinv       - pointer to inverse of second modulus
 * @param [in]   mod        - pointer to mult of first and second modulus
 * @param [in]   size       - size of modulus
 *
 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rsa_set_privatekey(const alc_rsa_handle_p pRsaHandle,
                        const Uint8*           dp,
                        const Uint8*           dq,
                        const Uint8*           p,
                        const Uint8*           q,
                        const Uint8*           qinv,
                        const Uint8*           mod,
                        Uint64                 size);

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

/**
 * @brief              Get the error string for errors occurring in RSA
 *                     operations
 * @parblock <br> &nbsp;
 * <b> This API is called to get the error string. It should be called after
 * @ref alcp_rsa_request and before @ref alcp_rsa_finish </b>
 * @endparblock
 * @param [in] pRsaHandle Session handle for rsa operation
 * @param [out] pBuff  Destination Buffer to which Error String will be copied
 * @param [in] size    Length of the Buffer.
 *
 * @return alc_error_t Error code to validate the Handle
 */

alc_error_t
alcp_rsa_error(const alc_rsa_handle_p pRsaHandle, Uint8* pBuff, Uint64 size);

EXTERN_C_END
#endif /* _ALCP_RSA_H_ */

/**
 * @}
 */