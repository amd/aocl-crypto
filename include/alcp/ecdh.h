/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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
#ifndef _ALCP_ECDH_H_
#define _ALCP_ECDH_H_ 2

#include "alcp/ec.h"
#include "alcp/error.h"
#include "alcp/macros.h"

EXTERN_C_BEGIN

/**
 * @addtogroup ec
 * @{
 */

/**
 * @brief Set the input private key for ECDH
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_ec_request and before @ref
 * alcp_ec_finish</b>
 * @endparblock
 * @param [in] pEcHandle - Handler of the Context for the session
 * @param [in] pPrivKey - pointer to Input privateKey
 * @param [in] privKeyLen - size in bytes of the buffer pointed to by pPrivKey.
 * It must be exactly the private key size of the curve in use, otherwise the
 * key is rejected and ALC_ERROR_INVALID_SIZE is returned.
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_ec_set_privatekey(const alc_ec_handle_p pEcHandle,
                       const Uint8*          pPrivKey,
                       Uint64                privKeyLen);

/**
 * @brief Generate a public key from the input private key
 * The generated public key is shared with the peer.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_ec_request and before @ref
 * alcp_ec_finish</b>
 * @endparblock
 * @param [in] pEcHandle - Handler of the Context for the session
 * @param [out] pPublicKey - Pointer to output public key generated
 * @param [in] pubKeyLen - capacity in bytes of the buffer pointed to by
 * pPublicKey. It must be at least the public key size of the curve in use;
 * a smaller buffer is rejected and ALC_ERROR_INVALID_SIZE is returned. A
 * larger buffer is accepted, since the call writes exactly the public key
 * size and leaves the remainder untouched.
 * @param [in] pPrivKey - pointer to Input privateKey used for generating
 * publicKey
 * @param [in] privKeyLen - size in bytes of the buffer pointed to by pPrivKey.
 * Unlike pubKeyLen it must be exactly the private key size of the curve in
 * use, because any other length means the caller and the library disagree
 * about which key is being used; a mismatch is rejected and
 * ALC_ERROR_INVALID_SIZE is returned.
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_ec_get_publickey(const alc_ec_handle_p pEcHandle,
                      Uint8*                pPublicKey,
                      Uint64                pubKeyLen,
                      const Uint8*          pPrivKey,
                      Uint64                privKeyLen);

/**
 * @brief Compute the shared secret using the peer public key and local private key
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_ec_request and before @ref
 * alcp_ec_finish</b>
 * @endparblock
 * @param [in] pEcHandle - Handler of the Context for the session
 * @param [out] pSecretKey - pointer to output secretKey
 * @param [in] secretKeyLen - capacity in bytes of the buffer pointed to by
 * pSecretKey. It must be at least the shared secret size of the curve in use;
 * a smaller buffer is rejected and ALC_ERROR_INVALID_SIZE is returned. A
 * larger buffer is accepted, since the call writes exactly the shared secret
 * size and leaves the remainder untouched.
 * @param [in] pPublicKey - pointer to the peer's public key used for computing
 * the shared secret
 * @param [in] pubKeyLen - size in bytes of the buffer pointed to by pPublicKey.
 * Unlike secretKeyLen it must be exactly the public key size of the curve in
 * use, because a peer point of any other length is malformed rather than
 * merely short; a mismatch is rejected and ALC_ERROR_INVALID_SIZE is returned.
 * @param [out] pKeyLength - pointer to keyLength. The call writes the size in
 * bytes of the secret it produced; the caller's incoming value is not read and
 * does not bound the buffer pointed to by pSecretKey.
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_ec_get_secretkey(const alc_ec_handle_p pEcHandle,
                      Uint8*                pSecretKey,
                      Uint64                secretKeyLen,
                      const Uint8*          pPublicKey,
                      Uint64                pubKeyLen,
                      Uint64*               pKeyLength);

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
 * @param [in] pEcHandle The handle that was returned by alcp_ec_request().
 *                       Once this function is called, the handle will not be
 *                       valid for future calls.
 *
 * @return      None
 */
ALCP_API_EXPORT void
alcp_ec_finish(const alc_ec_handle_p pEcHandle);

EXTERN_C_END

#endif /* _ALCP_ECDH_H_ */
       /**
        * @}
        */
