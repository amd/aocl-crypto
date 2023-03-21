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
#ifndef _ALCP_ECDH_H_
#define _ALCP_ECDH_H_ 2

#include "alcp/error.h"
#include "alcp/macros.h"

EXTERN_C_BEGIN

/**
 * @addtogroup ec
 * @{
 */

/**
 * @brief Function generates public key using input privateKey generated
 * public key is shared with the peer.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_ec_request and at the
 * end of session call @ref alcp_ec_finish</b>
 * @endparblock
 * @param [in] pEcHandle - Handler of the Context for the session
 * @param [out] pPublicKey - pointer to Output Publickey generated
 * @param [in] pPrivKey - pointer to Input privateKey used for generating
 * publicKey
 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occured
 */
ALCP_API_EXPORT alc_error_t
alcp_ec_get_publickey(const alc_ec_handle_p pEcHandle,
                      Uint8*                pPublicKey,
                      const Uint8*          pPrivKey);

/**
 * @brief Function compute secret key with publicKey from remotePeer and
 * local privatekey.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_ec_request and at the
 * end of session call @ref alcp_ec_finish</b>
 * @endparblock
 * @param [in] pEcHandle - Handler of the Context for the session
 * @param [out] pSecretKey - pointer to output secretKey
 * @param [in] pPublicKey - pointer to Input privateKey used for generating
 * publicKey
 * @param [in] pKeyLength - pointer to keyLength
 * @return Error Code for the API called . if alc_error_t is not zero then
 * alcp_error_str needs to be called to know about error occured
 */
ALCP_API_EXPORT alc_error_t
alcp_ec_get_secretkey(const alc_ec_handle_p pEcHandle,
                      Uint8*                pSecretKey,
                      const Uint8*          pPublicKey,
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
 * @param [in] pEcHandle The handle that was returned as part of call
 *                       together alcp_ec_request(), once this function
 *                       is called. The handle will not be valid for future
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