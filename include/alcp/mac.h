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

#ifndef _ALCP_MAC_H_
#define _ALCP_MAC_H_ 2

#include "alcp/cipher.h"
#include "alcp/digest.h"
#include "alcp/key.h"

EXTERN_C_BEGIN

/**
 * @defgroup mac MAC API
 * @brief
 * A Message Authentication Code (MAC) is a cryptographic technique used to
 * verify the authenticity and integrity of a message, ensuring that it has not
 * been tampered with during transmission.
 * @{
 */

/**
 * @brief Stores info regarding the type of MAC used
 *
 * @typedef enum alc_mac_type_t
 *
 */
typedef enum _alc_mac_type
{
    ALC_MAC_HMAC,
    ALC_MAC_CMAC,
    ALC_MAC_POLY1305,
} alc_mac_type_t;

/**
 * @brief Stores details of HMAC
 *
 * @param  digest_mode Store info of digest used for HMAC
 *
 * @struct alc_hmac_info_t
 *
 */
typedef struct _alc_hmac_info
{
    // Info about the hash function to be used in HMAC
    alc_digest_mode_t digest_mode;
    // Other specific info about HMAC

} alc_hmac_info_t, *alc_hmac_info_p;

/**
 * @brief Stores details of CMAC
 *
 * @param  cmac_cipher Store info of cipher used for CMAC
 *
 * @struct alc_cmac_info_t
 *
 */
// TODO: Do we need type and mode since only one mode is supported ? Currently
// its used to validate.
typedef struct _alc_cmac_info
{
    alc_cipher_mode_t ci_mode; /*! Mode: ALC_AES_MODE_CTR etc */
    // Other specific info about CMAC
} alc_cmac_info_t, *alc_cmac_info_p;

/**
 * @brief Stores details for algo info for mac
 *
 * @param hmac Stores the hmac info in case MAC to be used is HMAC
 * @param cmac Stores the cmac info in case MAC to be used is CMAC
 *
 * @union alc_mac_info_t
 */
typedef union _mac_info
{
    alc_hmac_info_t hmac;
    alc_cmac_info_t cmac;
} alc_mac_info_t;

typedef void               alc_mac_context_t;
typedef alc_mac_context_t* alc_mac_context_p;

/**
 *
 * @brief  Handle for maintaining session.
 *
 * @param ch_context pointer to the context of the mac
 *
 * @struct alc_mac_handle_t
 *
 */
typedef struct alc_mac_handle
{
    alc_mac_context_p ch_context;
} alc_mac_handle_t, *alc_mac_handle_p, AlcMacHandle;

/**
 * @brief       Gets the size of the context for a session described by
 *              pMacInfo
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called before @ref alcp_mac_request to identify the memory
 * to be allocated for context </b>
 * @endparblock
 *
 * @return      Size of Context
 */
ALCP_API_EXPORT Uint64
alcp_mac_context_size(void);

/**
 * @brief    Allows caller to request for a MAC as described by
 *           macType
 * @parblock <br> &nbsp;
 * <b>This API must be called before making any other API call</b>
 * @endparblock
 * @note     Error needs to be checked after each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param  [in]  macType     Description of the MAC session
 * @param [out]  pMacHandle  Library populated session handle for future
 * mac operations.
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then, an error has occurred and handle will be invalid
 * for future operations
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_request(alc_mac_handle_p pMacHandle, alc_mac_type_t macType);

/**
 * @brief    Allows caller to set key and initialize hmac session
 * @parblock <br> &nbsp;
 * <b>This API must be called only after @ref alcp_mac_request</b>
 * @endparblock
 * @note     Error needs to be checked after each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param [in]   pMacHandle Library populated session handle for future
 * @param [in]   key  pointer to key for mac operations.
 * @param [in]   size size of key.
 * @param [in] info Macinfo populated based on the type of the MAC

 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then, an error has occurred and handle will be invalid
 for future operations
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_init(alc_mac_handle_p pMacHandle,
              const Uint8*     key,
              Uint64           size,
              alc_mac_info_t*  info);

/**
 * @brief    Allows caller to update MAC with chunk of data to be authenticated
 * @parblock <br> &nbsp;
 * <b>This API is called to update data to be authenticated. So should be called
 * after @ref alcp_mac_request  and before the end of session call, @ref
 * alcp_mac_finish</b>
 * @endparblock
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param [in]   pMacHandle  Session handle for future MAC
 *                         operation
 * @param [in]   buff       The chunk of the message to be updated
 * @param [in]   size       Length of input buffer in bytes
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then, an error has occurred and handle will be invalid
 * for future operations
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_update(alc_mac_handle_p pMacHandle, const Uint8* buff, Uint64 size);

/**
 * @brief               Allows caller to finalize and copy final MAC
 * @parblock <br> &nbsp;
 * <b>This API is called to finalize mac so should be called after @ref
 * alcp_mac_init and before @ref alcp_mac_finish</b>
 * @endparblock
 * @note
 *                      - Error needs to be checked for each call,
 *                        valid only if @ref alcp_is_error (ret) is false.
 *
 * @param [in]   pMacHandle  Session handle for future MAC
 *                       operation
 * @param [in]   buff        The buffer holding mac
 * @param [in]   size        mac size in bytes.
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then, an error has occurred and handle will be invalid
 * for future operations
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_finalize(alc_mac_handle_p pMacHandle, Uint8* buff, Uint64 size);

/**
 *
 * @brief               Free resources that was allotted by @ref
 *                      alcp_mac_request
 * @parblock <br> &nbsp;
 * <b>This API is called to free resources so should be called to free the
 * session</b>
 * @endparblock
 * @note                alcp_mac_request() should be called first to allocate
 *                      the Handler.
 *
 * @param [in]   pMacHandle Session handle used for the MAC operations
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then, an error has occurred and handle will be invalid
 * for future operations
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_finish(alc_mac_handle_p pMacHandle);

/**
 *
 * @brief               resets the data given to it during @ref alcp_mac_update
 * or @ref alcp_mac_finalize
 * @parblock <br> &nbsp;
 * <b>This API is called to reset data so should be called after @ref
 * alcp_mac_request  and before @ref alcp_mac_finish</b>
 * @endparblock
 * @param [in]   pMacHandle Session handle for future MAC operation
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE, an error has occurred and handle will be invalid for
 * future operations
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_reset(alc_mac_handle_p pMacHandle);

/**
 * @brief        copies the context from source to destination
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_mac_init and before @ref
 * alcp_mac_finish  on pSrcHandle</b>
 * @endparblock
 *
 * @param [in]   pSrcHandle   source mac handle
 * @param [out]  pDestHandle  destination mac handle
 *
 * @return       alc_error_t Error code to validate the operation
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_context_copy(const alc_mac_handle_p pSrcHandle,
                      const alc_mac_handle_p pDestHandle);

EXTERN_C_END

#endif /* _ALCP_CIPHER_H_ */
       /**
        * @}
        */
