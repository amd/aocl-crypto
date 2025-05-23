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

#ifndef _ALCP_DIGEST_H
#define _ALCP_DIGEST_H 2

#include <stdint.h>

#include "alcp/error.h"
#include "alcp/macros.h"

EXTERN_C_BEGIN

/**
 * @defgroup digest Digest API
 * @brief
 * A digest is a one way cryptographic function by which a message of any length
 * can be mapped into a fixed-length output. It can be used for verifying
 * integrity or passwords.
 * @{
 */

/**
 * @brief Stores info about digest length used for digest
 *
 * @typedef enum alc_digest_len_t
 */
typedef enum _alc_digest_len
{
    ALC_DIGEST_LEN_128              = 128, /* for MD2,MD4,MD5 */
    ALC_DIGEST_LEN_192              = 192,
    ALC_DIGEST_LEN_160              = 160, /* for SHA1 */
    ALC_DIGEST_LEN_288              = 288, /* for MD5_SHA1 */
    ALC_DIGEST_LEN_224              = 224, /* SHA224, SHA512/224 */
    ALC_DIGEST_LEN_256              = 256, /* MD6, SHA256, SHA512/256 */
    ALC_DIGEST_LEN_384              = 384, /* SHA348 */
    ALC_DIGEST_LEN_512              = 512, /* SHA512 */
    ALC_DIGEST_LEN_CUSTOM_SHAKE_128 = 17,  /* anything not covered by above */
    ALC_DIGEST_LEN_CUSTOM_SHAKE_256 = 18,  /* anything not covered by above */
} alc_digest_len_t;

/**
 * @brief Stores info about block size used for digest
 *
 * @typedef enum alc_digest_block_size_t
 */
typedef enum alc_digest_block_size
{
    ALC_DIGEST_BLOCK_SIZE_MD5       = 512,
    ALC_DIGEST_BLOCK_SIZE_SHA1      = 512,
    ALC_DIGEST_BLOCK_SIZE_MD5_SHA1  = ALC_DIGEST_BLOCK_SIZE_SHA1,
    ALC_DIGEST_BLOCK_SIZE_SHA2_256  = 512,
    ALC_DIGEST_BLOCK_SIZE_SHA2_512  = 1024,
    ALC_DIGEST_BLOCK_SIZE_SHA3_224  = 1152,
    ALC_DIGEST_BLOCK_SIZE_SHA3_256  = 1088,
    ALC_DIGEST_BLOCK_SIZE_SHA3_384  = 832,
    ALC_DIGEST_BLOCK_SIZE_SHA3_512  = 576,
    ALC_DIGEST_BLOCK_SIZE_SHAKE_128 = 1344,
    ALC_DIGEST_BLOCK_SIZE_SHAKE_256 = 1088
} alc_digest_block_size_t;

/**
 * @brief Stores info about digest mode to be used
 *
 * @typedef enum alc_digest_mode_t
 */
typedef enum _alc_digest_mode
{
    ALC_MD5,
    ALC_SHA1,
    ALC_MD5_SHA1,
    ALC_SHA2_224,
    ALC_SHA2_256,
    ALC_SHA2_384,
    ALC_SHA2_512,
    ALC_SHA2_512_224,
    ALC_SHA2_512_256,
    ALC_SHA3_224,
    ALC_SHA3_256,
    ALC_SHA3_384,
    ALC_SHA3_512,
    ALC_SHAKE_128,
    ALC_SHAKE_256,
} alc_digest_mode_t,
    *alc_diget_mode_p;

/**
 * @brief Store Context for the future operation of digest
 *
 */
typedef void                  alc_digest_context_t;
typedef alc_digest_context_t* alc_digest_context_p;

/**
 * @brief Handle for maintaining session.
 *
 * @param context pointer to the context of the digest
 *
 * @struct alc_digest_handle_t
 */
typedef struct _alc_digest_handle
{
    alc_digest_context_p context;
} alc_digest_handle_t, *alc_digest_handle_p, AlcDigestHandle, *AlcDigestHandleP;

/**
 * @brief  Returns the context size
 *
 * @parblock <br> &nbsp;
 * <b>This API should be called before @ref alcp_digest_request to identify the
 * memory to be allocated for context </b>
 * @endparblock
 *
 *
 *
 * @return Size of Context
 */
ALCP_API_EXPORT Uint64
alcp_digest_context_size(void);

/**
 * @brief        Request a handle for digest  for a configuration
 *               as pointed by alc_digest_mode_t
 *
 * @param [in]   mode             Description of the requested digest session
 *
 * @param [out]  p_digest_handle  Library populated session handle for future
 * digest operations.
 *
 * @return       &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_request(alc_digest_mode_t   mode,
                    alc_digest_handle_p p_digest_handle);

/**
 * @brief       Initializes the digest handle
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_digest_request and before @ref
 * alcp_digest_finish</b>
 * @endparblock
 *
 * @param [in]  p_digest_handle  Library populated session handle
 *
 * @return      &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_init(alc_digest_handle_p p_digest_handle);

/**
 * @brief       Computes digest for the buffer pointed by buf for size as
 *              as mentioned by size in bytes.
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_digest_init and before @ref
 * alcp_digest_finalize</b>
 * @endparblock
 *
 * @note        repeated calls to this is allowed and the handle will
 *              contain the latest digest.
 *
 * @param [in]  p_digest_handle  Handle created by alcp_digest_request()
 *
 * @param [in]  buf              Input buffer
 *
 * @param [in]  size             Input buffer size in bytes.
 *
 * @return      &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_update(const alc_digest_handle_p p_digest_handle,
                   const Uint8*              buf,
                   Uint64                    size);

/**
 * @brief       Finalize the digest with digest copy.
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_digest_update and before @ref
 * alcp_digest_finish</b>
 * @endparblock
 *
 * @param [in]   p_digest_handle  Handle created by alcp_digest_request()
 *
 * @param [out]  buf              Destination buffer to which digest will be
 *                                copied
 *
 * @param [in]   size             Destination buffer size in bytes, should be
 *                                big enough to hold the digest
 *
 * @return       &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_finalize(const alc_digest_handle_p p_digest_handle,
                     Uint8*                    buf,
                     Uint64                    size);

/**
 *
 * @brief       Performs any cleanup actions
 *
 * @parblock <br> &nbsp;
 * <b>This API is called to free resources so should be called to free the
 * session</b>
 * @endparblock
 *
 * @note        Must be called to ensure memory allotted (if any) is cleaned.
 *
 * @param [in]  p_digest_handle  Handle created by alcp_digest_request().
 *                               Once this function is called, the handle will
 *                               not be valid for future calls
 *
 * @return      None
 */
ALCP_API_EXPORT void
alcp_digest_finish(const alc_digest_handle_p p_digest_handle);

/**
 * @brief        copies the context from source to destination
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_digest_init and before @ref
 * alcp_digest_finish</b> on pSrcHandle
 * @endparblock
 *
 * @param [in]   pSrcHandle   source digest handle
 * @param [out]  pDestHandle  destination digest handle
 *
 * @return       alc_error_t Error code to validate the operation
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_context_copy(const alc_digest_handle_p pSrcHandle,
                         const alc_digest_handle_p pDestHandle);

/**
 * @brief        Valid only for Shake algorithm for squeezing the digest out.
 *               It can be called multiple times. It should not be called with
 * @ref alcp_digest_finalize
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_digest_update and before @ref
 * alcp_digest_finish</b>
 * @endparblock
 *
 * @param [in]   pDigestHandle  Handle created by alcp_digest_request()
 * @param [out]  pBuff          Destination Buffer for digest out
 * @param [in]   size           size of data to be squeezed out
 *
 * @return       alc_error_t Error code to validate the operation
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_shake_squeeze(const alc_digest_handle_p pDigestHandle,
                          Uint8*                    pBuff,
                          Uint64                    size);

EXTERN_C_END

#endif /* _ALCP_DIGEST_H */
       /**
        * @}
        */
