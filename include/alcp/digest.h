/*
 * Copyright (C) 2021-2023, Advanced Micro Devices. All rights reserved.
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
 * @brief Stores info about type of digest used
 *
 * @typedef enum alc_digest_type_t
 */
typedef enum _alc_digest_type
{
    ALC_DIGEST_TYPE_MD2,
    ALC_DIGEST_TYPE_MD4,
    ALC_DIGEST_TYPE_MD5,
    ALC_DIGEST_TYPE_SHA1,
    ALC_DIGEST_TYPE_SHA2,
    ALC_DIGEST_TYPE_SHA3,
} alc_digest_type_t;

/**
 * @brief Stores info about mode of sha2 digest used
 *
 * @typedef enum alc_sha2_mode_t
 */
typedef enum _alc_sha2_mode
{
    ALC_SHA2_224,
    ALC_SHA2_256,
    ALC_SHA2_384,
    ALC_SHA2_512,
} alc_sha2_mode_t;

/**
 * @brief Stores info about mode of sha3 digest used
 *
 * @typedef enum alc_sha3_mode_t
 */
typedef enum _alc_sha3_mode
{
    ALC_SHA3_224,
    ALC_SHA3_256,
    ALC_SHA3_384,
    ALC_SHA3_512,
    ALC_SHAKE_128,
    ALC_SHAKE_256,
} alc_sha3_mode_t;

/**
 * @brief Stores info about digest length used for digest
 *
 * @typedef enum alc_digest_len_t
 */
typedef enum _alc_digest_len
{
    ALC_DIGEST_LEN_128 = 128, /* for MD2,MD4,MD5 */
    ALC_DIGEST_LEN_192 = 192,
    ALC_DIGEST_LEN_160 = 160, /* for SHA1 */
    ALC_DIGEST_LEN_224 = 224, /* SHA224, SHA512/224 */
    ALC_DIGEST_LEN_256 = 256, /* MD6, SHA256, SHA512/256 */
    ALC_DIGEST_LEN_384 = 384, /* SHA348 */
    ALC_DIGEST_LEN_512 = 512, /* SHA512 */

    ALC_DIGEST_LEN_CUSTOM = 17, /* anything not covered by above */
} alc_digest_len_t;

/**
 * @brief Stores info about digest mode to be used
 *
 * @param dm_sha2, dm_sha3 used to store info of mode
 *
 * @union alc_digest_mode_t
 */
typedef union _alc_digest_mode
{
    alc_sha2_mode_t dm_sha2;
    alc_sha3_mode_t dm_sha3;

} alc_digest_mode_t, *alc_diget_mode_p;

/**
 * @brief Stores info about digest data
 *
 * @param dd_ptr used to store digest data
 *
 * @struct alc_digest_data_t
 */
typedef struct _alc_digest_data
{
    void* dd_ptr;
} alc_digest_data_t;

/**
 * @brief Stores all info about digest
 *
 * @param dt_type Stores info about type of digest used
 * @param dt_len  Stores info about digest length used for digest
 * @param dt_custom_len Stores digest length valid when dgst_len ==
 * ALC_DIGEST_LEN_CUSTOM
 * @param dt_mode Stores info about digest mode to be used
 * @param dt_data Stores info about digest data
 *
 * @struct alc_digest_info_t
 */
typedef struct _alc_digest_info
{
    alc_digest_type_t dt_type;
    alc_digest_len_t  dt_len;
    /* valid when dgst_len == ALC_DIGEST_LEN_CUSTOM */
    Uint32            dt_custom_len;
    alc_digest_mode_t dt_mode;
    alc_digest_data_t dt_data;
} alc_digest_info_t, *alc_digest_info_p;

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
 * @brief       Returns the context size of the interaction
 *
 * @parblock <br> &nbsp;
 * <b>This API should be called before @ref alcp_digest_request to identify the
 * memory to be allocated for context </b>
 * @endparblock
 *
 * @note       alcp_digest_supported() should be called first to
 *              know if the given configuration is valid.
 *
 * @param [in]       p_digest_info   Description of the requested digest session
 *
 * @return      Size of Context
 */
ALCP_API_EXPORT Uint64
alcp_digest_context_size(const alc_digest_info_p p_digest_info);

/**
 * @brief  Allows to check if a given algorithm is supported or not
 *
 * @parblock <br> &nbsp;
 * <b>This API needs to be called before any other API is called to
 * know if digest that is being request is supported or not </b>
 * @endparblock
 *
 * @note        alcp_digest_supported() is called first to
 *              know if the given configuration is valid.
 *
 * @param [in]      p_digest_info Description of the requested digest session
 *
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str needs to be called to know
 * about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_supported(const alc_digest_info_p p_digest_info);

/**
 * @brief       Request a handle for digest  for a configuration
 *              as pointed by p_digest_info_p
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_digest_supported is called and at
 * the end of session call @ref alcp_digest_finish </b>
 * @endparblock
 *
 * @note       alcp_digest_supported() should be called first to
 *              know if the given type/digest length configuration is valid.
 *
 * @param [in]      p_digest_info   Description of the requested digest session
 *
 * @param [out]      p_digest_handle Library populated session handle for future
 * digest operations.
 *
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str needs to be called to know
 * about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_request(const alc_digest_info_p p_digest_info,
                    alc_digest_handle_p     p_digest_handle);

/**
 * @brief       Computes digest for the buffer pointed by buf for size as
 *              as mentioned by size in bytes.
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_digest_request and at the end of
 * session call @ref alcp_digest_finish</b>
 * @endparblock
 *
 * @note       repeated calls to this is allowed and the handle will
 *               contain the latest digest.
 * @param [in] p_digest_handle The handle that was returned as part of call
 * together alcp_digest_request()
 * @param [in] buf              Destination buffer to which digest will be
 * copied
 * @param [in] size             Destination buffer size in bytes, should be big
 * enough to hold the digest
 * @return   &nbsp; Error Code for the API called. if alc_error_t
 * is not zero then @ref alcp_error_str needs to be called to know about error
 * occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_update(const alc_digest_handle_p p_digest_handle,
                   const Uint8*              buf,
                   Uint64                    size);

/**
 * @brief       Digest is kept as part of p_digest_handle, this API allows
 *              it to be copied to specified buffer
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_digest_request and at the end of
 * session call @ref alcp_digest_finish</b>
 * @endparblock
 *
 * @param [in] p_digest_handle The handle that was returned as part of
 *                         call together alcp_digest_request()
 * @param [out]       buf     Destination buffer to which digest will be copied
 *
 * @param [in]       size    Destination buffer size in bytes, should be big
 * enough to hold the digest
 *
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str needs to be called to know
 * about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_copy(const alc_digest_handle_p p_digest_handle,
                 Uint8*                    buf,
                 Uint64                    size);

/**
 * @brief       Finalize the digest with last buffer.
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_digest_request  and at the end of
 * session call @ref alcp_digest_finish</b>
 * @endparblock
 *
 * @note       It is expected that application calls @ref alcp_digest_copy()
 * after calling this functions as the contents of the session is not guaranteed
 * to persist after @ref alcp_digest_finish()
 *
 * @param [in]      p_digest_handle The handle that was returned as part of call
 *                              together alcp_digest_request(),
 *
 * @param[out]      p_msg_buf       pointer to message buffer or NULL
 *
 * @param[in]      size            Size of message buffer in bytes can be 0
 *
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str needs to be called to know
 * about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_finalize(const alc_digest_handle_p p_digest_handle,
                     const Uint8*              p_msg_buf,
                     Uint64                    size);

/**
 *
 * FIXME: Need to fix return type of API
 * @brief       Performs any cleanup actions
 *
 * @parblock <br> &nbsp;
 * <b>This API is called to free resources so should be called to free the
 * session</b>
 * @endparblock
 *
 * @note       Must be called to ensure memory allotted (if any) is cleaned.
 *
 * @param [in] p_digest_handle The handle that was returned as part of call
 *                       together alcp_digest_request(), once this function
 *                       is called. the handle is will not be valid for future
 *
 * @return      None
 */
ALCP_API_EXPORT void
alcp_digest_finish(const alc_digest_handle_p p_digest_handle);

/**
 *
 * FIXME: Need to fix return type of API
 * @brief       resets the internal state of the digest handle
 *
 * @parblock <br> &nbsp;
 * <b>This API is called to reset data so should be called after @ref
 * alcp_digest_request and at the end of
 * session call @ref alcp_digest_finish</b>
 * @endparblock
 *
 * @note       Must be called to restart the digest operation on an already
 * existing handle.
 *
 * @param [in] p_digest_handle The handle that was returned as part of call
 *                       together alcp_digest_request(), once this function
 *                       is called. the handle is will not be valid for future
 *
 * @return      None
 */
ALCP_API_EXPORT void
alcp_digest_reset(const alc_digest_handle_p p_digest_handle);

/**
 * @brief              Get the error string for errors occurring in digest
 *                     operations
 * @parblock <br> &nbsp;
 * <b> This API is called to get the error string. It should be called after
 * @ref alcp_digest_request and before @ref alcp_digest_finish </b>
 * @endparblock
 * @param [in] pDigestHandle Session handle for digest operation
 * @param [out] pBuff  Destination Buffer to which Error String will be copied
 * @param [in] size    Length of the Buffer.
 *
 * @return alc_error_t Error code to validate the Handle
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_error(alc_digest_handle_p pDigestHandle, Uint8* pBuff, Uint64 size);

/**
 * @brief       To Set custom length for SHAKE128 or SHAKE256
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_digest_request  and before @ref
 * alcp_digest_finalize. This will override the digest size value set during
 * @ref alcp_digest_request</b>
 * @endparblock
 *
 *
 * @param [in]      p_digest_handle The handle that was returned as part of call
 *                              together alcp_digest_request(),
 *
 * @param[in]      size            Size of the Digest to be set
 *
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str needs to be called to know
 * about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_set_shake_length(const alc_digest_handle_p p_digest_handle,
                             Uint64                    size);

EXTERN_C_END

#endif /* _ALCP_DIGEST_H */
       /**
        * @}
        */
