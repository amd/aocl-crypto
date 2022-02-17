/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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

typedef enum _alc_digest_type
{
    ALC_DIGEST_TYPE_MD2,
    ALC_DIGEST_TYPE_MD4,
    ALC_DIGEST_TYPE_MD5,
    ALC_DIGEST_TYPE_SHA1,
    ALC_DIGEST_TYPE_SHA2,
    ALC_DIGEST_TYPE_SHA3,
} alc_digest_type_t;

typedef enum _alc_sha2_mode
{
    ALC_SHA2_224,
    ALC_SHA2_256,
    ALC_SHA2_384,
    ALC_SHA2_512,
} alc_sha2_mode_t;

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

typedef union _alc_digest_mode
{
    alc_sha2_mode_t dm_sha2;

} alc_digest_mode_t, *alc_diget_mode_p;

typedef struct _alc_digest_data
{
    void* dd_ptr;
} alc_digest_data_t;

typedef struct _alc_digest_info
{
    alc_digest_type_t dt_type;
    alc_digest_len_t  dt_len;
    /* valid when dgst_len == ALC_DIGEST_LEN_CUSTOM */
    uint32_t          dt_custom_len;
    alc_digest_mode_t dt_mode;
    alc_digest_data_t dt_data;
} alc_digest_info_t, *alc_digest_info_p;

/**
 * \brief
 *
 * \notes
 */
typedef void                  alc_digest_context_t;
typedef alc_digest_context_t* alc_digest_context_p;

/**
 * \brief
 * \notes
 */
typedef struct _alc_digest_handle
{
    alc_digest_context_p context;
} alc_digest_handle_t, *alc_digest_handle_p;

/**
 * \brief       Returns the context size of the interaction
 *
 * \notes       alcp_cipher_supported() should be called first to
 *              know if the given cipher/key length configuration is valid.
 *
 * \param       p_digest_info   Description of the requested cipher session
 *
 * \return      size > 0        if valid session is found, size otherwise
 */
uint64_t
alcp_digest_context_size(const alc_digest_info_p p_digest_info);

/**
 * \brief       TODO: fix this comment
 *
 * \notes       alcp_cipher_supported() should be called first to
 *              know if the given cipher/key length configuration is valid.
 *
 * \param       p_digest_info Description of the requested cipher session
 *
 * \return      size > 0 if valid session is found, size otherwise
 */
alc_error_t
alcp_digest_supported(const alc_digest_info_p p_digest_info);

/**
 * \brief       Request a handle for digest  for a configuration
 *              as pointed by p_digest_info_p
 * \notes       alcp_cipher_supported() should be called first to
 *              know if the given type/digest length configuration is valid.
 *
 * \param       p_digest_info   Description of the requested digest session
 *
 * \param        p_digest_handle The handle returned by the Library
 *
 * \return      size > 0        if valid session is found, size otherwise
 */
alc_error_t
alcp_digest_request(const alc_digest_info_p p_digest_info,
                    alc_digest_handle_p     p_digest_handle);

/**
 * \brief       Computes digest for the buffer pointed by buf for size as
 *              as mentioned by size.
 * \notes       repeated calls to this is allowed and the handle will
 *               contain the latest digest.
 * \param  p_digest_handle The handle that was returned as part of call together
 *                         alcp_digest_request()
 * \param buf              Destination buffer to which digest will be copied
 * \param size             Destination buffer size, should be big enough
 *                         to hold the digest
 * \return      ALC_ERROR_NONE if buffer is big enough and handle is valid;
 *              otherwise corresponding error is returned.
 */
alc_error_t
alcp_digest_update(const alc_digest_handle_p p_digest_handle,
                   const uint8_t*            buf,
                   uint64_t                  size);

/**
 * \brief       Digest is kept as part of p_digest_handle, this API allows
 *              it to be copied to specified buffer
 * \notes
 *
 * \param  p_digest_handle The handle that was returned as part of
 *                         call together alcp_digest_request()
 * \param       buf     Destination buffer to which digest will be copied
 *
 * \param       size    Destination buffer size, should be big enough
 *                      to hold the digest
 *
 * \return      ALC_ERROR_NONE  if buffer is big enough and handle is valid;
 *                      otherwise corresponding error is returned.
 */
alc_error_t
alcp_digest_copy(const alc_digest_handle_p p_digest_handle,
                 uint8_t*                  buf,
                 uint64_t                  size);

/**
 * \brief       Final buffer call
 *
 * \notes       It is expected that application calls alcp_digest_copy() before
 *              calling this functions as the contents of the session is not
 *              guaranteed to persist after alcp_digest_finish()
 *
 * \param       p_digest_handle The handle that was returned as part of call
 *                              together alcp_digest_request(),
 *
 * \param       p_msg_buf       pointer to message buffer or NULL
 *
 * \param       size            Size of message buffer or 0
 *
 * \return      ALC_ERROR_NONE if no error occurs
 */
alc_error_t
alcp_digest_finalize(const alc_digest_handle_p p_digest_handle,
                     const uint8_t*            p_msg_buf,
                     uint64_t                  size);

/**
 * \brief       Performs any cleanup actions
 *
 * \notes       Must be called to ensure memory allotted (if any) is cleaned.
 *
 * \param  p_digest_handle The handle that was returned as part of call
 *                       together alcp_digest_request(), once this function
 *                       is called. the handle is will not be valid for future
 *
 * \return      None
 */
void
alcp_digest_finish(const alc_digest_handle_p p_digest_handle);

EXTERN_C_END

#endif /* _ALCP_DIGEST_H */
