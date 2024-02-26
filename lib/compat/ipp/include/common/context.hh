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

#include "alcp/alcp.h"
#include "ippcp.h"
#include <cstddef>
#include <vector>
#pragma once
typedef struct _ipp_wrp_aes_ctx
{
    alc_cipher_handle_t    handle;
    alc_cipher_info_t      cinfo;
    alc_cipher_aead_info_t c_aeadinfo;

} ipp_wrp_aes_ctx;
typedef struct _ipp_wrp_aes_aead_ctx
{
    bool            is_encrypt;
    size_t          msg_len;
    size_t          tag_len;
    ipp_wrp_aes_ctx aead_ctx;
} ipp_wrp_aes_aead_ctx;

typedef struct _ipp_wrp_aes_xts_ctx
{
    bool            is_encrypt;
    ipp_wrp_aes_ctx cipher_ctx;
} ipp_wrp_aes_xts_ctx;

typedef struct _ipp_wrp_sha2_ctx
{
    alc_digest_handle_t handle;
    alc_digest_info_t   dinfo;
} ipp_wrp_sha2_ctx;

typedef struct _ipp_sha2_rmf_algo_ctx
{
    IppHashAlgId algId;      // ID of the current algorithm
    int          len;        // Length of hash output in bytes
    int          blockSize;  // Length of a block in bytes
    int          lenRepSize; // Length of processed message
    // There are more, for now they are useless.
} ipp_sha2_rmf_algo_ctx;

typedef struct _ipp_wrp_mac_ctx
{
    alc_mac_handle handle   = {};
    alc_mac_info_t mac_info = {};
} ipp_wrp_mac_ctx;