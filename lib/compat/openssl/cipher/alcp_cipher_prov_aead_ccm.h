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

#pragma once

#include "alcp_cipher_prov_aead.h"
#include "provider/alcp_provider.h"
typedef struct alcp_prov_ccm_st
{
    Uint32                  isTagSet;
    Uint32                  isLenSet : 1;
    size_t                  l, m;
    alc_prov_cipher_data_t* prov_cipher_data;
    alc_cipher_handle_t     handle;
} ALCP_PROV_CCM_CTX;

OSSL_FUNC_cipher_encrypt_init_fn   ALCP_prov_ccm_einit;
OSSL_FUNC_cipher_decrypt_init_fn   ALCP_prov_ccm_dinit;
OSSL_FUNC_cipher_get_ctx_params_fn ALCP_prov_ccm_get_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn ALCP_prov_ccm_set_ctx_params;
OSSL_FUNC_cipher_update_fn         ALCP_prov_ccm_stream_update;
OSSL_FUNC_cipher_final_fn          ALCP_prov_ccm_stream_final;
OSSL_FUNC_cipher_cipher_fn         ALCP_prov_ccm_cipher;