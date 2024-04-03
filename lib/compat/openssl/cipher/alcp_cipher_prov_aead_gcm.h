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

#include <inttypes.h>

#include "cipher/alcp_cipher_prov.h"
#include "provider/alcp_names.h"

/* ALCP Headers */
#include "alcp_cipher_prov_common.h"
#include <alcp/cipher.h>

#define GCM_IV_DEFAULT_SIZE 12
#define GCM_IV_MAX_SIZE     (1024 / 8)
#define GCM_TAG_MAX_SIZE    16

OSSL_FUNC_cipher_encrypt_init_fn   ALCP_prov_gcm_einit;
OSSL_FUNC_cipher_decrypt_init_fn   ALCP_prov_gcm_dinit;
OSSL_FUNC_cipher_get_ctx_params_fn ALCP_prov_gcm_get_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn ALCP_prov_gcm_set_ctx_params;
OSSL_FUNC_cipher_cipher_fn         ALCP_prov_gcm_cipher;
OSSL_FUNC_cipher_update_fn         ALCP_prov_gcm_stream_update;
OSSL_FUNC_cipher_final_fn          ALCP_prov_gcm_stream_final;

void
ALCP_prov_gcm_initctx(void* provctx, ALCP_PROV_CIPHER_CTX* ctx, size_t keybits);
