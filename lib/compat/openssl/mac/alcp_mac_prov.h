/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 notice,
 *    this list of conditions and the following disclaimer in the
 documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 IS"
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

#ifndef _OPENSSL_ALCP_MAC_PROV_H
#define _OPENSSL_ALCP_MAC_PROV_H 2

#include "debug.h"
#include "provider/alcp_provider.h"
#include <alcp/mac.h>
#include <openssl/core_names.h>

struct _alc_prov_mac_ctx
{
    alc_mac_handle_t handle;
};
typedef struct _alc_prov_mac_ctx alc_prov_mac_ctx_t, *alc_prov_mac_ctx_p;
extern const OSSL_ALGORITHM      ALC_prov_macs[];

int
alcp_prov_mac_init(void*                vctx,
                   const unsigned char* key,
                   size_t               keylen,
                   const OSSL_PARAM     params[]);
void*
alcp_prov_mac_newctx(alc_mac_type_t mac_type);
void
alcp_prov_mac_freectx(void* vctx);
int
alcp_prov_mac_update(void* vctx, const unsigned char* in, size_t inl);
int
alcp_prov_mac_final(void*          vctx,
                    unsigned char* out,
                    size_t*        outl,
                    size_t         outsize);

#endif /* _OPENSSL_alcp_prov_MAC_PROV_H */
