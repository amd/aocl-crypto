/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp_mac_hmac.h"
DEFINE_HMAC_CONTEXT(SHA2);

int
ALCP_prov_HMAC_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    ENTER();
    int ret = ALCP_prov_mac_get_ctx_params(vctx, params);
    EXIT();
    return ret;
}

int
ALCP_prov_HMAC_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    int ret = ALCP_prov_mac_set_ctx_params(vctx, params);
    EXIT();
    return ret;
}

void
ALCP_prov_HMAC_ctxfree(alc_prov_mac_ctx_p mac_ctx)
{
    ENTER();
    ALCP_prov_mac_freectx(mac_ctx);
    EXIT();
}

/* MAC dispatchers */
CREATE_MAC_DISPATCHERS(HMAC, SHA2);