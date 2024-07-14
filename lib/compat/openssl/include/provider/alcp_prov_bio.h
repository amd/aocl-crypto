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
#include "alcp_provider.h"
#include <openssl/bio.h>
#include <openssl/core.h>
#include <stdarg.h>

int
alcp_prov_bio_from_dispatch(const OSSL_DISPATCH* fns);

OSSL_CORE_BIO*
alcp_prov_bio_new_file(const char* filename, const char* mode);
OSSL_CORE_BIO*
alcp_prov_bio_new_membuf(const char* filename, int len);
int
alcp_prov_bio_read_ex(OSSL_CORE_BIO* bio,
                      void*          data,
                      size_t         data_len,
                      size_t*        bytes_read);
int
alcp_prov_bio_write_ex(OSSL_CORE_BIO* bio,
                       const void*    data,
                       size_t         data_len,
                       size_t*        written);
int
alcp_prov_bio_gets(OSSL_CORE_BIO* bio, char* buf, int size);
int
alcp_prov_bio_puts(OSSL_CORE_BIO* bio, const char* str);
int
alcp_prov_bio_ctrl(OSSL_CORE_BIO* bio, int cmd, long num, void* ptr);
int
alcp_prov_bio_up_ref(OSSL_CORE_BIO* bio);
int
alcp_prov_bio_free(OSSL_CORE_BIO* bio);
int
alcp_prov_bio_vprintf(OSSL_CORE_BIO* bio, const char* format, va_list ap);
int
alcp_prov_bio_printf(OSSL_CORE_BIO* bio, const char* format, ...);

BIO_METHOD*
alcp_bio_prov_init_bio_method(void);
BIO*
alcp_bio_new_from_core_bio(alc_prov_ctx_t* provctx, OSSL_CORE_BIO* corebio);
BIO_METHOD*
alcp_prov_ctx_get0_core_bio_method(alc_prov_ctx_t* ctx);
