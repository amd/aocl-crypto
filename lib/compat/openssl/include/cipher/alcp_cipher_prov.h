/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#ifndef _OPENSSL_ALCP_CIPHER_PROV_H
#define _OPENSSL_ALCP_CIPHER_PROV_H 2

/* OpenSSL Headers */
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>

/* ALCP Headers */
#include <alcp/cipher.h>
#include <alcp/key.h>

/* Provider Internal Headers */
#include "debug.h"

/*
 * Dispatchers are created by alcp_cipher_aes.c using macro
 * defined above
 */

extern const OSSL_DISPATCH ALCP_prov_aes128ctr_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes192ctr_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes256ctr_functions[];

extern const OSSL_DISPATCH ALCP_prov_aes128cfb_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes192cfb_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes256cfb_functions[];

extern const OSSL_DISPATCH ALCP_prov_aes128ofb_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes192ofb_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes256ofb_functions[];

extern const OSSL_DISPATCH ALCP_prov_aes128cbc_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes192cbc_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes256cbc_functions[];

extern const OSSL_DISPATCH ALCP_prov_aes128gcm_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes192gcm_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes256gcm_functions[];

extern const OSSL_DISPATCH ALCP_prov_aes128xts_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes256xts_functions[];

extern const OSSL_DISPATCH ALCP_prov_aes128siv_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes192siv_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes256siv_functions[];

extern const OSSL_DISPATCH ALCP_prov_aes128ccm_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes192ccm_functions[];
extern const OSSL_DISPATCH ALCP_prov_aes256ccm_functions[];

#if 0

 extern const OSSL_DISPATCH siv_functions_128[];
 extern const OSSL_DISPATCH siv_functions_192[];
 extern const OSSL_DISPATCH siv_functions_256[];
#endif

#endif /* _OPENSSL_ALCP_prov_CIPHER_PROV_H */
