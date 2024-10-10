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

// config.h is cmake generated, please modify config.h.in instead.
#ifndef _INCLUDE_PROVIDER_CONFIG_H
#define _INCLUDE_PROVIDER_CONFIG_H 2

/* #undef ALCP_COMPAT_ENABLE_OPENSSL_DIGEST */
#define ALCP_COMPAT_ENABLE_OPENSSL_CIPHER
#define ALCP_COMPAT_ENABLE_OPENSSL_RSA
#define ALCP_COMPAT_ENABLE_OPENSSL_MAC

// Sub options for DIGEST
/* #undef ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA2 */
/* #undef ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA3 */
/* #undef ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHAKE */

// Sub options for CIPHER
/* #undef ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CBC */
#define ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_OFB
#define ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CFB
#define ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CTR
#define ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_XTS
#define ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_GCM
/* #undef ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CCM */
#define ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_SIV

// Sub options for MAC
/* #undef ALCP_COMPAT_ENABLE_OPENSSL_MAC_HMAC */
#define ALCP_COMPAT_ENABLE_OPENSSL_MAC_CMAC
#define ALCP_COMPAT_ENABLE_OPENSSL_MAC_POLY1305

#endif
