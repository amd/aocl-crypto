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

#include "alcp/alcp.h"
#include "alcp/rsa.h"
#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>

#define ALCP_MAX_NAME_SIZE 50 /* Algorithm name */

// structure taken from OpenSSL code to support key management

typedef struct rsa_pss_params_30_st
{
    int hash_algorithm_nid;
    struct
    {
        int algorithm_nid; /* Currently always NID_mgf1 */
        int hash_algorithm_nid;
    } mask_gen;
    int salt_len;
    int trailer_field;
} RSA_PSS_PARAMS_30;

typedef struct
{
    BN_ULONG* d; /*
                  * Pointer to an array of 'BN_BITS2' bit
                  * chunks. These chunks are organised in
                  * a least significant chunk first order.
                  */
    int top;     /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax; /* Size of the d array. */
    int neg;  /* one if the number is negative */
    int flags;
} bignum_st;

typedef struct
{
    /*
     * #legacy
     * The first field is used to pickup errors where this is passed
     * instead of an EVP_PKEY.  It is always zero.
     * THIS MUST REMAIN THE FIRST FIELD.
     */
    int dummy_zero;

    OSSL_LIB_CTX*     libctx;
    int32_t           version;
    const RSA_METHOD* meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE*    engine;
    bignum_st* n;
    bignum_st* e;
    bignum_st* d;
    bignum_st* p;
    bignum_st* q;
    bignum_st* dmp1;
    bignum_st* dmq1;
    bignum_st* iqmp;

    /*
     * If a PSS only key this contains the parameter restrictions.
     * There are two structures for the same thing, used in different cases.
     */
    /* This is used uniquely by OpenSSL provider implementations. */
    RSA_PSS_PARAMS_30 pss_params;

#if defined(FIPS_MODULE) && !defined(OPENSSL_NO_ACVP_TESTS)
    RSA_ACVP_TEST* acvp_test;
#endif

#ifndef FIPS_MODULE
    /* This is used uniquely by rsa_ameth.c and rsa_pmeth.c. */
    RSA_PSS_PARAMS* pss;
    /* for multi-prime RSA, defined in RFC 8017 */
    STACK_OF(RSA_PRIME_INFO) * prime_infos;
    /* Be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;
#endif
    int references;
    int flags;
    /* Used to cache montgomery values */
    BN_MONT_CTX*   _method_mod_n;
    BN_MONT_CTX*   _method_mod_p;
    BN_MONT_CTX*   _method_mod_q;
    BN_BLINDING*   blinding;
    BN_BLINDING*   mt_blinding;
    CRYPTO_RWLOCK* lock;

    int dirty_cnt;
} Rsa;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes RSA structures, so
 * we use that here too.
 */
int
alcp_rsa_size(const Rsa* r);
int
alcp_rsa_get_digest_mode(const char* str);
int
alcp_rsa_get_digest_size(alc_digest_mode_t mode);
void
alcp_rsa_free(Rsa* r);
