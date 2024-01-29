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

#include "rsa/ipp_rsa.hh"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <ostream>
namespace alcp::testing {

/* Function to create bignum from a byte stream */
IppsBigNumState*
createSetBigNUM(Uint8* buff, int size_buff) // size in bytes
{
    int size;
    ippsBigNumGetSize(size_buff * 2 / 8, &size);
    IppsBigNumState* m_pBN_N = (IppsBigNumState*)(new Ipp8u[size]);
    ippsBigNumInit(size_buff * 2 / 8, m_pBN_N);

    if (buff == NULL) {
        return m_pBN_N;
    }
    Ipp32u*        N     = new Ipp32u[size_buff * 2 / 8];
    unsigned char* p_res = (unsigned char*)(N);
    for (int i = size_buff - 1, j = 0; i >= 0; --i, ++j) {
        p_res[j] = buff[i];
    }
    ippsSet_BN(IppsBigNumPOS, size_buff * 2 / 8, N, m_pBN_N);
    delete[](Ipp32u*) N;

    return m_pBN_N;
}

/* get sha2 method from digest info */
const IppsHashMethod*
getIppHashMethod(alc_digest_info_t pDigestInfo)
{
    switch (pDigestInfo.dt_len) {
        case ALC_DIGEST_LEN_256:
            return ippsHashMethod_SHA256_TT();
            break;
        case ALC_DIGEST_LEN_512:
            return ippsHashMethod_SHA512();
            break;
        default:
            return nullptr;
    }
    return nullptr;
}

IPPRsaBase::IPPRsaBase() {}

IPPRsaBase::~IPPRsaBase()
{
    if (m_pPub) {
        delete[](Ipp8u*) m_pPub;
    }
    if (m_pPrv) {
        delete[](Ipp8u*) m_pPrv;
    }
    if (m_scratchBuffer_Pub) {
        delete[](Ipp8u*) m_scratchBuffer_Pub;
    }
    if (m_scratchBuffer_Pvt) {
        delete[](Ipp8u*) m_scratchBuffer_Pvt;
    }
}

bool
IPPRsaBase::init()
{
    return true;
}

bool
IPPRsaBase::SetPrivateKey(const alcp_rsa_data_t& data)
{
    IppStatus status   = ippStsNoErr;
    Uint8     P_1024[] = { 0xfd, 0xf9, 0xc7, 0x69, 0x6c, 0x3b, 0x60, 0x8f,
                       0xec, 0x27, 0xc7, 0x50, 0x42, 0x29, 0xf0, 0x81,
                       0x9b, 0xa9, 0xeb, 0x7b, 0xe7, 0xc1, 0x58, 0x04,
                       0x52, 0xc0, 0x07, 0x84, 0x32, 0xd3, 0xf2, 0x72,
                       0x41, 0x9c, 0x96, 0x5c, 0x84, 0x14, 0x9e, 0x63,
                       0xba, 0x0a, 0x98, 0xcd, 0x56, 0xab, 0x47, 0x0b,
                       0xd5, 0xa7, 0x43, 0x30, 0x0c, 0xf5, 0x62, 0xd1,
                       0x3b, 0xa2, 0x0d, 0x7e, 0xdf, 0x38, 0x9a, 0x4b };
    Uint8     P_2048[] = {
        0xd5, 0x39, 0x40, 0x4f, 0xf5, 0x22, 0xe1, 0x30, 0x5d, 0x80, 0x69, 0xa6,
        0xd1, 0x19, 0x63, 0xec, 0x92, 0x89, 0x10, 0xd9, 0xe9, 0x0c, 0xa2, 0x05,
        0x13, 0xc6, 0xcf, 0xe9, 0x5c, 0xbc, 0x4b, 0x00, 0x66, 0xa7, 0x93, 0x22,
        0x46, 0x87, 0xc4, 0x4c, 0xc9, 0xde, 0xe0, 0x10, 0x4a, 0x2d, 0xc1, 0x5c,
        0xb2, 0x50, 0x89, 0xac, 0x5b, 0xe3, 0x97, 0xbf, 0xaf, 0xe0, 0x1f, 0x5a,
        0xd9, 0xd7, 0xbb, 0x84, 0x96, 0x2a, 0xb5, 0xeb, 0xeb, 0x5e, 0x33, 0x3d,
        0xd6, 0xfc, 0x05, 0x85, 0xce, 0xb3, 0xd2, 0x6d, 0xbb, 0xbe, 0xfe, 0x8c,
        0x29, 0x2b, 0x50, 0xde, 0xe2, 0x97, 0xf3, 0xed, 0x11, 0x18, 0x74, 0x37,
        0x8f, 0x9d, 0xe4, 0x02, 0xf2, 0xf1, 0x15, 0x2b, 0x80, 0xa9, 0x84, 0x3e,
        0x81, 0xff, 0x48, 0x02, 0xec, 0x86, 0xd2, 0x0a, 0x4c, 0x00, 0x14, 0x6f,
        0x8f, 0x4f, 0xfc, 0x1d, 0x8d, 0xd3, 0xee, 0xd3
    };

    Uint8 Q_1024[] = { 0xf3, 0x75, 0x72, 0x9d, 0xec, 0x88, 0x12, 0x23,
                       0x65, 0xd1, 0x96, 0x98, 0xfe, 0xe6, 0xb3, 0xb2,
                       0xc9, 0x42, 0xcd, 0x65, 0x5c, 0xbb, 0xcf, 0x9f,
                       0x81, 0xc5, 0xf2, 0xa9, 0x55, 0xea, 0x02, 0x59,
                       0x9b, 0x88, 0x76, 0xc7, 0x56, 0x99, 0xbc, 0x80,
                       0x84, 0x0c, 0xac, 0xba, 0xb4, 0xef, 0x45, 0x13,
                       0x52, 0xfb, 0xf8, 0x49, 0xf3, 0x5e, 0xf7, 0xdf,
                       0xc1, 0x72, 0xd6, 0xa6, 0xd9, 0xac, 0x4b, 0x7b };
    Uint8 Q_2048[] = {
        0xd1, 0x0f, 0xce, 0xd2, 0x88, 0x3d, 0x51, 0xb5, 0xe1, 0xf3, 0x2d, 0xf2,
        0x23, 0xde, 0x33, 0xb5, 0xcc, 0xd6, 0x74, 0x84, 0x04, 0x47, 0x21, 0x21,
        0x42, 0x21, 0x8d, 0x45, 0x49, 0xc7, 0x0a, 0xa3, 0xb6, 0x41, 0xb6, 0x50,
        0xf4, 0xd9, 0xb5, 0xf7, 0x42, 0x71, 0xff, 0xcc, 0x9e, 0xc3, 0x4d, 0xf1,
        0xa4, 0xf5, 0x5b, 0x7f, 0x25, 0x96, 0x7c, 0xaa, 0x8e, 0xf0, 0xa8, 0xe0,
        0xe6, 0x7a, 0x74, 0xc3, 0x7e, 0xe9, 0xa2, 0xb2, 0x34, 0x52, 0x67, 0xcb,
        0x67, 0x94, 0x0c, 0x0b, 0xe1, 0x85, 0x32, 0xad, 0x23, 0x39, 0x45, 0xe2,
        0x76, 0xcb, 0xe4, 0xca, 0x85, 0x8e, 0x7b, 0x80, 0xfc, 0x2c, 0x82, 0x34,
        0x2f, 0xdf, 0x24, 0xb2, 0x38, 0xa1, 0x1c, 0x19, 0x46, 0x36, 0xb7, 0xc5,
        0x8c, 0x48, 0x0e, 0x51, 0x06, 0xa8, 0xad, 0xe0, 0x7e, 0xf0, 0x5d, 0x3b,
        0x9b, 0xf8, 0xa8, 0x7d, 0x10, 0x91, 0x3a, 0x5b
    };

    Uint8 DP_1024[] = { 0x96, 0x96, 0x25, 0x20, 0x62, 0xe6, 0x09, 0xe9,
                        0x0b, 0xf2, 0xc2, 0x00, 0xda, 0x5a, 0x17, 0x9a,
                        0x21, 0x7b, 0xec, 0x7d, 0xf8, 0xf9, 0xf0, 0x80,
                        0x0f, 0xb8, 0x80, 0x3c, 0x68, 0x0e, 0xb7, 0x2f,
                        0xfb, 0xab, 0x26, 0x94, 0x10, 0x54, 0x51, 0x5d,
                        0x7c, 0x0f, 0x90, 0x6e, 0x1f, 0xb7, 0x4a, 0x56,
                        0xc0, 0x05, 0x7e, 0x96, 0xdc, 0xf8, 0x19, 0xf1,
                        0x49, 0x54, 0x5a, 0x80, 0x21, 0x46, 0x64, 0x65 };
    Uint8 DP_2048[] = {
        0x0f, 0x51, 0x41, 0x91, 0x7c, 0xe6, 0xb8, 0x8e, 0xa4, 0xe8, 0xe8, 0xae,
        0x17, 0x2f, 0x5f, 0xc2, 0x4a, 0xf4, 0x95, 0xc5, 0x51, 0xbc, 0x9a, 0x97,
        0x0a, 0xc8, 0xa9, 0x7e, 0xf6, 0x2e, 0x80, 0xa4, 0xd2, 0xbb, 0x0f, 0x12,
        0xd3, 0x46, 0x45, 0x8f, 0xce, 0xa0, 0xb8, 0x2f, 0xf3, 0x64, 0x3e, 0x13,
        0xce, 0xab, 0x82, 0x78, 0x63, 0x51, 0x82, 0x41, 0x3e, 0xfd, 0x36, 0xc3,
        0x6c, 0x0a, 0xd7, 0x69, 0xba, 0xef, 0xee, 0x89, 0xb8, 0x2a, 0xd8, 0x3b,
        0x85, 0x0a, 0x2d, 0xcb, 0x63, 0x02, 0x00, 0x07, 0xea, 0x08, 0xda, 0x78,
        0x6f, 0x2c, 0xb1, 0x6e, 0x91, 0x90, 0xa0, 0xf1, 0x52, 0xdd, 0x12, 0xdc,
        0x3a, 0xf0, 0xf8, 0xc4, 0x4d, 0x77, 0x8c, 0x31, 0xc7, 0xd8, 0x65, 0xab,
        0xa7, 0xe3, 0x12, 0xe5, 0x42, 0xe0, 0x9c, 0x8e, 0x28, 0xcf, 0x88, 0xa8,
        0x4a, 0xff, 0x4f, 0xf9, 0x3f, 0x8b, 0x0e, 0x09
    };

    Uint8 DQ_1024[] = { 0x54, 0x8e, 0x94, 0x32, 0x79, 0x76, 0x81, 0x26,
                        0x3e, 0x34, 0xdf, 0x23, 0x60, 0x54, 0xec, 0x50,
                        0xca, 0x4a, 0x23, 0x60, 0x73, 0x26, 0xdf, 0xe3,
                        0xbc, 0x84, 0xed, 0xd5, 0x16, 0x7b, 0xe2, 0x39,
                        0x11, 0x26, 0x02, 0x6b, 0x15, 0x8e, 0xeb, 0xc3,
                        0x8f, 0x19, 0x7f, 0xdc, 0x90, 0xff, 0x11, 0x74,
                        0xb6, 0xbb, 0xc0, 0xee, 0x9e, 0x52, 0x7b, 0xb1,
                        0x01, 0x55, 0x4b, 0x6c, 0x43, 0xe9, 0xed, 0x85 };
    Uint8 DQ_2048[] = {
        0x7b, 0x22, 0xed, 0x75, 0xd1, 0xab, 0x14, 0x5a, 0xa5, 0xd8, 0x3f, 0x02,
        0xb5, 0x1f, 0xa6, 0xa3, 0x79, 0x20, 0x03, 0x86, 0xd2, 0xa2, 0x36, 0xa0,
        0x49, 0x3c, 0x4b, 0xe2, 0x38, 0xbf, 0x54, 0xc3, 0xf2, 0x90, 0xa7, 0xda,
        0xed, 0x2c, 0xe2, 0x61, 0xdd, 0xb0, 0x19, 0xb3, 0xa2, 0xfb, 0x74, 0x08,
        0x55, 0x59, 0xf2, 0xe7, 0x63, 0xf3, 0x4c, 0x40, 0x85, 0x6a, 0xb8, 0x7d,
        0xa7, 0x23, 0x0f, 0x6d, 0x2a, 0x6e, 0x60, 0x56, 0xc8, 0x3c, 0x95, 0x48,
        0x18, 0x1c, 0xfa, 0x2f, 0x71, 0x48, 0xab, 0xfd, 0x90, 0x96, 0xa6, 0x53,
        0xea, 0x16, 0xd4, 0x0e, 0x79, 0x35, 0xe0, 0x06, 0xac, 0x01, 0x67, 0x3b,
        0x67, 0xca, 0xed, 0xe9, 0x4f, 0x33, 0x8d, 0xc2, 0x51, 0x39, 0xdf, 0x6a,
        0x2a, 0xe3, 0x32, 0x13, 0x85, 0x71, 0x8a, 0xe0, 0x84, 0xc3, 0xfc, 0x96,
        0x24, 0x9b, 0x04, 0x5a, 0x8d, 0x8c, 0x8c, 0xab
    };

    Uint8 QINV_1024[] = { 0x65, 0x95, 0xd7, 0x7a, 0xee, 0x82, 0xf7, 0x82,
                          0x72, 0x34, 0xcb, 0x91, 0xbf, 0x25, 0x65, 0x47,
                          0x03, 0x1e, 0x5b, 0xe9, 0x28, 0xc6, 0x9e, 0xf4,
                          0xe7, 0x1b, 0x24, 0x95, 0x04, 0x72, 0x30, 0x07,
                          0x9a, 0xa7, 0x09, 0x98, 0xb1, 0x1b, 0x57, 0xc3,
                          0xa8, 0xd1, 0x18, 0x75, 0xca, 0x5f, 0x02, 0x8d,
                          0xd7, 0x99, 0x63, 0xdf, 0x34, 0x1f, 0x52, 0x64,
                          0x7c, 0x43, 0x17, 0xb7, 0x41, 0x79, 0xc5, 0x42 };
    Uint8 QINV_2048[] = {
        0x54, 0x66, 0x50, 0x55, 0x98, 0x22, 0x72, 0x64, 0xa9, 0xa5, 0xb0, 0x6e,
        0x65, 0x82, 0x4f, 0x3a, 0xe7, 0xa0, 0x3d, 0x56, 0x21, 0x9d, 0xca, 0xb7,
        0x5e, 0xd0, 0x59, 0x0a, 0xd1, 0x06, 0x1a, 0x53, 0x2d, 0x42, 0x92, 0xa0,
        0xcf, 0xe1, 0x91, 0x87, 0x2b, 0xd3, 0x02, 0xbf, 0xc7, 0x0b, 0xbc, 0x67,
        0x4b, 0x91, 0xa3, 0x7f, 0x28, 0xe3, 0xe9, 0xe1, 0x87, 0xb0, 0x10, 0x23,
        0x4e, 0xc1, 0x38, 0xb7, 0x7f, 0x2a, 0x0f, 0x89, 0xf1, 0x41, 0x7c, 0xc1,
        0x98, 0x04, 0x10, 0xd7, 0xfe, 0xff, 0x8a, 0xad, 0xd6, 0x36, 0xee, 0xb7,
        0x39, 0x5d, 0xaa, 0xe0, 0x64, 0x61, 0xc0, 0x28, 0x4e, 0x3b, 0x4a, 0x5c,
        0x24, 0xf3, 0x99, 0x7d, 0x6b, 0x6f, 0x2a, 0x2c, 0xbb, 0x85, 0xb3, 0x74,
        0xf5, 0xed, 0x27, 0xb7, 0x96, 0xe5, 0x5f, 0x5c, 0xaa, 0x7b, 0xa2, 0xdd,
        0x3b, 0xb9, 0x80, 0x09, 0x69, 0x62, 0xfd, 0x2b
    };
    int keyCtxSize;

    // (bit) size of key components
    int bitsP, bitsQ;
    if (m_key_len * 8 == KEY_SIZE_2048) {
        bitsP = bitsQ = 2048;
    } else if (m_key_len * 8 == KEY_SIZE_1024) {
        bitsP = bitsQ = 1024;
    } else {
        std::cout << "Invalid keysize in RSA SetPublicKey" << std::endl;
        return false;
    }

    // define and setup(type2) private key
    status = ippsRSA_GetSizePrivateKeyType2(bitsP, bitsQ, &keyCtxSize);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_GetSizePrivateKeyType2 failed with err code"
                  << status << std::endl;
        return false;
    }
    if (m_pPrv) {
        delete[](Ipp8u*) m_pPrv;
    }
    m_pPrv = (IppsRSAPrivateKeyState*)(new Ipp8u[keyCtxSize]);

    status = ippsRSA_InitPrivateKeyType2(bitsP, bitsQ, m_pPrv, keyCtxSize);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_InitPrivateKeyType2 failed with err code"
                  << status << std::endl;
        return false;
    }

    /* create bignums from the byte stream data */
    IppsBigNumState *m_pBN_P = nullptr, *m_pBN_Q = nullptr, *m_pBN_DP = nullptr,
                    *m_pBN_DQ = nullptr, *m_pBN_invQ = nullptr;

    if (m_key_len * 8 == KEY_SIZE_2048) {
        m_pBN_P    = createSetBigNUM(P_2048, sizeof(P_2048));
        m_pBN_Q    = createSetBigNUM(Q_2048, sizeof(Q_2048));
        m_pBN_DP   = createSetBigNUM(DP_2048, sizeof(DP_2048));
        m_pBN_DQ   = createSetBigNUM(DQ_2048, sizeof(DQ_2048));
        m_pBN_invQ = createSetBigNUM(QINV_2048, sizeof(QINV_2048));
    } else if (m_key_len * 8 == KEY_SIZE_1024) {
        m_pBN_P    = createSetBigNUM(P_1024, sizeof(P_1024));
        m_pBN_Q    = createSetBigNUM(Q_1024, sizeof(Q_1024));
        m_pBN_DP   = createSetBigNUM(DP_1024, sizeof(DP_1024));
        m_pBN_DQ   = createSetBigNUM(DQ_1024, sizeof(DQ_1024));
        m_pBN_invQ = createSetBigNUM(QINV_1024, sizeof(QINV_1024));
    } else {
        std::cout << "Invalid keysize in RSA SetPublicKey" << std::endl;
        return false;
    }

    status = ippsRSA_SetPrivateKeyType2(
        m_pBN_P, m_pBN_Q, m_pBN_DP, m_pBN_DQ, m_pBN_invQ, m_pPrv);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_SetPrivateKeyType2 failed with err code" << status
                  << std::endl;
        return false;
    }
    /* clean up these after setting pub key */
    if (m_pBN_P) {
        delete[](Ipp8u*) m_pBN_P;
    }
    if (m_pBN_Q) {
        delete[](Ipp8u*) m_pBN_Q;
    }
    if (m_pBN_DP) {
        delete[](Ipp8u*) m_pBN_DP;
    }
    if (m_pBN_DQ) {
        delete[](Ipp8u*) m_pBN_DQ;
    }
    if (m_pBN_invQ) {
        delete[](Ipp8u*) m_pBN_invQ;
    }
    status = ippsRSA_GetBufferSizePrivateKey(&m_buffSizePrivate, m_pPrv);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_GetBufferSizePrivateKey failed with err code"
                  << status << std::endl;
        return false;
    }
    m_buffSize = m_buffSizePrivate;

    if (m_scratchBuffer_Pvt) {
        delete[](Ipp8u*) m_scratchBuffer_Pvt;
    }
    m_scratchBuffer_Pvt = new Ipp8u[m_buffSize];

    return true;
}

bool
IPPRsaBase::SetPublicKey(const alcp_rsa_data_t& data)
{
    IppStatus status         = ippStsNoErr;
    Uint8     Modulus_1024[] = {
        0xf1, 0x88, 0x9d, 0x27, 0x1c, 0x90, 0x54, 0x2b, 0x5e, 0x52, 0x63, 0x63,
        0x4d, 0x83, 0x23, 0x6d, 0x9b, 0x48, 0x6b, 0x6b, 0x9d, 0x87, 0x6d, 0xda,
        0x16, 0xb0, 0x19, 0xcd, 0xf1, 0xdd, 0x10, 0xb4, 0xc5, 0x35, 0xbc, 0xaa,
        0x00, 0x8c, 0x40, 0x41, 0xe1, 0xa0, 0x57, 0x91, 0x49, 0x0f, 0xd9, 0x3c,
        0x89, 0xb4, 0xbc, 0xb2, 0x47, 0xe7, 0x7d, 0x24, 0xb2, 0x2f, 0x9a, 0xb9,
        0x6a, 0xa5, 0x20, 0xe6, 0xd4, 0xde, 0xd3, 0x0e, 0x28, 0xdc, 0xaf, 0x3f,
        0x88, 0x11, 0x4f, 0xa5, 0x02, 0x46, 0x91, 0xe7, 0xf1, 0x93, 0xb2, 0x47,
        0x11, 0x5b, 0x7b, 0xbb, 0xda, 0xe9, 0x47, 0x7f, 0xeb, 0xa5, 0xd7, 0x17,
        0x96, 0x53, 0x09, 0xa6, 0x6a, 0xbe, 0x8e, 0xe4, 0x45, 0xdf, 0xe7, 0x12,
        0x80, 0x78, 0x86, 0x65, 0x47, 0xf9, 0x4a, 0xe5, 0x90, 0xd6, 0xdc, 0x0c,
        0x0d, 0x5a, 0x5a, 0xce, 0x12, 0xca, 0x1b, 0x09
    };
    Uint8 Modulus_2048[] = {
        0xae, 0x20, 0xe8, 0x1f, 0x78, 0x01, 0x6c, 0x9a, 0x3e, 0x4a, 0x88, 0xde,
        0x2f, 0x98, 0xfe, 0xe3, 0x24, 0x2e, 0x99, 0x78, 0x27, 0x8e, 0x1a, 0xed,
        0xe7, 0xe1, 0x42, 0x84, 0x1c, 0x4e, 0x7e, 0xf4, 0xdc, 0xc9, 0xcc, 0xf3,
        0xa7, 0x9a, 0xa5, 0x50, 0xda, 0x8b, 0xcd, 0x04, 0x1c, 0x43, 0xf6, 0xbe,
        0x5d, 0x1e, 0x6a, 0x52, 0x16, 0x80, 0xe2, 0x5f, 0x7b, 0x0e, 0x03, 0x6c,
        0x78, 0x53, 0x72, 0xa1, 0x81, 0xc8, 0xc6, 0xb0, 0x79, 0xb7, 0xe0, 0x50,
        0xc3, 0x6e, 0xd0, 0xf9, 0x4b, 0x94, 0x61, 0x86, 0x88, 0xc0, 0x9a, 0x99,
        0xea, 0xbd, 0x8f, 0x54, 0x29, 0xd0, 0x17, 0xd5, 0x8f, 0xaa, 0xa5, 0x9d,
        0xcc, 0x13, 0x7a, 0xfb, 0x5d, 0xc8, 0x96, 0xb7, 0x87, 0xd9, 0x75, 0xf8,
        0xab, 0x2e, 0x3b, 0x92, 0xe2, 0xc8, 0xde, 0x57, 0x0f, 0x94, 0xfe, 0x6a,
        0x85, 0x86, 0x83, 0xa2, 0x0a, 0x59, 0x0a, 0x5e, 0xe5, 0x37, 0xb3, 0x9e,
        0x42, 0x3d, 0x85, 0x00, 0xf6, 0x75, 0x9e, 0x45, 0x7e, 0x3c, 0xbe, 0x11,
        0x61, 0xf5, 0x99, 0x6c, 0x1c, 0xa6, 0x53, 0x3d, 0x02, 0xd7, 0x4e, 0x72,
        0xb5, 0x3e, 0xcf, 0x5a, 0x02, 0xc0, 0x65, 0x5b, 0xda, 0x83, 0xc9, 0x07,
        0x88, 0xd5, 0xd1, 0x62, 0xfe, 0x0a, 0xb1, 0xcf, 0x52, 0x27, 0x70, 0x04,
        0x66, 0xb8, 0x99, 0xd6, 0xdc, 0xe9, 0x27, 0xaf, 0xd9, 0x90, 0x8d, 0xef,
        0x7c, 0x96, 0x6a, 0x09, 0xe7, 0x25, 0x10, 0xb4, 0x3c, 0xcc, 0x6c, 0x5b,
        0xf0, 0x26, 0xdf, 0x49, 0xde, 0x26, 0x1e, 0x81, 0xc2, 0x55, 0x8e, 0xed,
        0xd6, 0x1f, 0x81, 0x34, 0xce, 0x33, 0x53, 0x14, 0xa3, 0x37, 0xc7, 0x7b,
        0x6d, 0xcb, 0x58, 0x27, 0x09, 0xdf, 0x06, 0xdc, 0xed, 0x44, 0x53, 0x76,
        0xb9, 0x3a, 0x2d, 0x0c, 0x9b, 0x3a, 0x9e, 0x3b, 0x28, 0xc5, 0xf9, 0xa1,
        0xe3, 0xf4, 0xb3, 0x01
    };

    Ipp32u PublicKeyExponent = 0x10001; // public exponent

    int keyCtxSize;

    // (bit) size of key components
    int bitsN, bitsE;
    if (m_key_len * 8 == KEY_SIZE_2048) {
        bitsN = 2048;
        bitsE = 17;
    } else if (m_key_len * 8 == KEY_SIZE_1024) {
        bitsN = 1024;
        bitsE = 17;
    } else {
        std::cout << "Invalid keysize in RSA SetPublicKey" << std::endl;
        return false;
    }
    m_modulus_size = bitsN;
    int size       = 0;

    // define and setup public key
    status = ippsRSA_GetSizePublicKey(bitsN, bitsE, &keyCtxSize);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_GetSizePublicKey failed with err code" << status
                  << std::endl;
        return false;
    }

    if (m_pPub) {
        delete[](Ipp8u*) m_pPub;
    }
    m_pPub = (IppsRSAPublicKeyState*)(new Ipp8u[keyCtxSize]);
    status = ippsRSA_InitPublicKey(bitsN, bitsE, m_pPub, keyCtxSize);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_InitPublicKey failed with err code" << status
                  << std::endl;
        return false;
    }

    /* create bignums */
    IppsBigNumState *m_pBN_N = nullptr, *m_pBN_E = nullptr;

    if (m_key_len * 8 == KEY_SIZE_2048) {
        m_pBN_N = createSetBigNUM(Modulus_2048, sizeof(Modulus_2048));
    } else if (m_key_len * 8 == KEY_SIZE_1024) {
        m_pBN_N = createSetBigNUM(Modulus_1024, sizeof(Modulus_1024));
    } else {
        std::cout << "Invalid keysize in RSA SetPublicKey" << std::endl;
        return false;
    }
    ippsBigNumGetSize(1, &size);
    m_pBN_E = (IppsBigNumState*)(new Ipp8u[size]);
    ippsBigNumInit(1, m_pBN_E);

    ippsSet_BN(IppsBigNumPOS, 1, &PublicKeyExponent, m_pBN_E);
    status = ippsRSA_SetPublicKey(m_pBN_N, m_pBN_E, m_pPub);

    /* clean up these after setting pub key */
    if (m_pBN_E) {
        delete[](Ipp8u*) m_pBN_E;
    }
    if (m_pBN_N) {
        delete[](Ipp8u*) m_pBN_N;
    }
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_SetPublicKey failed with err code" << status
                  << std::endl;
        return false;
    }
    // allocate scratch buffer
    status = ippsRSA_GetBufferSizePublicKey(&m_buffSizePublic, m_pPub);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_GetBufferSizePublicKey failed with err code"
                  << status << std::endl;
        return false;
    }

    if (m_scratchBuffer_Pub) {
        delete[](Ipp8u*) m_scratchBuffer_Pub;
    }
    m_scratchBuffer_Pub = new Ipp8u[m_buffSizePublic];

    return true;
}

bool
IPPRsaBase::ValidateKeys()
{
    return true;
}

int
IPPRsaBase::EncryptPubKey(const alcp_rsa_data_t& data)
{
    IppStatus status = ippStsNoErr;

    if (m_padding_mode == 1) {
        /* get hash type based on digest len */
        const IppsHashMethod* p_hash_method = getIppHashMethod(m_digest_info);

        /* Encrypt message */
        status = ippsRSAEncrypt_OAEP_rmf(data.m_msg,
                                         data.m_msg_len,
                                         0,
                                         0,
                                         data.m_pseed,
                                         data.m_encrypted_data,
                                         m_pPub,
                                         p_hash_method,
                                         m_scratchBuffer_Pub);

        if (status != ippStsNoErr) {
            std::cout << "ippsRSAEncrypt_OAEP_rmf failed with err code"
                      << status << std::endl;
            return status;
        }
    } else {
        /* for non padded mode */
        IppsBigNumState* m_pBN_kat_PT =
            createSetBigNUM((Uint8*)data.m_msg, data.m_msg_len);

        IppsBigNumState* m_pBN_kat_CT = createSetBigNUM(NULL, data.m_msg_len);

        status = ippsRSA_Encrypt(
            m_pBN_kat_PT, m_pBN_kat_CT, m_pPub, m_scratchBuffer_Pub);
        if (status != ippStsNoErr) {
            // std::cout << "ippsRSA_Encrypt failed with err code" << status
            //           << std::endl;
            if (m_pBN_kat_PT) {
                delete[](Ipp8u*) m_pBN_kat_PT;
            }
            if (m_pBN_kat_CT) {
                delete[](Ipp8u*) m_pBN_kat_CT;
            }
            return status;
        }
        /* read data from the bignum */
        IppsBigNumSGN sgn;
        int           length = 0;
        Ipp32u*       pdata  = NULL;
        status               = ippsRef_BN(&sgn, &length, &pdata, m_pBN_kat_CT);
        if (status != ippStsNoErr) {
            std::cout << "ippsRef_BN failed with err code" << status
                      << std::endl;
            return status;
        }
        std::reverse_copy((Uint8*)pdata,
                          (Uint8*)pdata + m_key_len * 8 / (sizeof(Uint8) * 8),
                          data.m_encrypted_data);
        /* clean up these after encrypt */
        if (m_pBN_kat_PT) {
            delete[](Ipp8u*) m_pBN_kat_PT;
        }
        if (m_pBN_kat_CT) {
            delete[](Ipp8u*) m_pBN_kat_CT;
        }
    }
    return 0;
}

int
IPPRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    IppStatus status = ippStsNoErr;

    if (m_padding_mode == 1) {
        int    plainTextLen = data.m_msg_len;
        Ipp8u* pPlainText   = new Ipp8u[data.m_key_len]();
        /* get hash type based on digest len */
        const IppsHashMethod* p_hash_method = getIppHashMethod(m_digest_info);
        /* Decrypt message */
        status = ippsRSADecrypt_OAEP_rmf(data.m_encrypted_data,
                                         0,
                                         0,
                                         pPlainText,
                                         &plainTextLen,
                                         m_pPrv,
                                         p_hash_method,
                                         m_scratchBuffer_Pvt);

        if (status != ippStsNoErr) {
            std::cout << "ippsRSADecrypt_OAEP_rmf failed with err code"
                      << status << std::endl;
            if (pPlainText) {
                delete[](Ipp8u*) pPlainText;
            }
            return status;
        }

        std::memcpy(data.m_decrypted_data, pPlainText, plainTextLen);

        if (pPlainText) {
            delete[](Ipp8u*) pPlainText;
        }
    } else {
        /* for non padded mode */
        IppsBigNumState* m_pBN_kat_CT =
            createSetBigNUM((Uint8*)data.m_encrypted_data, data.m_msg_len);
        IppsBigNumState* m_pBN_kat_PT = createSetBigNUM(NULL, data.m_msg_len);
        status                        = ippsRSA_Decrypt(
            m_pBN_kat_CT, m_pBN_kat_PT, m_pPrv, m_scratchBuffer_Pvt);
        if (status != ippStsNoErr) {
            std::cout << "ippsRSA_Decrypt failed with err code" << status
                      << std::endl;
            if (m_pBN_kat_PT) {
                delete[](Ipp8u*) m_pBN_kat_PT;
            }
            if (m_pBN_kat_CT) {
                delete[](Ipp8u*) m_pBN_kat_CT;
            }
            return status;
        }
        /* read data from the bignum */
        IppsBigNumSGN sgn;
        int           length = 0;
        Ipp32u*       pdata  = NULL;
        status               = ippsRef_BN(&sgn, &length, &pdata, m_pBN_kat_PT);
        if (status != ippStsNoErr) {
            std::cout << "ippsRef_BN failed with err code" << status
                      << std::endl;
            if (m_pBN_kat_PT) {
                delete[](Ipp8u*) m_pBN_kat_PT;
            }
            if (m_pBN_kat_CT) {
                delete[](Ipp8u*) m_pBN_kat_CT;
            }
            return status;
        }
        std::reverse_copy((Uint8*)pdata,
                          (Uint8*)pdata + m_key_len * 8 / (sizeof(Uint8) * 8),
                          data.m_decrypted_data);
        /* clean up these after decrypt */
        if (m_pBN_kat_PT) {
            delete[](Ipp8u*) m_pBN_kat_PT;
        }
        if (m_pBN_kat_CT) {
            delete[](Ipp8u*) m_pBN_kat_CT;
        }
    }
    return 0;
}

/* sign verify */
int
IPPRsaBase::Sign(const alcp_rsa_data_t& data)
{
    IppStatus             status        = ippStsNoErr;
    const IppsHashMethod* p_hash_method = getIppHashMethod(m_digest_info);
    if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        status = ippsRSASign_PSS_rmf(data.m_msg,
                                     data.m_msg_len,
                                     data.m_salt,
                                     data.m_salt_len,
                                     data.m_signature,
                                     m_pPrv,
                                     m_pPub,
                                     p_hash_method,
                                     m_scratchBuffer_Pvt);
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        status = ippsRSASign_PKCS1v15_rmf(data.m_msg,
                                          data.m_msg_len,
                                          data.m_signature,
                                          m_pPrv,
                                          m_pPub,
                                          p_hash_method,
                                          m_scratchBuffer_Pvt);
    } else {
        std::cout << "Unsupported padding mode!" << std::endl;
        return 1;
    }
    if (status != ippStsNoErr) {
        std::cout << "IPP RSA Sign failed with err code" << status << std::endl;
        return status;
    }
    return 0;
}
int
IPPRsaBase::Verify(const alcp_rsa_data_t& data)
{
    IppStatus             status        = ippStsNoErr;
    const IppsHashMethod* p_hash_method = getIppHashMethod(m_digest_info);
    int                   isValid       = 0;

    if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        status = ippsRSAVerify_PSS_rmf(data.m_msg,
                                       data.m_msg_len,
                                       data.m_signature,
                                       &isValid,
                                       m_pPub,
                                       p_hash_method,
                                       m_scratchBuffer_Pub);
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        status = ippsRSAVerify_PKCS1v15_rmf(data.m_msg,
                                            data.m_msg_len,
                                            data.m_signature,
                                            &isValid,
                                            m_pPub,
                                            p_hash_method,
                                            m_scratchBuffer_Pub);
    } else {
        std::cout << "Unsupported padding mode!" << std::endl;
        return 1;
    }
    if (status != ippStsNoErr) {
        std::cout << "IPP RSA Verify failed with err code" << status
                  << std::endl;
        return status;
    }
    return 0;
}

bool
IPPRsaBase::reset()
{
    return true;
}

} // namespace alcp::testing
