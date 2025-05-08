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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include "rsa/ipp_rsa.hh"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <ostream>
namespace alcp::testing {

/* Function to create bignum from a byte stream */
IppsBigNumState*
createSetBigNUM(const Uint8* buff, int size_buff) // size in bytes
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
    delete[] (Ipp32u*)N;

    return m_pBN_N;
}

IPPRsaBase::IPPRsaBase() {}

IPPRsaBase::~IPPRsaBase()
{
    if (m_pPub) {
        delete[] (Ipp8u*)m_pPub;
    }
    if (m_pPrv) {
        delete[] (Ipp8u*)m_pPrv;
    }
    if (m_scratchBuffer_Pub) {
        delete[] (Ipp8u*)m_scratchBuffer_Pub;
    }
    if (m_scratchBuffer_Pvt) {
        delete[] (Ipp8u*)m_scratchBuffer_Pvt;
    }
}

bool
IPPRsaBase::init()
{
    /* digest params to be added only for PADDED mode*/
    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        return true;
    }
    switch (m_digest_info.dt_len) {
        case ALC_DIGEST_LEN_256:
            m_md_type = ippsHashMethod_SHA256_TT();
            break;
        case ALC_DIGEST_LEN_512:
            m_md_type = ippsHashMethod_SHA512();
            break;
        default:
            m_md_type = nullptr;
            break;
    }
    if (m_md_type == nullptr) {
        std::cout << "Error, IPP Hash type returned is null!" << std::endl;
        return false;
    }
    return true;
}

bool
IPPRsaBase::SetPublicKey(const alcp_rsa_data_t& data)
{
    return true;
    UNREF(data);
}

bool
IPPRsaBase::SetPrivateKey(const alcp_rsa_data_t& data)
{
    return true;
    UNREF(data);
}

bool
IPPRsaBase::SetPrivateKeyBigNum(const alcp_rsa_data_t& data)
{
    IppStatus status = ippStsNoErr;

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
        delete[] (Ipp8u*)m_pPrv;
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
        m_pBN_P = createSetBigNUM(PvtKey_P_Modulus_2048,
                                  sizeof(PvtKey_P_Modulus_2048));
        m_pBN_Q = createSetBigNUM(PvtKey_Q_Modulus_2048,
                                  sizeof(PvtKey_Q_Modulus_2048));
        m_pBN_DP =
            createSetBigNUM(PvtKey_DP_EXP_2048, sizeof(PvtKey_DP_EXP_2048));
        m_pBN_DQ =
            createSetBigNUM(PvtKey_DQ_EXP_2048, sizeof(PvtKey_DQ_EXP_2048));
        m_pBN_invQ = createSetBigNUM(PvtKey_Q_ModulusINV_2048,
                                     sizeof(PvtKey_Q_ModulusINV_2048));
    } else if (m_key_len * 8 == KEY_SIZE_1024) {
        m_pBN_P = createSetBigNUM(PvtKey_P_Modulus_1024,
                                  sizeof(PvtKey_P_Modulus_1024));
        m_pBN_Q = createSetBigNUM(PvtKey_Q_Modulus_1024,
                                  sizeof(PvtKey_Q_Modulus_1024));
        m_pBN_DP =
            createSetBigNUM(PvtKey_DP_EXP_1024, sizeof(PvtKey_DP_EXP_1024));
        m_pBN_DQ =
            createSetBigNUM(PvtKey_DQ_EXP_1024, sizeof(PvtKey_DQ_EXP_1024));
        m_pBN_invQ = createSetBigNUM(PvtKey_Q_ModulusINV_1024,
                                     sizeof(PvtKey_Q_ModulusINV_1024));
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
        delete[] (Ipp8u*)m_pBN_P;
    }
    if (m_pBN_Q) {
        delete[] (Ipp8u*)m_pBN_Q;
    }
    if (m_pBN_DP) {
        delete[] (Ipp8u*)m_pBN_DP;
    }
    if (m_pBN_DQ) {
        delete[] (Ipp8u*)m_pBN_DQ;
    }
    if (m_pBN_invQ) {
        delete[] (Ipp8u*)m_pBN_invQ;
    }
    status = ippsRSA_GetBufferSizePrivateKey(&m_buffSizePrivate, m_pPrv);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_GetBufferSizePrivateKey failed with err code"
                  << status << std::endl;
        return false;
    }
    m_buffSize = m_buffSizePrivate;

    if (m_scratchBuffer_Pvt) {
        delete[] (Ipp8u*)m_scratchBuffer_Pvt;
    }
    m_scratchBuffer_Pvt = new Ipp8u[m_buffSize];

    return true;
    UNREF(data);
}

bool
IPPRsaBase::SetPublicKeyBigNum(const alcp_rsa_data_t& data)
{
    IppStatus status = ippStsNoErr;

    Ipp32u PublicKeyExponent = pub_key_exp; // public exponent

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
        delete[] (Ipp8u*)m_pPub;
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
        m_pBN_N =
            createSetBigNUM(PubKey_Modulus_2048, sizeof(PubKey_Modulus_2048));
    } else if (m_key_len * 8 == KEY_SIZE_1024) {
        m_pBN_N =
            createSetBigNUM(PubKey_Modulus_1024, sizeof(PubKey_Modulus_1024));
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
        delete[] (Ipp8u*)m_pBN_E;
    }
    if (m_pBN_N) {
        delete[] (Ipp8u*)m_pBN_N;
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
        delete[] (Ipp8u*)m_scratchBuffer_Pub;
    }
    m_scratchBuffer_Pub = new Ipp8u[m_buffSizePublic];

    return true;
    UNREF(data);
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

    if (m_padding_mode == ALCP_TEST_RSA_PADDING_OAEP) {
        /* Encrypt message */
        status = ippsRSAEncrypt_OAEP_rmf(data.m_msg,
                                         data.m_msg_len,
                                         0,
                                         0,
                                         data.m_pseed,
                                         data.m_encrypted_data,
                                         m_pPub,
                                         m_md_type,
                                         m_scratchBuffer_Pub);

        if (status != ippStsNoErr) {
            std::cout << "ippsRSAEncrypt_OAEP_rmf failed with err code"
                      << status << std::endl;
            return status;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        status = ippsRSAEncrypt_PKCSv15(data.m_msg,
                                        data.m_msg_len,
                                        NULL,
                                        data.m_encrypted_data,
                                        m_pPub,
                                        m_scratchBuffer_Pub);
        if (status != ippStsNoErr) {
            std::cout << "ippsRSAEncrypt_PKCSv15 failed with err code" << status
                      << std::endl;
            return status;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        /* for non padded mode */
        IppsBigNumState* m_pBN_kat_PT =
            createSetBigNUM((Uint8*)data.m_msg, data.m_msg_len);

        IppsBigNumState* m_pBN_kat_CT = createSetBigNUM(NULL, data.m_msg_len);

        status = ippsRSA_Encrypt(
            m_pBN_kat_PT, m_pBN_kat_CT, m_pPub, m_scratchBuffer_Pub);
        if (status != ippStsNoErr) {
            if (m_pBN_kat_PT) {
                delete[] (Ipp8u*)m_pBN_kat_PT;
            }
            if (m_pBN_kat_CT) {
                delete[] (Ipp8u*)m_pBN_kat_CT;
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
            delete[] (Ipp8u*)m_pBN_kat_PT;
        }
        if (m_pBN_kat_CT) {
            delete[] (Ipp8u*)m_pBN_kat_CT;
        }
    } else {
        std::cout << __func__ << ":Error Invalid padding mode!" << std::endl;
        return -1;
    }
    return 0;
}

int
IPPRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    IppStatus status = ippStsNoErr;
    int       plainTextLen;
    Ipp8u*    pPlainText = nullptr;

    if (m_padding_mode == ALCP_TEST_RSA_PADDING_OAEP) {
        plainTextLen = data.m_msg_len;
        pPlainText   = new Ipp8u[data.m_key_len]();
        /* Decrypt message */
        status = ippsRSADecrypt_OAEP_rmf(data.m_encrypted_data,
                                         0,
                                         0,
                                         pPlainText,
                                         &plainTextLen,
                                         m_pPrv,
                                         m_md_type,
                                         m_scratchBuffer_Pvt);
        if (status != ippStsNoErr) {
            std::cout << "ippsRSADecrypt_OAEP_rmf failed with err code"
                      << status << std::endl;
            if (pPlainText) {
                delete[] (Ipp8u*)pPlainText;
            }
            return status;
        }
        std::memcpy(data.m_decrypted_data, pPlainText, plainTextLen);
        if (pPlainText) {
            delete[] (Ipp8u*)pPlainText;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        plainTextLen = data.m_msg_len;
        pPlainText   = new Ipp8u[data.m_key_len]();
        status       = ippsRSADecrypt_PKCSv15(data.m_encrypted_data,
                                        pPlainText,
                                        &plainTextLen,
                                        m_pPrv,
                                        m_scratchBuffer_Pvt);
        if (status != ippStsNoErr) {
            std::cout << "ippsRSAEncrypt_PKCSv15 failed with err code" << status
                      << std::endl;
            if (pPlainText) {
                delete[] (Ipp8u*)pPlainText;
            }
            return status;
        }
        std::memcpy(data.m_decrypted_data, pPlainText, plainTextLen);
        if (pPlainText) {
            delete[] (Ipp8u*)pPlainText;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
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
                delete[] (Ipp8u*)m_pBN_kat_PT;
            }
            if (m_pBN_kat_CT) {
                delete[] (Ipp8u*)m_pBN_kat_CT;
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
                delete[] (Ipp8u*)m_pBN_kat_PT;
            }
            if (m_pBN_kat_CT) {
                delete[] (Ipp8u*)m_pBN_kat_CT;
            }
            return status;
        }
        std::reverse_copy((Uint8*)pdata,
                          (Uint8*)pdata + m_key_len * 8 / (sizeof(Uint8) * 8),
                          data.m_decrypted_data);
        /* clean up these after decrypt */
        if (m_pBN_kat_PT) {
            delete[] (Ipp8u*)m_pBN_kat_PT;
        }
        if (m_pBN_kat_CT) {
            delete[] (Ipp8u*)m_pBN_kat_CT;
        }
    } else {
        std::cout << __func__ << ":Error Invalid padding mode!" << std::endl;
        return -1;
    }
    return 0;
}

/* sign verify */
bool
IPPRsaBase::Sign(const alcp_rsa_data_t& data)
{
    return true;
    UNREF(data);
}
bool
IPPRsaBase::Verify(const alcp_rsa_data_t& data)
{
    return true;
    UNREF(data);
}

bool
IPPRsaBase::DigestSign(const alcp_rsa_data_t& data)
{
    IppStatus status = ippStsNoErr;
    if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        status = ippsRSASign_PSS_rmf(data.m_msg,
                                     data.m_msg_len,
                                     data.m_salt,
                                     data.m_salt_len,
                                     data.m_signature,
                                     m_pPrv,
                                     m_pPub,
                                     m_md_type,
                                     m_scratchBuffer_Pvt);
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        status = ippsRSASign_PKCS1v15_rmf(data.m_msg,
                                          data.m_msg_len,
                                          data.m_signature,
                                          m_pPrv,
                                          m_pPub,
                                          m_md_type,
                                          m_scratchBuffer_Pvt);
    } else {
        std::cout << "Unsupported padding mode!" << std::endl;
        return false;
    }
    if (status != ippStsNoErr) {
        std::cout << "IPP RSA Sign failed with err code" << status << std::endl;
        return false;
    }
    return true;
}
bool
IPPRsaBase::DigestVerify(const alcp_rsa_data_t& data)
{
    IppStatus status  = ippStsNoErr;
    int       isValid = 0;

    if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        status = ippsRSAVerify_PSS_rmf(data.m_msg,
                                       data.m_msg_len,
                                       data.m_signature,
                                       &isValid,
                                       m_pPub,
                                       m_md_type,
                                       m_scratchBuffer_Pub);
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        status = ippsRSAVerify_PKCS1v15_rmf(data.m_msg,
                                            data.m_msg_len,
                                            data.m_signature,
                                            &isValid,
                                            m_pPub,
                                            m_md_type,
                                            m_scratchBuffer_Pub);
    } else {
        std::cout << "Unsupported padding mode!" << std::endl;
        return false;
    }
    if (status != ippStsNoErr) {
        std::cout << "IPP RSA Verify failed with err code" << status
                  << std::endl;
        return false;
    }
    return true;
}

bool
IPPRsaBase::reset()
{
    return true;
}

} // namespace alcp::testing

#pragma GCC diagnostic pop
