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

#include "../rsa/base/BigNumber.cc"
#include "rsa/ipp_rsa.hh"
#include <cstddef>
#include <cstring>
#include <iostream>
#include <ostream>

namespace alcp::testing {

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
    IppStatus status = ippStsNoErr;
    //      private exponent
    BigNumber D(
        "0xA5DAFC5341FAF289C4B988DB30C1CDF83F31251E0668B42784813801579641B2"
        "9410B3C7998D6BC465745E5C392669D6870DA2C082A939E37FDCB82EC93EDAC9"
        "7FF3AD5950ACCFBC111C76F1A9529444E56AAF68C56C092CD38DC3BEF5D20A93"
        "9926ED4F74A13EDDFBE1A1CECC4894AF9428C2B7B8883FE4463A4BC85B1CB3C1");
    /* FIXME: should these params come from outside? */
    //  P prime factor
    BigNumber P(
        "0xEECFAE81B1B9B3C908810B10A1B5600199EB9F44AEF4FDA493B81A9E3D84F632"
        "124EF0236E5D1E3B7E28FAE7AA040A2D5B252176459D1F397541BA2A58FB6599");
    // Q prime factor
    BigNumber Q(
        "0xC97FB1F027F453F6341233EAAAD1D9353F6C42D08866B1D05A0F2035028B9D86"
        "9840B41666B42E92EA0DA3B43204B5CFCE3352524D0416A5A441E700AF461503");
    // P's CRT exponent
    BigNumber dP(
        "0x54494CA63EBA0337E4E24023FCD69A5AEB07DDDC0183A4D0AC9B54B051F2B13E"
        "D9490975EAB77414FF59C1F7692E9A2E202B38FC910A474174ADC93C1F67C981");
    // Q's CRT exponent
    BigNumber dQ(
        "0x471E0290FF0AF0750351B7F878864CA961ADBD3A8A7E991C5C0556A94C3146A7"
        "F9803F8F6F8AE342E931FD8AE47A220D1B99A495849807FE39F9245A9836DA3D");
    // CRT coefficient
    BigNumber invQ(
        "0xB06C4FDABB6301198D265BDBAE9423B380F271F73453885093077FCD39E2119F"
        "C98632154F5883B167A967BF402B4E9E2E0F9656E698EA3666EDFB25798039F7");

    int keyCtxSize;
    int bitsP = P.BitSize();
    int bitsQ = Q.BitSize();

    // define and setup(type2) private key
    status = ippsRSA_GetSizePrivateKeyType2(bitsP, bitsQ, &keyCtxSize);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_GetSizePrivateKeyType2 failed with err code"
                  << status << std::endl;
        return false;
    }
    m_pPrv = (IppsRSAPrivateKeyState*)(new Ipp8u[keyCtxSize]);

    status = ippsRSA_InitPrivateKeyType2(bitsP, bitsQ, m_pPrv, keyCtxSize);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_InitPrivateKeyType2 failed with err code"
                  << status << std::endl;
        return false;
    }
    status = ippsRSA_SetPrivateKeyType2(P, Q, dP, dQ, invQ, m_pPrv);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_SetPrivateKeyType2 failed with err code" << status
                  << std::endl;
        return false;
    }
    status = ippsRSA_GetBufferSizePrivateKey(&m_buffSizePrivate, m_pPrv);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_GetBufferSizePrivateKey failed with err code"
                  << status << std::endl;
        return false;
    }
    m_buffSize          = m_buffSizePrivate;
    m_scratchBuffer_Pvt = new Ipp8u[m_buffSize];

    return true;
}

bool
IPPRsaBase::SetPublicKey(const alcp_rsa_data_t& data)
{
    IppStatus status = ippStsNoErr;

    /* FIXME: this should be from outside ?*/
    // rsa modulus N = P*Q
    BigNumber N(
        "0xBBF82F090682CE9C2338AC2B9DA871F7368D07EED41043A440D6B6F07454F51F"
        "B8DFBAAF035C02AB61EA48CEEB6FCD4876ED520D60E1EC4619719D8A5B8B807F"
        "AFB8E0A3DFC737723EE6B4B7D93A2584EE6A649D060953748834B2454598394E"
        "E0AAB12D7B61A51F527A9A41F6C1687FE2537298CA2A8F5946F8E5FD091DBDCB");
    // public exponent
    BigNumber E("0x11");

    int keyCtxSize;

    // (bit) size of key components
    int bitsN = N.BitSize();
    int bitsE = E.BitSize();
    // define and setup public key
    status = ippsRSA_GetSizePublicKey(bitsN, bitsE, &keyCtxSize);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_GetSizePublicKey failed with err code" << status
                  << std::endl;
        return false;
    }
    m_pPub = (IppsRSAPublicKeyState*)(new Ipp8u[keyCtxSize]);
    status = ippsRSA_InitPublicKey(bitsN, bitsE, m_pPub, keyCtxSize);
    if (status != ippStsNoErr) {
        std::cout << "ippsRSA_InitPublicKey failed with err code" << status
                  << std::endl;
        return false;
    }
    status = ippsRSA_SetPublicKey(N, E, m_pPub);
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
    m_scratchBuffer_Pub = new Ipp8u[m_buffSizePublic];
    // save modulus size, will be used in enc/dec
    m_modulus_size = N.DwordSize();

    return true;
}

// int
// IPPRsaBase::EncryptPubKey(const alcp_rsa_data_t& data, int padding_mode)
// {
//     IppStatus status = ippStsNoErr;

//     /* The BigNum way */
//     //#if 0
//     else {
//         std::string temp = alcp::testing::utils::parseBytesToHexStr(
//             data.m_msg, data.m_msg_len);

//         temp = alcp::testing::utils::bytes_to_hex(temp);

//         char tab2[data.m_msg_len];
//         strncpy(tab2, temp.c_str(), sizeof(tab2));
//         tab2[sizeof(tab2) - 1] = 0;

//         // BigNumber PlainText_BN((const char*)data.m_msg);
//         // IppsBigNumSGN sign;

//         BigNumber PlainText_BN(tab2);
//         int       size_pt;
//         PlainText_BN.GetSize(&size_pt);
//         BigNumber CipherText_BN(0, m_modulus_size);
//         status = ippsRSA_Encrypt(
//             PlainText_BN, CipherText_BN, m_pPub, m_scratchBuffer);
//         if (status != ippStsNoErr) {
//             std::cout << "ippsRSA_Encrypt failed with err code" << status
//                       << std::endl;
//             return false;
//         }
//         status =
//             CipherText_BN.GetOctetString(data.m_encrypted_data,
//             data.m_msg_len);
//         if (status != ippStsNoErr) {
//             std::cout << "ippsGetOctString_BN failed with err code" << status
//                       << std::endl;
//             return false;
//         }

//         /* TESTING */
//         BigNumber PlainText_BN_2(0, m_modulus_size);
//         status = ippsRSA_Decrypt(
//             CipherText_BN, PlainText_BN_2, m_pPrv, m_scratchBuffer);
//         if (status != ippStsNoErr) {
//             std::cout << "ippsRSA_Decrypt failed with err code" << status
//                       << std::endl;
//             return false;
//         }
//         if (PlainText_BN != PlainText_BN_2) {
//             std::cout << "FAIL" << std::endl;
//         }
//         /* TESTING */

//         //#endif
//     }
//     return 0;
// }

bool
IPPRsaBase::EncryptPubKey(const alcp_rsa_data_t& data)
{
    IppStatus status = ippStsNoErr;

    if (m_padding_mode == 1) {
        /*! Seed string of hash size */
        /*FIXME: should this come from test data? Also randomize this */
        static Ipp8u pSeed[] = "\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4"
                               "\x79\xe5\x07\x6d\xde\xc2\xf0\x6c\xb5\x8f";

        /* Encrypt message */
        status = ippsRSAEncrypt_OAEP_rmf(
            data.m_msg,
            data.m_msg_len,
            0,
            0,
            pSeed,
            data.m_encrypted_data,
            m_pPub,
            ippsHashMethod_SHA256_TT(), /*FIXME: this will change based on hash
                                           lenght in future */
            m_scratchBuffer_Pub);

        if (status != ippStsNoErr) {
            std::cout << "ippsRSAEncrypt_OAEP_rmf failed with err code"
                      << status << std::endl;
            return false;
        }
    } else {
        /* FIXME: not functional now */
        BigNumber     PlainText_BN((const char*)data.m_msg);
        IppsBigNumSGN sign;
        BigNumber     CipherText_BN(0, 128);
        status = ippsRSA_Encrypt(
            PlainText_BN, CipherText_BN, m_pPub, m_scratchBuffer_Pub);
        if (status != ippStsNoErr) {
            std::cout << "ippsRSA_Encrypt failed with err code" << status
                      << std::endl;
            return false;
        }
        /*FIXME: how to read data from this Bignum ?*/
        // status =
        //     CipherText_BN.GetOctetString(data.m_encrypted_data,
        //     data.m_msg_len);
        // if (status != ippStsNoErr) {
        //     std::cout << "ippsGetOctString_BN failed with err code" << status
        //               << std::endl;
        //     return false;
        // }
    }
    return true;
}

bool
IPPRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    IppStatus status = ippStsNoErr;

    if (m_padding_mode == 1) {
        int    plainTextLen = data.m_msg_len;
        Ipp8u* pPlainText   = new Ipp8u[plainTextLen];
        /* Decrypt message */
        status = ippsRSADecrypt_OAEP_rmf(
            data.m_encrypted_data,
            0,
            0,
            pPlainText,
            &plainTextLen,
            m_pPrv,
            ippsHashMethod_SHA256_TT(), /*FIXME: this will change based on hash
                                           lenght in future */
            m_scratchBuffer_Pvt);

        if (status != ippStsNoErr) {
            std::cout << "ippsRSADecrypt_OAEP_rmf failed with err code"
                      << status << std::endl;
            return false;
        }

        std::memcpy(data.m_decrypted_data, pPlainText, plainTextLen);

        if (pPlainText) {
            delete[] pPlainText;
        }
    } else {
        /* FIXME: not functional now */
        BigNumber CipherText_BN((const char*)data.m_encrypted_data);
        BigNumber PlainText_BN(0, m_modulus_size);
        status = ippsRSA_Decrypt(
            CipherText_BN, PlainText_BN, m_pPrv, m_scratchBuffer_Pvt);
        if (status != ippStsNoErr) {
            std::cout << "ippsRSA_Decrypt failed with err code" << status
                      << std::endl;
            return false;
        }
        /*FIXME: how to read data from this Bignum ?*/
        status =
            PlainText_BN.GetOctetString(data.m_decrypted_data, data.m_msg_len);
        if (status != ippStsNoErr) {
            std::cout << "ippsGetOctString_BN failed with err code" << status
                      << std::endl;
            return false;
        }
    }
    return true;
}

bool
IPPRsaBase::reset()
{
    return true;
}

} // namespace alcp::testing
