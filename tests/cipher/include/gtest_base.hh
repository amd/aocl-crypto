/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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
#ifndef __GTEST_BASE_HH
#define __GTEST_BASE_HH 2

#include "alc_base.hh"
#include "base.hh"
#include "gtest_common.hh"
#include <vector>
#ifdef USE_IPP
#include "ipp_base.hh"
#endif
#ifdef USE_OSSL
#include "openssl_base.hh"
#endif
enum ENC_DEC
{
    DECRYPT = 0,
    ENCRYPT
};

/**
 * returns respective string based on AES modes
 */
std::string
GetModeSTR(alc_aes_mode_t mode)
{
    switch (mode) {
        case ALC_AES_MODE_ECB:
            return "ECB";
        case ALC_AES_MODE_CBC:
            return "CBC";
        case ALC_AES_MODE_OFB:
            return "OFB";
        case ALC_AES_MODE_CTR:
            return "CTR";
        case ALC_AES_MODE_CFB:
            return "CFB";
        case ALC_AES_MODE_XTR:
            return "XTR";
        case ALC_AES_MODE_GCM:
            return "GCM";
        default:
            return "NULL";
    }
}
/**
 * Macro for Cipher KAT
 */
#define KAT_TEST_MACRO(TEST_NAME, TEST_TYPE, keySize, enc_dec, mode)           \
    TEST(TEST_NAME, TEST_TYPE)                                                 \
    {                                                                          \
        int         key_size = keySize;                                        \
        std::string MODE_STR = GetModeSTR(mode);                               \
        bool        test_ran = false;                                          \
        std::string enc_dec_str;                                               \
        if (enc_dec == ENCRYPT)                                                \
            enc_dec_str = "_ENC";                                              \
        else                                                                   \
            enc_dec_str = "_DEC";                                              \
        TestingCore testingCore = TestingCore(MODE_STR, ALC_MODE);             \
                                                                               \
        while (testingCore.getDs()->readPtIvKeyCt(                             \
            key_size)) { /*Checks if output is correct*/                       \
            test_ran = true;                                                   \
            if (enc_dec == ENCRYPT)                                            \
                EXPECT_TRUE(ArraysMatch(                                       \
                    testingCore.getCipherHandler()->testingEncrypt(            \
                        testingCore.getDs()->getPt(),                          \
                        testingCore.getDs()->getKey(),                         \
                        testingCore.getDs()->getIv()),                         \
                    testingCore.getDs()->getCt(),                              \
                    *(testingCore.getDs()),                                    \
                    std::string("AES_" + MODE_STR + "_"                        \
                                + std::to_string(keySize) + enc_dec_str)));    \
            else                                                               \
                EXPECT_TRUE(ArraysMatch(                                       \
                    testingCore.getCipherHandler()->testingDecrypt(            \
                        testingCore.getDs()->getCt(),                          \
                        testingCore.getDs()->getKey(),                         \
                        testingCore.getDs()->getIv()),                         \
                    testingCore.getDs()->getPt(),                              \
                    *(testingCore.getDs()),                                    \
                    std::string("AES_" + MODE_STR + "_"                        \
                                + std::to_string(keySize) + enc_dec_str)));    \
        }                                                                      \
        if (!test_ran) {                                                       \
            EXPECT_TRUE(::testing::AssertionFailure()                          \
                        << "No tests to run, check dataset");                  \
        }                                                                      \
    }
// Just a class to reduce duplication of lines
class TestingCore
{
  private:
    DataSet*        m_ds            = nullptr;
    CipherTesting*  m_cipherHandler = nullptr;
    AlcpCipherBase* m_acb           = nullptr;
    lib_t           m_lib;
    alc_aes_mode_t  m_alcpMode;
#ifdef USE_IPP
    IPPCipherBase* icb = nullptr;
#endif
#ifdef USE_OSSL
    OpenSSLCipherBase* ocb = nullptr;
#endif
  public:
    TestingCore(lib_t lib, alc_aes_mode_t alcpMode)
    {
        m_lib           = lib;
        m_alcpMode      = alcpMode;
        m_cipherHandler = new CipherTesting();
        switch (lib) {
            case OPENSSL:
#ifndef USE_OSSL
                delete m_cipherHandler;
                throw "OpenSSL not avaiable!";
#else
                ocb = new OpenSSLCipherBase(alcpMode, NULL);
                m_cipherHandler->setcb(ocb);
#endif
                break;
            case IPP:
#ifndef USE_IPP
                delete m_cipherHandler;
                throw "IPP not avaiable!";
#else
                if (!useipp) {
                    delete m_cipherHandler;
                    throw "IPP disabled!";
                }
                icb = new IPPCipherBase(alcpMode, NULL);
                m_cipherHandler->setcb(icb);
#endif
                break;
            case ALCP:
                m_acb = new AlcpCipherBase(alcpMode, NULL);
                m_cipherHandler->setcb(m_acb);
                break;
        }
    }
    TestingCore(std::string modeStr, alc_aes_mode_t alcpMode)
    {
        std::transform(
            modeStr.begin(), modeStr.end(), modeStr.begin(), ::tolower);
        m_ds = new DataSet(std::string("dataset_") + modeStr
                           + std::string(".csv"));

        // Initialize cipher testing classes
        m_cipherHandler = new CipherTesting();
        m_acb           = new AlcpCipherBase(alcpMode, NULL);
        m_cipherHandler->setcb(m_acb);
#ifdef USE_IPP
        icb = new IPPCipherBase(alcpMode, NULL);
        if (useipp) {
            std::cout << "Using IPP" << std::endl;
            m_cipherHandler->setcb(icb);
        }
#else
        if (useipp) {
            printErrors("IPP is unavailable at the moment switching to ALCP!");
        }
#endif
#ifdef USE_OSSL
        ocb = new OpenSSLCipherBase(alcpMode, NULL);
        if (useossl) {
            std::cout << "Using OpenSSL" << std::endl;
            m_cipherHandler->setcb(ocb);
        }
#else
        if (useossl) {
            printErrors(
                "OpenSSL is unavailable at the moment switching to ALCP!");
        }
#endif
    }
    ~TestingCore()
    {
        if (m_ds != nullptr)
            delete m_ds;
        if (m_cipherHandler != nullptr)
            delete m_cipherHandler;
        if (m_acb != nullptr)
            delete m_acb;
#ifdef USE_IPP
        if (icb != nullptr)
            delete icb;
#endif
#ifdef USE_OSSL
        if (ocb != nullptr)
            delete ocb;
#endif
    }
    DataSet*       getDs() { return m_ds; }
    CipherTesting* getCipherHandler() { return m_cipherHandler; }
};

#endif