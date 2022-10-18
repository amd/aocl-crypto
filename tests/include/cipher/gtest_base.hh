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
#include "rng_base.hh"
typedef enum
{
    DECRYPT = 0,
    ENCRYPT
} enc_dec_t;

typedef enum
{
    SMALL = 0,
    BIG
} big_small_t;
/**
 * returns respective string based on AES modes
 */
std::string
GetModeSTR(alc_cipher_mode_t mode)
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
        case ALC_AES_MODE_XTS:
            return "XTS";
        case ALC_AES_MODE_GCM:
            return "GCM";
        default:
            return "NULL";
    }
}
/**
 * Macro for Cipher KAT
 */
#define KAT_TEST_MACRO(keySize, enc_dec, mode)                                 \
    int         key_size = keySize;                                            \
    std::string MODE_STR = GetModeSTR(mode);                                   \
    bool        test_ran = false;                                              \
    std::string enc_dec_str;                                                   \
    if (enc_dec == ENCRYPT)                                                    \
        enc_dec_str = "_ENC";                                                  \
    else                                                                       \
        enc_dec_str = "_DEC";                                                  \
    TestingCore testingCore = TestingCore(MODE_STR, ALC_MODE);                 \
                                                                               \
    while (testingCore.getDs()->readPtIvKeyCt(                                 \
        key_size)) { /*Checks if output is correct*/                           \
        test_ran = true;                                                       \
        if (enc_dec == ENCRYPT)                                                \
            EXPECT_TRUE(ArraysMatch(                                           \
                testingCore.getCipherHandler()->testingEncrypt(                \
                    testingCore.getDs()->getPt(),                              \
                    testingCore.getDs()->getKey(),                             \
                    testingCore.getDs()->getIv()),                             \
                testingCore.getDs()->getCt(),                                  \
                *(testingCore.getDs()),                                        \
                std::string("AES_" + MODE_STR + "_" + std::to_string(keySize)  \
                            + enc_dec_str)));                                  \
        else                                                                   \
            EXPECT_TRUE(ArraysMatch(                                           \
                testingCore.getCipherHandler()->testingDecrypt(                \
                    testingCore.getDs()->getCt(),                              \
                    testingCore.getDs()->getKey(),                             \
                    testingCore.getDs()->getIv()),                             \
                testingCore.getDs()->getPt(),                                  \
                *(testingCore.getDs()),                                        \
                std::string("AES_" + MODE_STR + "_" + std::to_string(keySize)  \
                            + enc_dec_str)));                                  \
    }                                                                          \
    if (!test_ran) {                                                           \
        EXPECT_TRUE(::testing::AssertionFailure()                              \
                    << "No tests to run, check dataset");                      \
    }
// Just a class to reduce duplication of lines
class TestingCore
{
  private:
    DataSet*          m_ds            = nullptr;
    CipherTesting*    m_cipherHandler = nullptr;
    AlcpCipherBase*   m_acb           = nullptr;
    lib_t             m_lib;
    alc_cipher_mode_t m_alcpMode;
#ifdef USE_IPP
    IPPCipherBase* icb = nullptr;
#endif
#ifdef USE_OSSL
    OpenSSLCipherBase* ocb = nullptr;
#endif
  public:
    TestingCore(lib_t lib, alc_cipher_mode_t alcpMode)
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
    TestingCore(std::string modeStr, alc_cipher_mode_t alcpMode)
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

/**
 * @brief Use the below parameters to control the range of small and big cross
 * test
 *
 */

// Below in bytes
#define SMALL_MAX_LOOP   160000
#define SMALL_INC_LOOP   16
#define SMALL_START_LOOP 16
// Below in 0.1MB size
#define BIG_MAX_LOOP   2
#define BIG_INC_LOOP   1
#define BIG_START_LOOP 1
/**
 * @brief
 *
 * @param e_d encryption or Decryption
 * @param b_s big or small
 * @return record_t returns Enum for the type of encryption or decryption(big or
 * small)
 */
record_t
EncDecType(enc_dec_t e_d, big_small_t b_s)
{
    if (b_s == BIG && e_d == ENCRYPT)
        return BIG_ENC;
    else if (b_s == BIG && e_d == DECRYPT)
        return BIG_DEC;
    else if (b_s == SMALL && e_d == ENCRYPT)
        return SMALL_ENC;
    else if (b_s == SMALL && e_d == DECRYPT)
        return SMALL_DEC;
    else
        std::cout << "ERROR....invalid values of big_small or enc_dec"
                  << std::endl;
    return SMALL_DEC;
}

/**
 * @brief funtion to avoid repeated code in every cross test, can only be used
 * for AES-CTR,AES-CBC,AES-OFB,AES-CFB
 *
 * @param keySize keysize in bits(128,192 or 256)
 * @param enc_dec (encryption or Decryption)
 * @param mode AES modes (CTR, OFB, CBC and CFB)
 * @param big_small Type (Big or Small) of test
 */
void
AesCrosstest(int               keySize,
             enc_dec_t         enc_dec,
             alc_cipher_mode_t mode,
             big_small_t       big_small)
{
    int         key_size = keySize;
    int         LOOP_START, MAX_LOOP, INC_LOOP;
    size_t      size = 1;
    std::string enc_dec_str, big_small_str;
    std::string MODE_STR = GetModeSTR(mode);

    bool        isxts = (MODE_STR.compare("XTS") == 0);
    bool        isgcm = (MODE_STR.compare("GCM") == 0);

    if (enc_dec == ENCRYPT)
        enc_dec_str.assign("ENC");
    else
        enc_dec_str.assign("DEC");
    if (big_small == BIG)
        big_small_str.assign("BIG");
    else
        big_small_str.assign("SMALL");
    /* Request from others to validate openssl with ipp */
    TestingCore* alcpTC = nullptr;
    if (oa_override) {
        alcpTC = new TestingCore(OPENSSL, mode);
        printErrors("ALCP is overriden!... OpenSSL is now main lib");
        printErrors("ALCP is overriden!... Forcing IPP as extlib");
        useipp  = true;
        useossl = false;
    } else {
        alcpTC = new TestingCore(ALCP, mode);
    }
    TestingCore* extTC = nullptr;
    ExecRecPlay* fr    = nullptr;
    RngBase      rb;
    if (bbxreplay) {
        fr = new ExecRecPlay("AES_" + MODE_STR + "_" + enc_dec_str + "_"
                                 + std::to_string(key_size) + "_"
                                 + big_small_str,
                             "AES_" + MODE_STR + "_TEST_DATA",
                             true);
        fr->fastForward(EncDecType(enc_dec, big_small));
    } else
        fr = new ExecRecPlay("AES_" + MODE_STR + "_" + enc_dec_str + "_"
                                 + std::to_string(key_size) + "_"
                                 + big_small_str,
                             "AES_" + MODE_STR + "_TEST_DATA",
                             false);
    /* Set extTC based on which external testing core user asks*/
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, mode);
        else if (useipp)
            extTC = new TestingCore(IPP, mode);
        else {
            printErrors("No Lib Specified!.. but trying OpenSSL");
            extTC = new TestingCore(OPENSSL, mode);
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }
    if (big_small == SMALL) {
        LOOP_START = SMALL_START_LOOP;
        MAX_LOOP   = SMALL_MAX_LOOP;
        INC_LOOP   = SMALL_INC_LOOP;
        size       = 1;
    } else {
        LOOP_START = BIG_START_LOOP;
        MAX_LOOP   = BIG_MAX_LOOP;
        INC_LOOP   = BIG_INC_LOOP;
        size       = 16 * 10000000;
    }

    if (extTC != nullptr) {
        for (int i = LOOP_START; i < MAX_LOOP; i += INC_LOOP) {
            if (big_small == BIG) {
                size = 524288;
            }
            if (!bbxreplay)
                fr->startRecEvent();

            alcp_data_ex_t     data_alc, data_ext;
            std::vector<Uint8> pt(i*size, 0), ct(i*size, 0), key(key_size/8, 0), iv(12, 0), tkey(key_size / 8, 0), add(16,0), tag_alc(16, 0), tag_ext(16, 0),
                out_ct_alc(i * size, 0), out_ct_ext(i * size, 0), out_pt(i * size, 0);

            if (!bbxreplay) {
                pt = rb.genRandomBytes(i * size);
                ct = rb.genRandomBytes(i * size);
                key = rb.genRandomBytes(key_size/8);
                iv  = rb.genRandomBytes(16);
                add = rb.genRandomBytes(16);
                tkey = rb.genRandomBytes(key_size/8);
                iv  = rb.genRandomBytes(12);

                // ALC/Main Lib Data
                data_alc.m_in   = &(pt[0]);
                data_alc.m_inl  = pt.size();
                data_alc.m_iv   = &(iv[0]);
                data_alc.m_ivl  = iv.size();
                data_alc.m_out  = &(out_ct_alc[0]);
                data_alc.m_outl = data_alc.m_inl;
                if (isgcm) {
                    data_alc.m_ad   = &(add[0]);
                    data_alc.m_adl  = add.size();
                    data_alc.m_tag  = &(tag_alc[0]);
                    data_alc.m_tagl = tag_alc.size();
                }
                if (isxts) {
                    data_alc.m_tkey  = &(tkey[0]);
                    data_alc.m_tkeyl = 16;
                }
                
                // External Lib Data
                data_ext.m_in   = &(pt[0]);
                data_ext.m_inl  = pt.size();
                data_ext.m_iv   = &(iv[0]);
                data_ext.m_ivl  = iv.size();
                data_ext.m_out  = &(out_ct_ext[0]);
                data_ext.m_outl = data_alc.m_inl;
                if (isgcm) {
                    data_ext.m_ad   = &(add[0]);
                    data_ext.m_adl  = add.size();
                    data_ext.m_tag  = &(tag_ext[0]);
                    data_ext.m_tagl = tag_ext.size();
                }
                if (isxts) {
                    data_ext.m_tkey  = &(tkey[0]);
                    data_ext.m_tkeyl      = 16;
                    data_ext.m_block_size = ct.size();
                }
                if (enc_dec == ENCRYPT)
                    fr->setRecEvent(
                        key, iv, pt, EncDecType(enc_dec, big_small));
                else if ((enc_dec == DECRYPT))
                    fr->setRecEvent(
                        key, iv, ct, EncDecType(enc_dec, big_small));
            } else {
                fr->nextLog();
                try {
                    if (enc_dec == ENCRYPT)
                        fr->getValues(&key, &iv, &pt);
                    else if ((enc_dec == DECRYPT))
                        fr->getValues(&key, &iv, &ct);

                } catch (std::string excp) {
                    std::cout << excp << std::endl;
                    exit(-1);
                }
            }
            if (enc_dec == ENCRYPT) {
                //printf("%p %p %p\n", data_alc.m_in, data_alc.m_ad, data_alc.m_out);
                alcpTC->getCipherHandler()->testingEncrypt(data_alc, key);
                extTC->getCipherHandler()->testingEncrypt(data_ext, key);
                ASSERT_TRUE(ArraysMatch(out_ct_alc, out_ct_ext));
                /* for gcm*/
                if (isgcm) {
                    ASSERT_TRUE(ArraysMatch(tag_alc, tag_ext));
                }
                //ASSERT_TRUE(ArraysMatch(tag_alc, tag_ext));
            } else {
                alcpTC->getCipherHandler()->testingDecrypt(data_alc, key);
                extTC->getCipherHandler()->testingDecrypt(data_ext, key);
                ASSERT_TRUE(ArraysMatch(out_ct_alc, out_ct_ext));
            }
            if (!bbxreplay) {
                fr->dumpBlackBox();
                fr->endRecEvent();
                fr->dumpLog();
            }
        }
        delete extTC;
        delete alcpTC;
    }
    delete fr;
}

bool
RunTest(TestingCore& testingCore,
        enc_dec_t    enc_dec,
        std::string  enc_dec_str,
        std::string  MODE_STR,
        int          keySize,
        bool         isxts,
        bool         isgcm)
{
    bool               ret = false;
    alcp_data_ex_t     data;
    std::vector<Uint8> outpt(testingCore.getDs()->getCt().size(), 0);
    std::vector<Uint8> outct(testingCore.getDs()->getPt().size(), 0);
    std::vector<Uint8> pt     = testingCore.getDs()->getPt();
    std::vector<Uint8> ct     = testingCore.getDs()->getCt();
    std::vector<Uint8> iv     = testingCore.getDs()->getIv();
    std::vector<Uint8> tkey   = testingCore.getDs()->getTKey();
    std::vector<Uint8> outtag = testingCore.getDs()->getTag();
    std::vector<Uint8> ad     = testingCore.getDs()->getAdd();

    if (enc_dec == ENCRYPT) {
        data.m_in    = &(pt[0]);
        data.m_inl   = pt.size();
        data.m_iv    = &(iv[0]);
        data.m_ivl   = iv.size();
        data.m_out   = &(outct[0]);
        data.m_outl  = data.m_inl;
        data.m_tkeyl = 0;
        data.m_adl   = 0;
        data.m_tagl  = 0;
        if (isxts) {
            data.m_tkey       = &(tkey[0]);
            data.m_tkeyl      = tkey.size();
            data.m_block_size = pt.size();
        }
        if (isgcm) {
            data.m_tag  = &(outtag[0]);
            data.m_tagl = outtag.size();
            data.m_ad   = &(ad[0]);
            data.m_adl  = ad.size();
        }
        ret = testingCore.getCipherHandler()->testingEncrypt(
            data, testingCore.getDs()->getKey());
        EXPECT_TRUE(
            ArraysMatch(outct,
                        testingCore.getDs()->getCt(),
                        *(testingCore.getDs()),
                        std::string("AES_" + MODE_STR + "_"
                                    + std::to_string(keySize) + enc_dec_str)));

        if (isgcm) {
            EXPECT_TRUE(ArraysMatch(outtag,
                                    testingCore.getDs()->getTag(),
                                    *(testingCore.getDs()),
                                    std::string("AES_" + MODE_STR + "_"
                                                + std::to_string(keySize)
                                                + enc_dec_str + "_TAG")));
        }
        // Enforce that no errors are reported from lib side.
        EXPECT_TRUE(ret);
    } else {
        data.m_in    = &(ct[0]);
        data.m_inl   = ct.size();
        data.m_iv    = &(iv[0]);
        data.m_ivl   = iv.size();
        data.m_out   = &(outpt[0]);
        data.m_outl  = data.m_inl;
        data.m_tkeyl = 0;
        data.m_adl   = 0;
        data.m_tagl  = 0;
        if (isxts) {
            data.m_tkey       = &(tkey[0]);
            data.m_tkeyl      = tkey.size();
            data.m_block_size = ct.size();
        }
        if (isgcm) {
            data.m_tag  = &(outtag[0]);
            data.m_tagl = outtag.size();
            data.m_ad   = &(ad[0]);
            data.m_adl  = ad.size();
        }
        bool ret = testingCore.getCipherHandler()->testingDecrypt(
            data, testingCore.getDs()->getKey());

        if (isgcm && data.m_tagl == 0) {
            ret = true; // Skip tag test
        }
        EXPECT_TRUE(
            ArraysMatch(outpt,
                        testingCore.getDs()->getPt(),
                        *(testingCore.getDs()),
                        std::string("AES_" + MODE_STR + "_"
                                    + std::to_string(keySize) + enc_dec_str)));
        // Enforce that no errors are reported from lib side.
        EXPECT_TRUE(ret);
    }
    return ret;
}

/**
 * @brief function to run KAT for AES Schemes CTR,CFB,OFB,CBC,XTS
 *
 * @param keySize keysize in bits(128,192,256)
 * @param enc_dec enum for encryption or decryption
 * @param mode Aode of encryption/Decryption (CTR,CFB,OFB,CBC,XTS)
 */
void
AesKatTest(int keySize, enc_dec_t enc_dec, alc_cipher_mode_t mode)
{
    int         key_size = keySize;
    std::string MODE_STR = GetModeSTR(mode);
    std::string enc_dec_str;
    bool        isxts = (MODE_STR.compare("XTS") == 0);
    bool        isgcm = (MODE_STR.compare("GCM") == 0);

    if (enc_dec == ENCRYPT)
        enc_dec_str = "_ENC";
    else
        enc_dec_str = "_DEC";

    TestingCore testingCore = TestingCore(MODE_STR, mode);

    if (isxts) {
        while (testingCore.getDs()->readPtIvKeyCtTKey(key_size))
            RunTest(testingCore,
                    enc_dec,
                    enc_dec_str,
                    MODE_STR,
                    keySize,
                    true,
                    false);
    } else if (isgcm) {
        while (testingCore.getDs()->readPtIvKeyCtAddTag(key_size)) {
            RunTest(testingCore,
                    enc_dec,
                    enc_dec_str,
                    MODE_STR,
                    keySize,
                    false,
                    true);
        }
    } else {
        while (testingCore.getDs()->readPtIvKeyCt(key_size))
            RunTest(testingCore,
                    enc_dec,
                    enc_dec_str,
                    MODE_STR,
                    keySize,
                    false,
                    false);
    }
}

#endif