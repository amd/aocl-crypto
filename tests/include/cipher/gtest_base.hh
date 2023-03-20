/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "../../../lib/include/types.hh"
#include "alc_cipher_base.hh"
#include "cipher_base.hh"
#include "csv.hh"
#include "gtest_common.hh"
#include <vector>
#ifdef USE_IPP
#include "ipp_cipher_base.hh"
#endif
#ifdef USE_OSSL
#include "openssl_cipher_base.hh"
#endif
#include "rng_base.hh"
#include <algorithm>

using alcp::String;

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
        case ALC_AES_MODE_CCM:
            return "CCM";
        default:
            return "NULL";
    }
}

// Just a class to reduce duplication of lines
class TestingCore
{
  private:
    std::shared_ptr<Csv> m_csv;
    // FIXME: Change these to unique_ptr
    CipherTesting*    m_cipherHandler = {};
    AlcpCipherBase*   m_acb           = {};
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
        m_csv = std::make_shared<Csv>(std::string("dataset_") + modeStr
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
    std::shared_ptr<Csv> getCsv() { return m_csv; }
    CipherTesting*       getCipherHandler() { return m_cipherHandler; }
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

/* print params verbosely */
inline void
PrintTestData(std::vector<Uint8> key, alcp_data_ex_t data, std::string mode)
{
    std::cout << "KEY: " << parseBytesToHexStr(&key[0], key.size())
              << " Len: " << key.size() << std::endl;
    std::cout << "PLAINTEXT: " << parseBytesToHexStr(data.m_in, data.m_inl)
              << " Len: " << data.m_inl << std::endl;
    std::cout << "IV: " << parseBytesToHexStr(data.m_iv, data.m_ivl)
              << " Len: " << data.m_ivl << std::endl;
    std::cout << "CIPHERTEXT: " << parseBytesToHexStr(data.m_out, data.m_outl)
              << " Len: " << data.m_outl << std::endl;
    /* gcm / ccm / xts specific */
    if (mode.compare("GCM") == 0 || mode.compare("CCM") == 0) {
        std::cout << "ADL: " << parseBytesToHexStr(data.m_ad, data.m_adl)
                  << " Len: " << data.m_adl << std::endl;
        std::cout << "TAG: " << parseBytesToHexStr(data.m_tag, data.m_tagl)
                  << " Len: " << data.m_tagl << std::endl;
    }
    if (mode.compare("XTS") == 0) {
        std::cout << "TKEY: " << parseBytesToHexStr(data.m_tkey, data.m_tkeyl)
                  << " Len: " << data.m_tkeyl << std::endl;
    }
    return;
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
    Int32       ivl, adl, tkeyl = 16;
    bool        ret       = false;
    Int32       IVL_START = 0, IVL_MAX = 0, ADL_START = 0, ADL_MAX = 0;
    // FIXME: Tag Length should not be hard coded
    const Uint64 tagLength = 16;

    bool isxts = (MODE_STR.compare("XTS") == 0);
    bool isgcm = (MODE_STR.compare("GCM") == 0);
    bool isccm = (MODE_STR.compare("CCM") == 0);

    /* IV, AD Length limits for different cases */
    if (isccm) {
        IVL_START = 7;
        IVL_MAX   = 13;
        ADL_START = 12;
        ADL_MAX   = 16;
    } else if (isgcm) {
        IVL_START = 12;
        IVL_MAX   = 16;
        ADL_START = 12;
        ADL_MAX   = 16;
    } else {
        IVL_START = 16;
        IVL_MAX   = 16;
    }

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
        if (useipp && isxts) {
            /* ipp max supported block size is 128 */
            MAX_LOOP = 128;
        }
    } else {
        LOOP_START = BIG_START_LOOP;
        MAX_LOOP   = BIG_MAX_LOOP;
        INC_LOOP   = BIG_INC_LOOP;
        size       = 16 * 10000000;
    }

    /* max size supported by XTS is 2 ^ 20 = 1048576 */
    if (big_small == BIG && isxts) {
        size = (1048576 / 2);
    }

    /* generate these only once and use it in the loop below, chunk by chunk */
    std::vector<Uint8> msg_full  = rb.genRandomBytes(MAX_LOOP * size);
    std::vector<Uint8> key_full  = rb.genRandomBytes(key_size);
    std::vector<Uint8> iv_full   = rb.genRandomBytes(IVL_MAX);
    std::vector<Uint8> add_full  = rb.genRandomBytes(ADL_MAX);
    std::vector<Uint8> tkey_full = rb.genRandomBytes(key_size);

    std::vector<Uint8>::const_iterator pos1, pos2;

    auto rng = std::default_random_engine{};

    if (extTC != nullptr) {
        for (int i = LOOP_START; i < MAX_LOOP; i += INC_LOOP) {
            if (!bbxreplay)
                fr->startRecEvent();

            /* generate multiple iv and adl */
            ivl = IVL_START + (std::rand() % (IVL_START - IVL_MAX + 1));
            adl = ADL_START + (std::rand() % (ADL_MAX - ADL_START + 1));

            alcp_data_ex_t data_alc, data_ext;

            std::vector<Uint8> ct(i * size, 0), tag_alc(tagLength, 0),
                tag_ext(tagLength, 0), out_ct_alc(i * size, 0),
                out_ct_ext(i * size, 0), out_pt(i * size, 0);

            auto tagBuff = std::make_unique<Uint8[]>(tagLength);

            pos1 = msg_full.end() - i * size;
            pos2 = msg_full.end();
            std::vector<Uint8> pt(pos1, pos2);

            key_full = ShuffleVector(key_full, rng);
            pos1     = key_full.begin();
            pos2     = key_full.begin() + (key_size / 8);
            std::vector<Uint8> key(pos1, pos2);

            pos1 = iv_full.begin();
            pos2 = iv_full.begin() + (ivl);
            std::vector<Uint8> iv(pos1, pos2);

            pos1 = add_full.begin();
            pos2 = add_full.begin() + (adl);
            std::vector<Uint8> add(pos1, pos2);

            tkey_full = ShuffleVector(tkey_full, rng);
            pos1      = tkey_full.begin();
            pos2      = tkey_full.begin() + (key_size / 8);
            std::vector<Uint8> tkey(pos1, pos2);

            if (!bbxreplay) {
                // ALC/Main Lib Data
                data_alc.m_in   = &(pt[0]);
                data_alc.m_inl  = pt.size();
                data_alc.m_iv   = &(iv[0]);
                data_alc.m_ivl  = iv.size();
                data_alc.m_out  = &(out_ct_alc[0]);
                data_alc.m_outl = data_alc.m_inl;
                if (isgcm || isccm) {
                    data_alc.m_ad      = &(add[0]);
                    data_alc.m_adl     = add.size();
                    data_alc.m_tag     = &(tag_alc[0]);
                    data_alc.m_tagl    = tag_alc.size();
                    data_alc.m_tagBuff = tagBuff.get();
                }
                if (isxts) {
                    data_alc.m_tkey  = &(tkey[0]);
                    data_alc.m_tkeyl = tkeyl;
                }

                // External Lib Data
                data_ext.m_in   = &(pt[0]);
                data_ext.m_inl  = pt.size();
                data_ext.m_iv   = &(iv[0]);
                data_ext.m_ivl  = iv.size();
                data_ext.m_out  = &(out_ct_ext[0]);
                data_ext.m_outl = data_alc.m_inl;
                if (isgcm || isccm) {
                    data_ext.m_ad      = &(add[0]);
                    data_ext.m_adl     = add.size();
                    data_ext.m_tag     = &(tag_ext[0]);
                    data_ext.m_tagl    = tag_ext.size();
                    data_ext.m_tagBuff = tagBuff.get();
                }
                if (isxts) {
                    data_ext.m_tkey       = &(tkey[0]);
                    data_ext.m_tkeyl      = tkeyl;
                    data_ext.m_block_size = ct.size();
                }
                if (enc_dec == ENCRYPT)
                    fr->setRecEvent(
                        key, iv, pt, EncDecType(enc_dec, big_small));
                else if (enc_dec == DECRYPT)
                    fr->setRecEvent(
                        key, iv, ct, EncDecType(enc_dec, big_small));
            } else {
                fr->nextLog();
                try {
                    if (enc_dec == ENCRYPT)
                        fr->getValues(&key, &iv, &pt);
                    else if (enc_dec == DECRYPT)
                        fr->getValues(&key, &iv, &ct);

                } catch (std::string excp) {
                    std::cout << excp << std::endl;
                    exit(-1);
                }
            }

            if (enc_dec == ENCRYPT) {
                ret = alcpTC->getCipherHandler()->testingEncrypt(data_alc, key);
                if (!ret) {
                    std::cout << "ERROR: Enc: Main lib" << std::endl;
                    FAIL();
                }
                ret = extTC->getCipherHandler()->testingEncrypt(data_ext, key);
                if (!ret) {
                    std::cout << "ERROR: Enc: ext lib" << std::endl;
                    FAIL();
                }
                ASSERT_TRUE(ArraysMatch(out_ct_alc, out_ct_ext));
                /* for gcm*/
                if (isgcm || isccm) {
                    EXPECT_TRUE(ArraysMatch(tag_alc, tag_ext));
                }
                if (verbose > 1) {
                    PrintTestData(key, data_alc, MODE_STR);
                    PrintTestData(key, data_ext, MODE_STR);
                }
            } else {
                if (isgcm || isccm) {
                    ret = alcpTC->getCipherHandler()->testingEncrypt(data_alc,
                                                                     key);
                    if (!ret) {
                        std::cout << "ERROR: enc: main lib" << std::endl;
                        FAIL();
                    }
                    data_alc.m_in  = &(out_ct_alc[0]);
                    data_alc.m_out = &(pt[0]);
                }
                ret = alcpTC->getCipherHandler()->testingDecrypt(data_alc, key);
                if (!ret) {
                    std::cout << "ERROR: Dec: main lib" << std::endl;
                    FAIL();
                }

                /*ext lib decrypt */
                if (isgcm || isccm) {
                    ret = alcpTC->getCipherHandler()->testingEncrypt(data_ext,
                                                                     key);
                    if (!ret) {
                        std::cout << "ERROR: enc: ext lib" << std::endl;
                        FAIL();
                    }
                    data_ext.m_in  = &(out_ct_ext[0]);
                    data_ext.m_out = &(pt[0]);
                }
                ret = extTC->getCipherHandler()->testingDecrypt(data_ext, key);
                if (!ret) {
                    std::cout << "ERROR: Dec: ext lib" << std::endl;
                    FAIL();
                }
                data_ext.m_isTagValid = /* check if Tag is valid */
                    (std::find(tag_ext.begin(), tag_ext.end(), true)
                     == tag_ext.end());
                data_alc.m_isTagValid = /* check if Tag is valid */
                    (std::find(tag_alc.begin(), tag_alc.end(), true)
                     == tag_alc.end());
                if (isgcm || isccm) {
                    /* Verify only if tag contains valid data */
                    if (!data_alc.m_isTagValid || !data_ext.m_isTagValid) {
                        ASSERT_TRUE(ArraysMatch(out_ct_alc, out_ct_ext));
                        EXPECT_TRUE(ArraysMatch(tag_alc, tag_ext));
                    }
                } else {
                    ASSERT_TRUE(ArraysMatch(out_ct_alc, out_ct_ext));
                }
                if (verbose > 1) {
                    PrintTestData(key, data_alc, MODE_STR);
                    PrintTestData(key, data_ext, MODE_STR);
                }
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
RunCipherKATTest(TestingCore& testingCore,
                 enc_dec_t    enc_dec,
                 std::string  enc_dec_str,
                 std::string  MODE_STR,
                 int          keySize,
                 bool         isxts,
                 bool         isgcm)
{
    bool                 ret = false;
    alcp_data_ex_t       data;
    std::shared_ptr<Csv> csv = testingCore.getCsv();
    std::vector<Uint8>   outpt(csv->getVect("PLAINTEXT").size(), 0);
    std::vector<Uint8>   outct(csv->getVect("CIPHERTEXT").size(), 0);
    std::vector<Uint8>   pt      = csv->getVect("PLAINTEXT");
    std::vector<Uint8>   ct      = csv->getVect("CIPHERTEXT");
    std::vector<Uint8>   iv      = csv->getVect("INITVECT");
    std::vector<Uint8>   tkey    = csv->getVect("TWEAK_KEY");
    std::vector<Uint8>   outtag  = csv->getVect("TAG");
    std::vector<Uint8>   ad      = csv->getVect("ADDITIONAL_DATA");
    std::vector<Uint8>   tagBuff = std::vector<Uint8>(outtag.size());

    // Common Initialization
    data.m_tkeyl = 0;
    data.m_adl   = 0;
    data.m_tagl  = 0;
    if (isgcm) {
        if (outtag.size()) {
            data.m_tag     = &(outtag[0]);
            data.m_tagl    = outtag.size();
            data.m_tagBuff = &tagBuff[0];
        }
        if (ad.size()) {
            data.m_ad  = &(ad[0]);
            data.m_adl = ad.size();
        }
    }
    if (enc_dec == ENCRYPT) {
        if (pt.size()) {
            data.m_in  = &(pt[0]);
            data.m_inl = pt.size();
        }
        data.m_iv  = &(iv[0]);
        data.m_ivl = iv.size();
        if (outct.size())
            data.m_out = &(outct[0]);
        data.m_outl = data.m_inl;
        if (isxts) {
            data.m_tkey       = &(tkey[0]);
            data.m_tkeyl      = tkey.size();
            data.m_block_size = pt.size();
        }
        ret = testingCore.getCipherHandler()->testingEncrypt(
            data, csv->getVect("KEY"));
        if (!ret) {
            std::cout << "ERROR: Enc" << std::endl;
            EXPECT_TRUE(ret);
        }
        EXPECT_TRUE(
            ArraysMatch(outct,
                        csv->getVect("CIPHERTEXT"),
                        *(csv.get()),
                        std::string("AES_" + MODE_STR + "_"
                                    + std::to_string(keySize) + enc_dec_str)));

        if (isgcm) {
            EXPECT_TRUE(ArraysMatch(outtag,
                                    csv->getVect("TAG"),
                                    *(csv.get()),
                                    std::string("AES_" + MODE_STR + "_"
                                                + std::to_string(keySize)
                                                + enc_dec_str + "_TAG")));
        }
        // Enforce that no errors are reported from lib side.
        EXPECT_TRUE(ret);
    } else {
        if (ct.size()) {
            data.m_in  = &(ct[0]);
            data.m_inl = ct.size();
        }
        data.m_iv  = &(iv[0]);
        data.m_ivl = iv.size();
        if (outpt.size())
            data.m_out = &(outpt[0]);
        data.m_outl = data.m_inl;
        if (isxts) {
            data.m_tkey       = &(tkey[0]);
            data.m_tkeyl      = tkey.size();
            data.m_block_size = ct.size();
        }
        ret = testingCore.getCipherHandler()->testingDecrypt(
            data, csv->getVect("KEY"));

        if (isgcm && data.m_tagl == 0) {
            ret = true; // Skip tag test
        }
        if (!ret) {
            std::cout << "ERROR: Dec" << std::endl;
            EXPECT_TRUE(ret);
        }
        EXPECT_TRUE(
            ArraysMatch(outpt,
                        csv->getVect("PLAINTEXT"),
                        *(testingCore.getCsv()),
                        std::string("AES_" + MODE_STR + "_"
                                    + std::to_string(keySize) + enc_dec_str)));
        // Enforce that no errors are reported from lib side.
        EXPECT_TRUE(ret);
    }
    return ret;
}

/**
 * @brief Function to run KAT for AES Schemes CTR,CFB,OFB,CBC,XTS
 *
 * @param keySize keysize in bits(128,192,256)
 * @param enc_dec enum for encryption or decryption
 * @param mode Aode of encryption/Decryption (CTR,CFB,OFB,CBC,XTS)
 */
void
AesKatTest(int keySize, enc_dec_t enc_dec, alc_cipher_mode_t mode)
{
    size_t            key_size = keySize;
    const std::string cModeStr = GetModeSTR(mode);
    std::string       enc_dec_str;
    bool              isxts = (cModeStr.compare("XTS") == 0);
    bool              isgcm = (cModeStr.compare("GCM") == 0);
    bool              isccm = (cModeStr.compare("CCM") == 0);

    if (enc_dec == ENCRYPT)
        enc_dec_str = "_ENC";
    else
        enc_dec_str = "_DEC";

    TestingCore testing_core = TestingCore(cModeStr, mode);

    bool retval = false;

    while (testing_core.getCsv()->readNext()) {
        if ((testing_core.getCsv()->getVect("KEY").size() * 8) != key_size) {
            // std::cout << testing_core.getCsv()->getStr("KEY") << " "
            //           << testing_core.getCsv()->getStr("PLAINTEXT") << " "
            //           << testing_core.getCsv()->getVect("KEY").size() * 8
            //           << " ";
            continue;
        }
        // std::cout << std::endl;
        retval = RunCipherKATTest(testing_core,
                                  enc_dec,
                                  enc_dec_str,
                                  cModeStr,
                                  keySize,
                                  isxts,
                                  isgcm || isccm);
        EXPECT_TRUE(retval);
        // printf("MEOW\n");
    }
}
#endif