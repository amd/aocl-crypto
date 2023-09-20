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

#include "../../../lib/include/alcp/types.hh"
#include "alc_cipher.hh"
#include "alc_cipher_aead.hh"
#include "cipher.hh"
#include "csv.hh"
#include "gtest_common.hh"
#include <vector>
#ifdef USE_IPP
#include "ipp_cipher.hh"
#include "ipp_cipher_aead.hh"
#endif
#ifdef USE_OSSL
#include "openssl_cipher.hh"
#include "openssl_cipher_aead.hh"
#endif
#include "rng_base.hh"
#include <algorithm>

using alcp::String;

typedef enum
{
    DECRYPT = 0,
    ENCRYPT
} encDec_t;

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
        case ALC_AES_MODE_SIV:
            return "SIV";
        default:
            return "NULL";
    }
}

// Just a class to reduce duplication of line
class CipherTestingCore
{
  private:
#ifndef ENABLE_RSP
    std::shared_ptr<Csv> m_csv;
#else
    std::shared_ptr<CRspParser> m_rsp;
#endif
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
    CipherTestingCore(lib_t lib, alc_cipher_mode_t alcpMode)
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
                ocb =
                    new OpenSSLCipherBase(ALC_CIPHER_TYPE_AES, alcpMode, NULL);
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
                icb = new IPPCipherBase(ALC_CIPHER_TYPE_AES, alcpMode, NULL);
                m_cipherHandler->setcb(icb);
#endif
                break;
            case ALCP:
                m_acb = new AlcpCipherBase(ALC_CIPHER_TYPE_AES, alcpMode, NULL);
                m_cipherHandler->setcb(m_acb);
                break;
        }
    }
    CipherTestingCore(std::string modeStr, alc_cipher_mode_t alcpMode)
    {
        std::transform(
            modeStr.begin(), modeStr.end(), modeStr.begin(), ::tolower);
#ifndef ENABLE_RSP
        m_csv = std::make_shared<Csv>(std::string("dataset_") + modeStr
                                      + std::string(".csv"));
#else
        m_rsp = std::make_shared<CRspParser>(std::string("dataset_") + modeStr
                                             + std::string(".rsp"));
#endif
        // Initialize cipher testing classes
        m_cipherHandler = new CipherTesting();
        m_acb = new AlcpCipherBase(ALC_CIPHER_TYPE_AES, alcpMode, NULL);
        m_cipherHandler->setcb(m_acb);
#ifdef USE_IPP
        icb = new IPPCipherBase(ALC_CIPHER_TYPE_AES, alcpMode, NULL);
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
        ocb = new OpenSSLCipherBase(ALC_CIPHER_TYPE_AES, alcpMode, NULL);
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
    ~CipherTestingCore()
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

class CipherAeadTestingCore
{
  private:
    std::shared_ptr<Csv> m_csv;
    // FIXME: Change these to unique_ptr
    CipherTesting*      m_cipherHandler = {};
    AlcpCipherAeadBase* m_acb           = {};
    lib_t               m_lib;
    alc_cipher_mode_t   m_alcpMode;
#ifdef USE_IPP
    IPPCipherAeadBase* icb = nullptr;
#endif
#ifdef USE_OSSL
    OpenSSLCipherAeadBase* ocb = nullptr;
#endif
  public:
    CipherAeadTestingCore(lib_t lib, alc_cipher_mode_t alcpMode)
    {
        m_lib           = lib;
        m_alcpMode      = alcpMode;
        m_cipherHandler = new CipherTesting();
        switch (lib) {
                // FIXME: OpenSSL and IPP AEAD Bringup needed
            case OPENSSL:
#ifndef USE_OSSL
                delete m_cipherHandler;
                throw "OpenSSL not avaiable!";
#else
                ocb = new OpenSSLCipherAeadBase(alcpMode, NULL);
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
                icb = new IPPCipherAeadBase(alcpMode, NULL);
                m_cipherHandler->setcb(icb);
#endif
                break;
            case ALCP:
                m_acb = new AlcpCipherAeadBase(alcpMode, NULL);
                m_cipherHandler->setcb(m_acb);
                break;
        }
    }
    CipherAeadTestingCore(std::string modeStr, alc_cipher_mode_t alcpMode)
    {
        std::transform(
            modeStr.begin(), modeStr.end(), modeStr.begin(), ::tolower);
        m_csv = std::make_shared<Csv>(std::string("dataset_") + modeStr
                                      + std::string(".csv"));

        // Initialize cipher testing classes
        m_cipherHandler = new CipherTesting();
        m_acb           = new AlcpCipherAeadBase(alcpMode, NULL);
        m_cipherHandler->setcb(m_acb);
#ifdef USE_IPP
        icb = new IPPCipherAeadBase(alcpMode, NULL);
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
        ocb = new OpenSSLCipherAeadBase(alcpMode, NULL);
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
    ~CipherAeadTestingCore()
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
#ifndef ENABLE_RSP
    std::shared_ptr<Csv> getCsv() { return m_csv; }
#else
    std::shared_ptr<CRspParser> getRsp() { return m_rsp; }
#endif
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
EncDecType(encDec_t e_d, big_small_t b_s)
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
        std::cout << "ERROR....invalid values of big_small or encDec"
                  << std::endl;
    return SMALL_DEC;
}

// Non AEAD Version
/* print params verbosely */
inline void
PrintTestData(std::vector<Uint8> key, alcp_dc_ex_t data, std::string mode)
{
    std::cout << "KEY: " << parseBytesToHexStr(&key[0], key.size())
              << " Len: " << key.size() << std::endl;
    std::cout << "PLAINTEXT: " << parseBytesToHexStr(data.m_in, data.m_inl)
              << " Len: " << data.m_inl << std::endl;
    std::cout << "IV: " << parseBytesToHexStr(data.m_iv, data.m_ivl)
              << " Len: " << data.m_ivl << std::endl;
    std::cout << "CIPHERTEXT: " << parseBytesToHexStr(data.m_out, data.m_outl)
              << " Len: " << data.m_outl << std::endl;
    return;
}

// FIXME: Reduce the dupication
// AEAD Version
inline void
PrintTestData(std::vector<Uint8> key, alcp_dca_ex_t data, std::string mode)
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
 * @param encDec (encryption or Decryption)
 * @param mode AES modes (CTR, OFB, CBC and CFB)
 * @param big_small Type (Big or Small) of test
 */
void
AesCrosstest(int               keySize,
             encDec_t          encDec,
             alc_cipher_mode_t mode,
             big_small_t       big_small)
{
    int         key_size = keySize;
    int         LOOP_START, MAX_LOOP, INC_LOOP;
    size_t      size = 1;
    std::string encDecStr, big_small_str;
    std::string modeStr = GetModeSTR(mode);
    Int32       ivl, tkeyl = 16;
    bool        ret       = false;
    Int32       IVL_START = 0, IVL_MAX = 0;
    // FIXME: Tag Length should not be hard coded
    const Uint64 tagLength = 16;
    bool         isxts     = (modeStr.compare("XTS") == 0);

    IVL_START = 16;
    IVL_MAX   = 16;

    if (encDec == ENCRYPT)
        encDecStr.assign("ENC");
    else
        encDecStr.assign("DEC");
    if (big_small == BIG)
        big_small_str.assign("BIG");
    else
        big_small_str.assign("SMALL");
    /* Request from others to validate openssl with ipp */
    CipherTestingCore* alcpTC = nullptr;
    if (oa_override) {
        alcpTC = new CipherTestingCore(OPENSSL, mode);
        printErrors("ALCP is overriden!... OpenSSL is now main lib");
        printErrors("ALCP is overriden!... Forcing IPP as extlib");
        useipp  = true;
        useossl = false;
    } else {
        alcpTC = new CipherTestingCore(ALCP, mode);
    }
    CipherTestingCore* extTC = nullptr;
    RngBase            rb;

    /* Set extTC based on which external testing core user asks*/
    try {
        if (useossl)
            extTC = new CipherTestingCore(OPENSSL, mode);
        else if (useipp)
            extTC = new CipherTestingCore(IPP, mode);
        else {
            printErrors("No Lib Specified!.. but trying OpenSSL");
            extTC = new CipherTestingCore(OPENSSL, mode);
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
    std::vector<Uint8> tkey_full = rb.genRandomBytes(key_size);

    std::vector<Uint8>::const_iterator pos1, pos2;

    auto rng = std::default_random_engine{};

    if (extTC != nullptr) {
        for (int i = LOOP_START; i < MAX_LOOP; i += INC_LOOP) {
            /* generate multiple iv and adl */
            ivl = IVL_START + (std::rand() % (IVL_START - IVL_MAX + 1));

            alcp_dc_ex_t data_alc, data_ext;

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

            tkey_full = ShuffleVector(tkey_full, rng);
            pos1      = tkey_full.begin();
            pos2      = tkey_full.begin() + (key_size / 8);
            std::vector<Uint8> tkey(pos1, pos2);

            // ALC/Main Lib Data
            data_alc.m_in   = &(pt[0]);
            data_alc.m_inl  = pt.size();
            data_alc.m_iv   = &(iv[0]);
            data_alc.m_ivl  = iv.size();
            data_alc.m_out  = &(out_ct_alc[0]);
            data_alc.m_outl = data_alc.m_inl;
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
            if (isxts) {
                data_ext.m_tkey       = &(tkey[0]);
                data_ext.m_tkeyl      = tkeyl;
                data_ext.m_block_size = ct.size();
            }

            if (encDec == ENCRYPT) {
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
                if (verbose > 1) {
                    PrintTestData(key, data_alc, modeStr);
                    PrintTestData(key, data_ext, modeStr);
                }
            } else {
                ret = alcpTC->getCipherHandler()->testingDecrypt(data_alc, key);
                if (!ret) {
                    std::cout << "ERROR: Dec: main lib" << std::endl;
                    FAIL();
                }

                ret = extTC->getCipherHandler()->testingDecrypt(data_ext, key);
                if (!ret) {
                    std::cout << "ERROR: Dec: ext lib" << std::endl;
                    FAIL();
                }

                ASSERT_TRUE(ArraysMatch(out_ct_alc, out_ct_ext));

                if (verbose > 1) {
                    PrintTestData(key, data_alc, modeStr);
                    PrintTestData(key, data_ext, modeStr);
                }
            }
        }
        delete extTC;
        delete alcpTC;
    }
}

// FIXME: In future we need a direct path to each aead modes
/**
 * @brief funtion to avoid repeated code in every cross test, can only be used
 * for AES-CTR,AES-CBC,AES-OFB,AES-CFB
 *
 * @param keySize keysize in bits(128,192 or 256)
 * @param encDec (encryption or Decryption)
 * @param mode AES modes (CTR, OFB, CBC and CFB)
 * @param big_small Type (Big or Small) of test
 */
void
AesAeadCrosstest(int               keySize,
                 encDec_t          encDec,
                 alc_cipher_mode_t mode,
                 big_small_t       big_small)
{
    int         key_size = keySize;
    int         LOOP_START, MAX_LOOP, INC_LOOP;
    size_t      size = 1;
    std::string encDecStr, big_small_str;
    std::string modeStr = GetModeSTR(mode);
    Int32       ivl, adl, tkeyl = 16;
    bool        ret       = false;
    Int32       IVL_START = 0, IVL_MAX = 0, ADL_START = 0, ADL_MAX = 0;
    // FIXME: Tag Length should not be hard coded
    const Uint64 tagLength = 16;

    bool isxts = (modeStr.compare("XTS") == 0);
    bool isgcm = (modeStr.compare("GCM") == 0);
    bool isccm = (modeStr.compare("CCM") == 0);
    bool issiv = (modeStr.compare("SIV") == 0);

    /* IV, AD Length limits for different cases */
    if (isccm) {
        IVL_START = 7;
        IVL_MAX   = 13;
        ADL_START = 12;
        ADL_MAX   = 16;
    } else if (issiv) {
        IVL_START = 16;
        IVL_MAX   = 16;
        ADL_START = 16;
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

    if (encDec == ENCRYPT)
        encDecStr.assign("ENC");
    else
        encDecStr.assign("DEC");
    if (big_small == BIG)
        big_small_str.assign("BIG");
    else
        big_small_str.assign("SMALL");
    /* Request from others to validate openssl with ipp */
    CipherAeadTestingCore* alcpTC = nullptr;
    if (oa_override) {
        alcpTC = new CipherAeadTestingCore(OPENSSL, mode);
        printErrors("ALCP is overriden!... OpenSSL is now main lib");
        printErrors("ALCP is overriden!... Forcing IPP as extlib");
        useipp  = true;
        useossl = false;
    } else {
        alcpTC = new CipherAeadTestingCore(ALCP, mode);
    }
    CipherAeadTestingCore* extTC = nullptr;
    RngBase                rb;

    /* Set extTC based on which external testing core user asks*/
    try {
        if (useossl)
            extTC = new CipherAeadTestingCore(OPENSSL, mode);
        else if (useipp)
            extTC = new CipherAeadTestingCore(IPP, mode);
        else {
            printErrors("No Lib Specified!.. but trying OpenSSL");
            extTC = new CipherAeadTestingCore(OPENSSL, mode);
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
            /* generate multiple iv and adl */
            ivl = IVL_START + (std::rand() % (IVL_START - IVL_MAX + 1));
            adl = ADL_START + (std::rand() % (ADL_MAX - ADL_START + 1));

            alcp_dca_ex_t data_alc, data_ext;

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

            // ALC/Main Lib Data
            data_alc.m_in   = &(pt[0]);
            data_alc.m_inl  = pt.size();
            data_alc.m_iv   = &(iv[0]);
            data_alc.m_ivl  = iv.size();
            data_alc.m_out  = &(out_ct_alc[0]);
            data_alc.m_outl = data_alc.m_inl;
            if (isgcm || isccm || issiv) {
                data_alc.m_ad      = &(add[0]);
                data_alc.m_adl     = add.size();
                data_alc.m_tag     = &(tag_alc[0]);
                data_alc.m_tagl    = tag_alc.size();
                data_alc.m_tagBuff = tagBuff.get();
            }
            if (isxts || issiv) {
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
            if (isgcm || isccm || issiv) {
                data_ext.m_ad      = &(add[0]);
                data_ext.m_adl     = add.size();
                data_ext.m_tag     = &(tag_ext[0]);
                data_ext.m_tagl    = tag_ext.size();
                data_ext.m_tagBuff = tagBuff.get();
            }
            if (isxts || issiv) {
                data_ext.m_tkey       = &(tkey[0]);
                data_ext.m_tkeyl      = tkeyl;
                data_ext.m_block_size = ct.size();
            }

            if (encDec == ENCRYPT) {
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
                    PrintTestData(key, data_alc, modeStr);
                    PrintTestData(key, data_ext, modeStr);
                }
            } else {
                if (isgcm || isccm || issiv) {
                    ret = alcpTC->getCipherHandler()->testingEncrypt(data_alc,
                                                                     key);
                    // TAG is IV for decrypt in SIV mode.
                    if (mode == ALC_AES_MODE_SIV) {
                        memcpy(&iv[0], &tag_alc[0], data_alc.m_tagl);
                    }
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
                if (isgcm || isccm || issiv) {
                    ret = alcpTC->getCipherHandler()->testingEncrypt(data_ext,
                                                                     key);
                    // TAG is IV for decrypt in SIV mode.
                    if (mode == ALC_AES_MODE_SIV) {
                        memcpy(&iv[0], &tag_ext[0], data_alc.m_tagl);
                    }
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
                } else if (!(isgcm || isccm)) {
                    ASSERT_TRUE(ArraysMatch(out_ct_alc, out_ct_ext));
                }
                if (verbose > 1) {
                    PrintTestData(key, data_alc, modeStr);
                    PrintTestData(key, data_ext, modeStr);
                }
            }
        }
        delete extTC;
        delete alcpTC;
    }
}

#ifndef ENABLE_RSP
/**
 * @brief Testing for non-aead based modes
 *
 * CBC, CFB, CTR, XTS, OFB
 *
 * @param testingCore
 * @param encDec
 * @param encDecStr
 * @param modeStr
 * @param keySize
 * @param isxts
 * @param isgcm
 * @return
 */
bool
RunCipherKatTest(CipherTestingCore& testingCore,
                 encDec_t           encDec,
                 std::string        encDecStr,
                 std::string        modeStr,
                 int                keySize)
{
    // FIXME: isxts and isgcm unused
    bool                 ret = false;
    alcp_dc_ex_t         data;
    std::shared_ptr<Csv> csv = testingCore.getCsv();
    std::vector<Uint8>   pt  = csv->getVect("PLAINTEXT");
    std::vector<Uint8>   ct  = csv->getVect("CIPHERTEXT");
    std::vector<Uint8>   outpt(pt.size(), 0);
    std::vector<Uint8>   outct(ct.size(), 0);
    std::vector<Uint8>   iv   = csv->getVect("INITVECT");
    std::vector<Uint8>   tkey = csv->getVect("TWEAK_KEY");

    if (encDec == ENCRYPT) {
        if (pt.size()) {
            data.m_in  = &(pt[0]);
            data.m_inl = pt.size();
        }
        data.m_iv  = &(iv[0]);
        data.m_ivl = iv.size();
        // XTS Specific
        data.m_tkey       = &(tkey[0]);
        data.m_tkeyl      = tkey.size();
        data.m_block_size = pt.size();
        if (outct.size())
            data.m_out = &(outct[0]);
        data.m_outl = data.m_inl;

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
                        std::string("AES_" + modeStr + "_"
                                    + std::to_string(keySize) + encDecStr)));
    } else {
        if (ct.size()) {
            data.m_in  = &(ct[0]);
            data.m_inl = ct.size();
        }
        data.m_iv  = &(iv[0]);
        data.m_ivl = iv.size();
        // XTS Specific
        data.m_tkey       = &(tkey[0]);
        data.m_tkeyl      = tkey.size();
        data.m_block_size = pt.size();
        if (outpt.size())
            data.m_out = &(outpt[0]);
        data.m_outl = data.m_inl;

        ret = testingCore.getCipherHandler()->testingDecrypt(
            data, csv->getVect("KEY"));
        if (!ret) {
            std::cout << "ERROR: Dec" << std::endl;
            EXPECT_TRUE(ret);
        }
        EXPECT_TRUE(
            ArraysMatch(outpt,
                        csv->getVect("PLAINTEXT"),
                        *(testingCore.getCsv()),
                        std::string("AES_" + modeStr + "_"
                                    + std::to_string(keySize) + encDecStr)));
    }
    return ret;
}
#else
bool
RunCipherKATTest(TestingCore& testingCore,
                 encDec_t encDec,
                 std::string encDecStr,
                 std::string modeStr,
                 int keySize,
                 bool isxts,
                 bool isgcm)
{
    bool ret = false;
    alcp_dc_ex_t data;
    std::shared_ptr<CRspParser> rsp = testingCore.getRsp();
    std::vector<Uint8> pt = rsp->getVect("PLAINTEXT");
    std::vector<Uint8> ct = rsp->getVect("CIPHERTEXT");
    std::vector<Uint8> outpt(pt.size(), 0);
    std::vector<Uint8> outct(ct.size(), 0);
    std::vector<Uint8> iv = rsp->getVect("INITVECT");
    std::vector<Uint8> tkey = rsp->getVect("TWEAK_KEY");

    if (encDec == ENCRYPT) {
        if (pt.size()) {
            data.m_in = &(pt[0]);
            data.m_inl = pt.size();
        }
        data.m_iv = &(iv[0]);
        data.m_ivl = iv.size();
        // XTS Specific
        data.m_tkey = &(tkey[0]);
        data.m_tkeyl = tkey.size();
        data.m_block_size = pt.size();
        if (outct.size())
            data.m_out = &(outct[0]);
        data.m_outl = data.m_inl;

        ret = testingCore.getCipherHandler()->testingEncrypt(
            data, rsp->getVect("KEY"));
        if (!ret) {
            std::cout << "ERROR: Enc" << std::endl;
            EXPECT_TRUE(ret);
        }
        EXPECT_TRUE(
            ArraysMatch(outct,
                        rsp->getVect("CIPHERTEXT"),
                        *(rsp.get()),
                        std::string("AES_" + modeStr + "_"
                                    + std::to_string(keySize) + encDecStr)));
    } else {
        if (ct.size()) {
            data.m_in = &(ct[0]);
            data.m_inl = ct.size();
        }
        data.m_iv = &(iv[0]);
        data.m_ivl = iv.size();
        // XTS Specific
        data.m_tkey = &(tkey[0]);
        data.m_tkeyl = tkey.size();
        data.m_block_size = pt.size();
        if (outpt.size())
            data.m_out = &(outpt[0]);
        data.m_outl = data.m_inl;

        ret = testingCore.getCipherHandler()->testingDecrypt(
            data, rsp->getVect("KEY"));
        if (!ret) {
            std::cout << "ERROR: Dec" << std::endl;
            EXPECT_TRUE(ret);
        }
        EXPECT_TRUE(
            ArraysMatch(outpt,
                        rsp->getVect("PLAINTEXT"),
                        *(testingCore.getRsp()),
                        std::string("AES_" + modeStr + "_"
                                    + std::to_string(keySize) + encDecStr)));
    }
    return ret;
}
#endif

bool
RunCipherAeadKATTest(CipherAeadTestingCore& testingCore,
                     encDec_t               encDec,
                     std::string            encDecStr,
                     std::string            modeStr,
                     int                    keySize,
                     bool                   isCcm,
                     bool                   isGcm)
{
    bool                 ret = false;
    alcp_dca_ex_t        data;
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
    std::vector<Uint8>   ctrkey  = csv->getVect("CTR_KEY");

    // Common Initialization
    data.m_tkeyl = 0;
    data.m_adl   = 0;
    data.m_tagl  = 0;
    if (isGcm) {
        if (outtag.size()) {
            if (encDec == ENCRYPT) {
                std::fill(outtag.begin(), outtag.end(), 0);
            }
            data.m_tag     = &(outtag[0]);
            data.m_tagl    = outtag.size();
            data.m_tagBuff = &tagBuff[0];
        }
        if (ad.size()) {
            data.m_ad  = &(ad[0]);
            data.m_adl = ad.size();
        }
    }
    if (isCcm && isGcm) {
        iv = csv->getVect("TAG"); // Let tag be IV (which is techically true
                                  // but not good idea)
    }
    if (encDec == ENCRYPT) {
        if (pt.size()) {
            data.m_in  = &(pt[0]);
            data.m_inl = pt.size();
        }
        data.m_iv  = &(iv[0]);
        data.m_ivl = iv.size();
        if (outct.size())
            data.m_out = &(outct[0]);
        data.m_outl = data.m_inl;
        if (isCcm && isGcm) {
            data.m_tkey  = &(ctrkey[0]);
            data.m_tkeyl = tkey.size();
        } else if (isCcm) {
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
                        std::string("AES_" + modeStr + "_"
                                    + std::to_string(keySize) + encDecStr)));

        if (isGcm || (isGcm && isCcm)) {
            EXPECT_TRUE(ArraysMatch(outtag,
                                    csv->getVect("TAG"),
                                    *(csv.get()),
                                    std::string("AES_" + modeStr + "_"
                                                + std::to_string(keySize)
                                                + encDecStr + "_TAG")));
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
        // FIXME: Ugly solution, this is SIV
        if (isCcm && isGcm) {
            data.m_tkey  = &(ctrkey[0]);
            data.m_tkeyl = tkey.size();
        } else if (isCcm) {
            data.m_tkey       = &(tkey[0]);
            data.m_tkeyl      = tkey.size();
            data.m_block_size = ct.size();
        }
        ret = testingCore.getCipherHandler()->testingDecrypt(
            data, csv->getVect("KEY"));
        if (isGcm && data.m_tagl == 0) {
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
                        std::string("AES_" + modeStr + "_"
                                    + std::to_string(keySize) + encDecStr)));
        // Enforce that no errors are reported from lib side.
        EXPECT_TRUE(ret);
    }
    return ret;
}

/**
 * @brief Function to run KAT for AES Schemes CTR,CFB,OFB,CBC,XTS
 *
 * @param keySize keysize in bits(128,192,256)
 * @param encDec enum for encryption or decryption
 * @param mode Aode of encryption/Decryption (CTR,CFB,OFB,CBC,XTS)
 */
void
AesKatTest(int keySize, encDec_t encDec, alc_cipher_mode_t mode)
{
    size_t            key_size = keySize;
    const std::string cModeStr = GetModeSTR(mode);
    std::string       encDecStr;

    if (encDec == ENCRYPT)
        encDecStr = "_ENC";
    else
        encDecStr = "_DEC";

    CipherTestingCore testing_core = CipherTestingCore(cModeStr, mode);

    bool retval = false;

#ifndef ENABLE_RSP
    /* check if file is valid */
    if (!testing_core.getCsv()->m_file_exists) {
        EXPECT_TRUE(retval);
    }

    while (testing_core.getCsv()->readNext()) {
        if ((testing_core.getCsv()->getVect("KEY").size() * 8) != key_size) {
            continue;
        }

        retval = RunCipherKatTest(
            testing_core, encDec, encDecStr, cModeStr, keySize);

        EXPECT_TRUE(retval);
    }
#else
    if (!testing_core.getRsp()->fileExists) {
        EXPECT_TRUE(retval);
    }

    while (testing_core.getRsp()->readNextTC()) {
        if ((testing_core.getRsp()->getVect("KEY").size() * 8) != key_size) {
            continue;
        }
        retval = RunCipherKATTest(testing_core,
                                  encDec,
                                  encDecStr,
                                  cModeStr,
                                  keySize,
                                  isxts || issiv,
                                  isgcm || isccm || issiv);
        EXPECT_TRUE(retval);
    }
#endif
}

/**
 * @brief Function to run KAT for AES Schemes CTR,CFB,OFB,CBC,XTS
 *
 * @param keySize keysize in bits(128,192,256)
 * @param encDec enum for encryption or decryption
 * @param mode Aode of encryption/Decryption (CTR,CFB,OFB,CBC,XTS)
 */
void
AesAeadKatTest(int keySize, encDec_t encDec, alc_cipher_mode_t mode)
{
    size_t            key_size = keySize;
    const std::string cModeStr = GetModeSTR(mode);
    std::string       encDecStr;
    bool              isxts = (cModeStr.compare("XTS") == 0);
    bool              isgcm = (cModeStr.compare("GCM") == 0);
    bool              isccm = (cModeStr.compare("CCM") == 0);
    bool              issiv = (cModeStr.compare("SIV") == 0);

    if (encDec == ENCRYPT)
        encDecStr = "_ENC";
    else
        encDecStr = "_DEC";

    CipherAeadTestingCore testing_core = CipherAeadTestingCore(cModeStr, mode);

    bool retval = false;

    /* check if file is valid */
    if (!testing_core.getCsv()->m_file_exists) {
        EXPECT_TRUE(retval);
    }
    while (testing_core.getCsv()->readNext()) {
        if ((testing_core.getCsv()->getVect("KEY").size() * 8) != key_size) {
            continue;
        }
        // FIXME: Cipher Needs to be changed to AES as its only AES
        retval = RunCipherAeadKATTest(testing_core,
                                      encDec,
                                      encDecStr,
                                      cModeStr,
                                      keySize,
                                      isxts || issiv, // FIXME: Not good design
                                      isgcm || isccm || issiv);
        EXPECT_TRUE(retval);
    }
}

#endif