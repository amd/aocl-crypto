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

/**
 * @brief Comparing ALCP's output to another external liberary
 *
 * Mandatory Dependances: alcp-cipher,alcp-rng,openssl/ipp (one of them needs to
 * be present)
 *
 */

#include "cipher/alc_base.hh"
#include "cipher/base.hh"
#include "cipher/gtest_base.hh"
#include "rng_base.hh"

using namespace alcp::testing;

ExecRecPlay* fr = nullptr;

#define ALC_MODE ALC_AES_MODE_XTS
#define STR_MODE "AES_XTS"
// Below in bytes
#define SMALL_MAX_LOOP   160000
#define SMALL_INC_LOOP   16
#define SMALL_START_LOOP 16
// Below in 0.1MB size
#define BIG_MAX_LOOP   2
#define BIG_INC_LOOP   1
#define BIG_START_LOOP 1

/* Testing Starts Here! */
TEST(SYMMETRIC_DEC_128, 128_CROSS_CHECK_BIG)
{
    int key_size = 128;

    // Request from others to validate openssl with ipp
    // TODO: Upgrade flight recorder
    TestingCore* alcpTC = nullptr;
    if (oa_override) {
        alcpTC = new TestingCore(OPENSSL, ALC_MODE);
        printErrors("ALCP is overriden!... OpenSSL is now main lib");
        printErrors("ALCP is overriden!... Forcing IPP as extlib");
        useipp  = true;
        useossl = false;
    } else {
        alcpTC = new TestingCore(ALCP, ALC_MODE);
    }
    TestingCore* extTC = nullptr;
    RngBase      rb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string(STR_MODE) + "_DEC_128_BIG",
                             std::string(STR_MODE) + "_TEST_DATA",
                             true);
        fr->fastForward(SMALL_ENC);
    } else
        fr = new ExecRecPlay(std::string(STR_MODE) + "_DEC_128_BIG",
                             std::string(STR_MODE) + "_TEST_DATA",
                             false);

    // Set extTC based on which external testing core user asks
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!.. but trying OpenSSL");
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }

    int max_loop   = BIG_MAX_LOOP;
    int start_loop = BIG_START_LOOP;
    int inc_loop   = SMALL_INC_LOOP;

    if (extTC != nullptr) {
        for (int i = start_loop; i < max_loop; i += inc_loop) {
            /* max size supported by XTS is 2 ^ 20 = 1048576 */
            size_t size = 524288 * i;

            if (!bbxreplay)
                fr->startRecEvent();
            alcp_data_ex_t       data_alc, data_ext;
            std::vector<uint8_t> ct(size, 0), key(key_size / 8, 0),
                tkey(key_size / 8, 0), iv(12, 0), out_pt_alc(size, 0),
                out_pt_ext(size, 0);
            if (!bbxreplay) {
                ct   = rb.genRandomBytes(size);
                key  = rb.genRandomBytes(key_size / 8);
                tkey = rb.genRandomBytes(key_size / 8);
                iv   = rb.genRandomBytes(12);

                // ALC/Main Lib Data
                data_alc.in    = &(ct[0]);
                data_alc.inl   = ct.size();
                data_alc.iv    = &(iv[0]);
                data_alc.ivl   = iv.size();
                data_alc.out   = &(out_pt_alc[0]);
                data_alc.outl  = data_alc.inl;
                data_alc.tkey  = &(tkey[0]);
                data_alc.tkeyl = 16;
                data_alc.tagl  = 0;
                data_alc.adl   = 0;

                // External Lib Data
                data_ext.in         = &(ct[0]);
                data_ext.inl        = ct.size();
                data_ext.iv         = &(iv[0]);
                data_ext.ivl        = iv.size();
                data_ext.out        = &(out_pt_ext[0]);
                data_ext.outl       = data_alc.inl;
                data_ext.tkey       = &(tkey[0]);
                data_ext.tkeyl      = 16;
                data_ext.block_size = ct.size();
                data_ext.tagl       = 0;
                data_ext.adl        = 0;

                fr->setRecEvent(key, iv, ct, BIG_DEC);
            } else {
                fr->nextLog();
                try {
                    fr->getValues(&key, &iv, &ct);
                } catch (std::string excp) {
                    std::cout << excp << std::endl;
                    exit(-1);
                }
            }
            alcpTC->getCipherHandler()->testingDecrypt(data_alc, key);
            extTC->getCipherHandler()->testingDecrypt(data_ext, key);
            ASSERT_TRUE(ArraysMatch(out_pt_alc, out_pt_ext));

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

TEST(SYMMETRIC_ENC_128, 128_CROSS_CHECK_BIG)
{
    int key_size = 128;

    // Request from others to validate openssl with ipp
    // TODO: Upgrade flight recorder
    TestingCore* alcpTC = nullptr;
    if (oa_override) {
        alcpTC = new TestingCore(OPENSSL, ALC_MODE);
        printErrors("ALCP is overriden!... OpenSSL is now main lib");
        printErrors("ALCP is overriden!... Forcing IPP as extlib");
        useipp  = true;
        useossl = false;
    } else {
        alcpTC = new TestingCore(ALCP, ALC_MODE);
    }
    TestingCore* extTC = nullptr;
    RngBase      rb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string(STR_MODE) + "_DEC_128_BIG",
                             std::string(STR_MODE) + "_TEST_DATA",
                             true);
        fr->fastForward(SMALL_ENC);
    } else
        fr = new ExecRecPlay(std::string(STR_MODE) + "_DEC_128_BIG",
                             std::string(STR_MODE) + "_TEST_DATA",
                             false);

    // Set extTC based on which external testing core user asks
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!.. but trying OpenSSL");
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }

    int max_loop   = BIG_MAX_LOOP;
    int start_loop = BIG_START_LOOP;
    int inc_loop   = SMALL_INC_LOOP;

    if (extTC != nullptr) {
        for (int i = start_loop; i < max_loop; i += inc_loop) {
            /* max size supported by XTS is 2 ^ 20 = 1048576 */
            size_t size = 524288 * i;

            if (!bbxreplay)
                fr->startRecEvent();
            alcp_data_ex_t       data_alc, data_ext;
            std::vector<uint8_t> pt(size, 0), key(key_size / 8, 0),
                tkey(key_size / 8, 0), iv(12, 0), out_ct_alc(size, 0),
                out_ct_ext(size, 0);
            if (!bbxreplay) {
                pt   = rb.genRandomBytes(size);
                key  = rb.genRandomBytes(key_size / 8);
                tkey = rb.genRandomBytes(key_size / 8);
                iv   = rb.genRandomBytes(12);

                // ALC/Main Lib Data
                data_alc.in    = &(pt[0]);
                data_alc.inl   = pt.size();
                data_alc.iv    = &(iv[0]);
                data_alc.ivl   = iv.size();
                data_alc.out   = &(out_ct_alc[0]);
                data_alc.outl  = data_alc.inl;
                data_alc.tkey  = &(tkey[0]);
                data_alc.tkeyl = 16;
                data_alc.tagl  = 0;
                data_alc.adl   = 0;

                // External Lib Data
                data_ext.in         = &(pt[0]);
                data_ext.inl        = pt.size();
                data_ext.iv         = &(iv[0]);
                data_ext.ivl        = iv.size();
                data_ext.out        = &(out_ct_ext[0]);
                data_ext.outl       = data_alc.inl;
                data_ext.tkey       = &(tkey[0]);
                data_ext.tkeyl      = 16;
                data_ext.block_size = pt.size();
                data_ext.tagl       = 0;
                data_ext.adl        = 0;

                fr->setRecEvent(key, iv, pt, BIG_ENC);
            } else {
                fr->nextLog();
                try {
                    fr->getValues(&key, &iv, &pt);
                } catch (std::string excp) {
                    std::cout << excp << std::endl;
                    exit(-1);
                }
            }
            alcpTC->getCipherHandler()->testingEncrypt(data_alc, key);
            extTC->getCipherHandler()->testingEncrypt(data_ext, key);
            ASSERT_TRUE(ArraysMatch(out_ct_alc, out_ct_ext));

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

TEST(SYMMETRIC_ENC_256, 256_CROSS_CHECK_BIG)
{
    int key_size = 256;

    // Request from others to validate openssl with ipp
    // TODO: Upgrade flight recorder
    TestingCore* alcpTC = nullptr;
    if (oa_override) {
        alcpTC = new TestingCore(OPENSSL, ALC_MODE);
        printErrors("ALCP is overriden!... OpenSSL is now main lib");
        printErrors("ALCP is overriden!... Forcing IPP as extlib");
        useipp  = true;
        useossl = false;
    } else {
        alcpTC = new TestingCore(ALCP, ALC_MODE);
    }
    TestingCore* extTC = nullptr;
    RngBase      rb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string(STR_MODE) + "_ENC_256_BIG",
                             std::string(STR_MODE) + "_TEST_DATA",
                             true);
        fr->fastForward(BIG_ENC);
    } else
        fr = new ExecRecPlay(std::string(STR_MODE) + "_ENC_256_BIG",
                             std::string(STR_MODE) + "_TEST_DATA",
                             false);

    // Set extTC based on which external testing core user asks
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!.. but trying OpenSSL");
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }

    int max_loop   = BIG_MAX_LOOP;
    int start_loop = BIG_START_LOOP;
    int inc_loop   = SMALL_INC_LOOP;

    if (extTC != nullptr) {
        for (int i = start_loop; i < max_loop; i += inc_loop) {
            /* max size supported by XTS is 2 ^ 20 = 1048576 */
            size_t size = 524288 * i;

            if (!bbxreplay)
                fr->startRecEvent();
            alcp_data_ex_t       data_alc, data_ext;
            std::vector<uint8_t> pt(size, 0), key(key_size / 8, 0),
                tkey(key_size / 8, 0), iv(12, 0), out_ct_alc(size, 0),
                out_ct_ext(size, 0);
            if (!bbxreplay) {
                pt   = rb.genRandomBytes(size);
                key  = rb.genRandomBytes(key_size / 8);
                tkey = rb.genRandomBytes(key_size / 8);
                iv   = rb.genRandomBytes(12);

                // ALC/Main Lib Data
                data_alc.in    = &(pt[0]);
                data_alc.inl   = pt.size();
                data_alc.iv    = &(iv[0]);
                data_alc.ivl   = iv.size();
                data_alc.out   = &(out_ct_alc[0]);
                data_alc.outl  = data_alc.inl;
                data_alc.tkey  = &(tkey[0]);
                data_alc.tkeyl = 16;
                data_alc.tagl  = 0;
                data_alc.adl   = 0;

                // External Lib Data
                data_ext.in         = &(pt[0]);
                data_ext.inl        = pt.size();
                data_ext.iv         = &(iv[0]);
                data_ext.ivl        = iv.size();
                data_ext.out        = &(out_ct_ext[0]);
                data_ext.outl       = data_alc.inl;
                data_ext.tkey       = &(tkey[0]);
                data_ext.tkeyl      = 16;
                data_ext.block_size = pt.size();
                data_ext.tagl       = 0;
                data_ext.adl        = 0;

                fr->setRecEvent(key, iv, pt, BIG_ENC);
            } else {
                fr->nextLog();
                try {
                    fr->getValues(&key, &iv, &pt);
                } catch (std::string excp) {
                    std::cout << excp << std::endl;
                    exit(-1);
                }
            }
            alcpTC->getCipherHandler()->testingEncrypt(data_alc, key);
            extTC->getCipherHandler()->testingEncrypt(data_ext, key);
            ASSERT_TRUE(ArraysMatch(out_ct_alc, out_ct_ext));

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

TEST(SYMMETRIC_DEC_256, 256_CROSS_CHECK_BIG)
{
    int key_size = 256;

    // Request from others to validate openssl with ipp
    // TODO: Upgrade flight recorder
    TestingCore* alcpTC = nullptr;
    if (oa_override) {
        alcpTC = new TestingCore(OPENSSL, ALC_MODE);
        printErrors("ALCP is overriden!... OpenSSL is now main lib");
        printErrors("ALCP is overriden!... Forcing IPP as extlib");
        useipp  = true;
        useossl = false;
    } else {
        alcpTC = new TestingCore(ALCP, ALC_MODE);
    }
    TestingCore* extTC = nullptr;
    RngBase      rb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string(STR_MODE) + "_DEC_256_BIG",
                             std::string(STR_MODE) + "_TEST_DATA",
                             true);
        fr->fastForward(BIG_DEC);
    } else
        fr = new ExecRecPlay(std::string(STR_MODE) + "_DEC_256_BIG",
                             std::string(STR_MODE) + "_TEST_DATA",
                             false);

    // Set extTC based on which external testing core user asks
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!.. but trying OpenSSL");
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }

    int max_loop   = BIG_MAX_LOOP;
    int start_loop = BIG_START_LOOP;
    int inc_loop   = SMALL_INC_LOOP;

    if (extTC != nullptr) {
        for (int i = start_loop; i < max_loop; i += inc_loop) {
            /* max size supported by XTS is 2 ^ 20 = 1048576 */
            size_t size = 524288 * i;

            if (!bbxreplay)
                fr->startRecEvent();
            alcp_data_ex_t       data_alc, data_ext;
            std::vector<uint8_t> ct(size, 0), key(key_size / 8, 0),
                tkey(key_size / 8, 0), iv(12, 0), out_pt_alc(size, 0),
                out_pt_ext(size, 0);
            if (!bbxreplay) {
                ct   = rb.genRandomBytes(size);
                key  = rb.genRandomBytes(key_size / 8);
                tkey = rb.genRandomBytes(key_size / 8);
                iv   = rb.genRandomBytes(12);

                // ALC/Main Lib Data
                data_alc.in    = &(ct[0]);
                data_alc.inl   = ct.size();
                data_alc.iv    = &(iv[0]);
                data_alc.ivl   = iv.size();
                data_alc.out   = &(out_pt_alc[0]);
                data_alc.outl  = data_alc.inl;
                data_alc.tkey  = &(tkey[0]);
                data_alc.tkeyl = 16;
                data_alc.tagl  = 0;
                data_alc.adl   = 0;

                // External Lib Data
                data_ext.in         = &(ct[0]);
                data_ext.inl        = ct.size();
                data_ext.iv         = &(iv[0]);
                data_ext.ivl        = iv.size();
                data_ext.out        = &(out_pt_ext[0]);
                data_ext.outl       = data_alc.inl;
                data_ext.tkey       = &(tkey[0]);
                data_ext.tkeyl      = 16;
                data_ext.block_size = ct.size();
                data_ext.tagl       = 0;
                data_ext.adl        = 0;

                fr->setRecEvent(key, iv, ct, BIG_DEC);
            } else {
                fr->nextLog();
                try {
                    fr->getValues(&key, &iv, &ct);
                } catch (std::string excp) {
                    std::cout << excp << std::endl;
                    exit(-1);
                }
            }
            alcpTC->getCipherHandler()->testingDecrypt(data_alc, key);
            extTC->getCipherHandler()->testingDecrypt(data_ext, key);
            ASSERT_TRUE(ArraysMatch(out_pt_alc, out_pt_ext));

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

TEST(SYMMETRIC_ENC_128, 128_CROSS_CHECK_SMALL)
{
    int key_size = 128;

    // Request from others to validate openssl with ipp
    // TODO: Upgrade flight recorder
    TestingCore* alcpTC = nullptr;
    if (oa_override) {
        alcpTC = new TestingCore(OPENSSL, ALC_MODE);
        printErrors("ALCP is overriden!... OpenSSL is now main lib");
        printErrors("ALCP is overriden!... Forcing IPP as extlib");
        useipp  = true;
        useossl = false;
    } else {
        alcpTC = new TestingCore(ALCP, ALC_MODE);
    }
    TestingCore* extTC = nullptr;
    RngBase      rb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string(STR_MODE) + "_ENC_128_SMALL",
                             std::string(STR_MODE) + "_TEST_DATA",
                             true);
        fr->fastForward(SMALL_ENC);
    } else
        fr = new ExecRecPlay(std::string(STR_MODE) + "_ENC_128_SMALL",
                             std::string(STR_MODE) + "_TEST_DATA",
                             false);

    // Set extTC based on which external testing core user asks
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!.. but trying OpenSSL");
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }

    int max_loop = SMALL_MAX_LOOP;

    if (useipp) {
        max_loop = 32;
    }
    if (extTC != nullptr) {
        for (int i = SMALL_START_LOOP; i < max_loop; i += SMALL_INC_LOOP) {
            if (!bbxreplay)
                fr->startRecEvent();
            alcp_data_ex_t       data_alc, data_ext;
            std::vector<uint8_t> pt(i, 0), key(key_size / 8, 0),
                tkey(key_size / 8, 0), iv(12, 0), add, out_ct_alc(i, 0),
                out_ct_ext(i, 0);
            if (!bbxreplay) {
                pt   = rb.genRandomBytes(i);
                key  = rb.genRandomBytes(key_size / 8);
                tkey = rb.genRandomBytes(key_size / 8);
                iv   = rb.genRandomBytes(12);

                // ALC/Main Lib Data
                data_alc.in    = &(pt[0]);
                data_alc.inl   = pt.size();
                data_alc.iv    = &(iv[0]);
                data_alc.ivl   = iv.size();
                data_alc.out   = &(out_ct_alc[0]);
                data_alc.outl  = data_alc.inl;
                data_alc.tkey  = &(tkey[0]);
                data_alc.tkeyl = 16;
                data_alc.tagl  = 0;
                data_alc.adl   = 0;

                // External Lib Data
                data_ext.in         = &(pt[0]);
                data_ext.inl        = pt.size();
                data_ext.iv         = &(iv[0]);
                data_ext.ivl        = iv.size();
                data_ext.out        = &(out_ct_ext[0]);
                data_ext.outl       = data_alc.inl;
                data_ext.tkey       = &(tkey[0]);
                data_ext.tkeyl      = 16;
                data_ext.block_size = pt.size();
                data_ext.tagl       = 0;
                data_ext.adl        = 0;

                fr->setRecEvent(key, iv, pt, SMALL_ENC);
            } else {
                fr->nextLog();
                try {
                    fr->getValues(&key, &iv, &pt);
                } catch (std::string excp) {
                    std::cout << excp << std::endl;
                    exit(-1);
                }
            }
            alcpTC->getCipherHandler()->testingEncrypt(data_alc, key);
            extTC->getCipherHandler()->testingEncrypt(data_ext, key);
            ASSERT_TRUE(ArraysMatch(out_ct_alc, out_ct_ext));

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

TEST(SYMMETRIC_DEC_128, 128_CROSS_CHECK_SMALL)
{
    int key_size = 128;

    // Request from others to validate openssl with ipp
    // TODO: Upgrade flight recorder
    TestingCore* alcpTC = nullptr;
    if (oa_override) {
        alcpTC = new TestingCore(OPENSSL, ALC_MODE);
        printErrors("ALCP is overriden!... OpenSSL is now main lib");
        printErrors("ALCP is overriden!... Forcing IPP as extlib");
        useipp  = true;
        useossl = false;
    } else {
        alcpTC = new TestingCore(ALCP, ALC_MODE);
    }
    TestingCore* extTC = nullptr;
    RngBase      rb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string(STR_MODE) + "_DEC_128_SMALL",
                             std::string(STR_MODE) + "_TEST_DATA",
                             true);
        fr->fastForward(SMALL_DEC);
    } else
        fr = new ExecRecPlay(std::string(STR_MODE) + "_DEC_128_SMALL",
                             std::string(STR_MODE) + "_TEST_DATA",
                             false);

    // Set extTC based on which external testing core user asks
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!.. but trying OpenSSL");
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }

    int max_loop = SMALL_MAX_LOOP;

    /*FIXME Need to update this for ippcp */
    if (useipp) {
        max_loop = 32;
    }
    if (extTC != nullptr) {
        for (int i = SMALL_START_LOOP; i < max_loop; i += SMALL_INC_LOOP) {
            if (!bbxreplay)
                fr->startRecEvent();
            alcp_data_ex_t       data_alc, data_ext;
            std::vector<uint8_t> ct(i, 0), key(key_size / 8, 0),
                tkey(key_size / 8, 0), iv(12, 0), out_pt_alc(i, 0),
                out_pt_ext(i, 0);
            // FIXME: There is some uninitialized problem with out_pt
            if (!bbxreplay) {
                ct   = rb.genRandomBytes(i);
                key  = rb.genRandomBytes(key_size / 8);
                tkey = rb.genRandomBytes(key_size / 8);
                iv   = rb.genRandomBytes(12);

                // ALC/Main Lib Data
                data_alc.in    = &(ct[0]);
                data_alc.inl   = ct.size();
                data_alc.iv    = &(iv[0]);
                data_alc.ivl   = iv.size();
                data_alc.out   = &(out_pt_alc[0]);
                data_alc.outl  = data_alc.inl;
                data_alc.tkey  = &(tkey[0]);
                data_alc.tkeyl = 16;
                data_alc.tagl  = 0;
                data_alc.adl   = 0;

                // External Lib Data
                data_ext.in         = &(ct[0]);
                data_ext.inl        = ct.size();
                data_ext.iv         = &(iv[0]);
                data_ext.ivl        = iv.size();
                data_ext.out        = &(out_pt_ext[0]);
                data_ext.outl       = data_alc.inl;
                data_ext.tkey       = &(tkey[0]);
                data_ext.tkeyl      = 16;
                data_ext.block_size = ct.size();
                data_ext.tagl       = 0;
                data_ext.adl        = 0;

                fr->setRecEvent(key, iv, ct, SMALL_DEC);
            } else {
                fr->nextLog();
                try {
                    fr->getValues(&key, &iv, &ct);
                } catch (std::string excp) {
                    std::cout << excp << std::endl;
                    exit(-1);
                }
            }
            alcpTC->getCipherHandler()->testingDecrypt(data_alc, key);
            extTC->getCipherHandler()->testingDecrypt(data_ext, key);
            ASSERT_TRUE(ArraysMatch(out_pt_alc, out_pt_ext));

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

TEST(SYMMETRIC_ENC_256, 256_CROSS_CHECK_SMALL)
{
    int key_size = 256;

    // Request from others to validate openssl with ipp
    // TODO: Upgrade flight recorder
    TestingCore* alcpTC = nullptr;
    if (oa_override) {
        alcpTC = new TestingCore(OPENSSL, ALC_MODE);
        printErrors("ALCP is overriden!... OpenSSL is now main lib");
        printErrors("ALCP is overriden!... Forcing IPP as extlib");
        useipp  = true;
        useossl = false;
    } else {
        alcpTC = new TestingCore(ALCP, ALC_MODE);
    }
    TestingCore* extTC = nullptr;
    RngBase      rb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string(STR_MODE) + "_ENC_256_SMALL",
                             std::string(STR_MODE) + "_TEST_DATA",
                             true);
        fr->fastForward(SMALL_ENC);
    } else
        fr = new ExecRecPlay(std::string(STR_MODE) + "_ENC_256_SMALL",
                             std::string(STR_MODE) + "_TEST_DATA",
                             false);

    // Set extTC based on which external testing core user asks
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!.. but trying OpenSSL");
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }

    int max_loop = SMALL_MAX_LOOP;

    /*FIXME Need to update this for ippcp */
    if (useipp) {
        max_loop = 32;
    }
    if (extTC != nullptr) {
        for (int i = SMALL_START_LOOP; i < max_loop; i += SMALL_INC_LOOP) {
            if (!bbxreplay)
                fr->startRecEvent();
            alcp_data_ex_t       data_alc, data_ext;
            std::vector<uint8_t> pt(i, 0), key(key_size / 8, 0),
                tkey(key_size / 8, 0), iv(12, 0), add, out_ct_alc(i, 0),
                out_ct_ext(i, 0);
            if (!bbxreplay) {
                pt   = rb.genRandomBytes(i);
                key  = rb.genRandomBytes(key_size / 8);
                tkey = rb.genRandomBytes(key_size / 8);
                iv   = rb.genRandomBytes(12);

                // ALC/Main Lib Data
                data_alc.in    = &(pt[0]);
                data_alc.inl   = pt.size();
                data_alc.iv    = &(iv[0]);
                data_alc.ivl   = iv.size();
                data_alc.out   = &(out_ct_alc[0]);
                data_alc.outl  = data_alc.inl;
                data_alc.tkey  = &(tkey[0]);
                data_alc.tkeyl = 16;
                data_alc.tagl  = 0;
                data_alc.adl   = 0;

                // External Lib Data
                data_ext.in         = &(pt[0]);
                data_ext.inl        = pt.size();
                data_ext.iv         = &(iv[0]);
                data_ext.ivl        = iv.size();
                data_ext.out        = &(out_ct_ext[0]);
                data_ext.outl       = data_alc.inl;
                data_ext.tkey       = &(tkey[0]);
                data_ext.tkeyl      = 16;
                data_ext.block_size = pt.size();
                data_ext.tagl       = 0;
                data_ext.adl        = 0;

                fr->setRecEvent(key, iv, pt, SMALL_ENC);
            } else {
                fr->nextLog();
                try {
                    fr->getValues(&key, &iv, &pt);
                } catch (std::string excp) {
                    std::cout << excp << std::endl;
                    exit(-1);
                }
            }
            alcpTC->getCipherHandler()->testingEncrypt(data_alc, key);
            extTC->getCipherHandler()->testingEncrypt(data_ext, key);
            ASSERT_TRUE(ArraysMatch(out_ct_alc, out_ct_ext));

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

TEST(SYMMETRIC_DEC_256, 256_CROSS_CHECK_SMALL)
{
    int key_size = 256;

    // Request from others to validate openssl with ipp
    // TODO: Upgrade flight recorder
    TestingCore* alcpTC = nullptr;
    if (oa_override) {
        alcpTC = new TestingCore(OPENSSL, ALC_MODE);
        printErrors("ALCP is overriden!... OpenSSL is now main lib");
        printErrors("ALCP is overriden!... Forcing IPP as extlib");
        useipp  = true;
        useossl = false;
    } else {
        alcpTC = new TestingCore(ALCP, ALC_MODE);
    }
    TestingCore* extTC = nullptr;
    RngBase      rb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string(STR_MODE) + "_DEC_256_SMALL",
                             std::string(STR_MODE) + "_TEST_DATA",
                             true);
        fr->fastForward(SMALL_ENC);
    } else
        fr = new ExecRecPlay(std::string(STR_MODE) + "_DEC_256_SMALL",
                             std::string(STR_MODE) + "_TEST_DATA",
                             false);

    // Set extTC based on which external testing core user asks
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!.. but trying OpenSSL");
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }

    int max_loop = SMALL_MAX_LOOP;

    /*FIXME Need to update this for ippcp */
    if (useipp) {
        max_loop = 32;
    }
    if (extTC != nullptr) {
        for (int i = SMALL_START_LOOP; i < max_loop; i += SMALL_INC_LOOP) {
            if (!bbxreplay)
                fr->startRecEvent();
            alcp_data_ex_t       data_alc, data_ext;
            std::vector<uint8_t> ct(i, 0), key(key_size / 8, 0),
                tkey(key_size / 8, 0), iv(12, 0), add, out_pt_alc(i, 0),
                out_pt_ext(i, 0);
            if (!bbxreplay) {
                ct   = rb.genRandomBytes(i);
                key  = rb.genRandomBytes(key_size / 8);
                tkey = rb.genRandomBytes(key_size / 8);
                iv   = rb.genRandomBytes(12);

                // ALC/Main Lib Data
                data_alc.in    = &(ct[0]);
                data_alc.inl   = ct.size();
                data_alc.iv    = &(iv[0]);
                data_alc.ivl   = iv.size();
                data_alc.out   = &(out_pt_alc[0]);
                data_alc.outl  = data_alc.inl;
                data_alc.tkey  = &(tkey[0]);
                data_alc.tkeyl = 16;
                data_alc.tagl  = 0;
                data_alc.adl   = 0;

                // External Lib Data
                data_ext.in         = &(ct[0]);
                data_ext.inl        = ct.size();
                data_ext.iv         = &(iv[0]);
                data_ext.ivl        = iv.size();
                data_ext.out        = &(out_pt_ext[0]);
                data_ext.outl       = data_alc.inl;
                data_ext.tkey       = &(tkey[0]);
                data_ext.tkeyl      = 16;
                data_ext.block_size = ct.size();
                data_ext.tagl       = 0;
                data_ext.adl        = 0;

                fr->setRecEvent(key, iv, ct, SMALL_DEC);
            } else {
                fr->nextLog();
                try {
                    fr->getValues(&key, &iv, &ct);
                } catch (std::string excp) {
                    std::cout << excp << std::endl;
                    exit(-1);
                }
            }
            alcpTC->getCipherHandler()->testingDecrypt(data_alc, key);
            extTC->getCipherHandler()->testingDecrypt(data_ext, key);
            ASSERT_TRUE(ArraysMatch(out_pt_alc, out_pt_ext));

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
/* end of list of tests */

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    testing::TestEventListeners& listeners =
        testing::UnitTest::GetInstance()->listeners();
    parseArgs(argc, argv);
    auto default_printer =
        listeners.Release(listeners.default_result_printer());

    ConfigurableEventListener* listener =
        new ConfigurableEventListener(default_printer);

    listener->showEnvironment    = true;
    listener->showTestCases      = true;
    listener->showTestNames      = true;
    listener->showSuccesses      = true;
    listener->showInlineFailures = true;
    listeners.Append(listener);
    return RUN_ALL_TESTS();
}
