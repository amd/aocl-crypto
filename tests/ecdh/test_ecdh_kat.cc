/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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

#include "alcp/alcp.h"
#include "alcp/utils/cpuid.hh"
#include "ecdh/alc_ecdh.hh"
#include "ecdh/ecdh.hh"
#include "ecdh/gtest_base_ecdh.hh"
#include "string.h"
#include <exception>
#include <iostream>
#include <vector>

using alcp::utils::CpuId;

/*
 * Negative length tests: buffers sized to claimed len so guard regression
 * triggers ASan, not just a failed EXPECT. cSentinel detects silent writes
 * without a sanitizer. pubKeySize: 64 (P-256) vs 32 (Curve25519).
 */
static constexpr Uint64 cUndersizedKeyLen = 16;
static constexpr Uint64 cOversizedKeyLen  = ECDH_KEYSIZE * 2;

static constexpr Uint8 cSentinel = 0xcd;

static void
ecdh_set_privatekey_bad_length(alc_ec_info_t info)
{
    std::vector<Uint8> context(alcp_ec_context_size(&info));
    alc_ec_handle_t    handle{};
    handle.context = context.data();

    ASSERT_FALSE(alcp_is_error(alcp_ec_request(&info, &handle)));

    std::vector<Uint8> short_key(cUndersizedKeyLen, 0xab);
    alc_error_t        err =
        alcp_ec_set_privatekey(&handle, &short_key[0], short_key.size());
    EXPECT_TRUE(alcp_is_error(err));
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);

    std::vector<Uint8> long_key(cOversizedKeyLen, 0xab);
    err = alcp_ec_set_privatekey(&handle, &long_key[0], long_key.size());
    EXPECT_TRUE(alcp_is_error(err));
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);

    alcp_ec_finish(&handle);
}

static void
ecdh_get_publickey_bad_length(alc_ec_info_t info)
{
    std::vector<Uint8> context(alcp_ec_context_size(&info));
    alc_ec_handle_t    handle{};
    handle.context = context.data();

    ASSERT_FALSE(alcp_is_error(alcp_ec_request(&info, &handle)));

    std::vector<Uint8> priv_key(ECDH_KEYSIZE, 0xab);
    std::vector<Uint8> pub_key(ECDH_KEYSIZE);

    std::vector<Uint8> short_priv_key(cUndersizedKeyLen, 0xab);
    alc_error_t        err = alcp_ec_get_publickey(&handle,
                                            &pub_key[0],
                                            pub_key.size(),
                                            &short_priv_key[0],
                                            short_priv_key.size());
    EXPECT_TRUE(alcp_is_error(err));
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);

    std::vector<Uint8> short_pub_key(cUndersizedKeyLen);
    err = alcp_ec_get_publickey(&handle,
                                &short_pub_key[0],
                                short_pub_key.size(),
                                &priv_key[0],
                                priv_key.size());
    EXPECT_TRUE(alcp_is_error(err));
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);

    alcp_ec_finish(&handle);
}

static void
ecdh_get_secretkey_bad_length(alc_ec_info_t info, Uint64 pubKeySize)
{
    std::vector<Uint8> context(alcp_ec_context_size(&info));
    alc_ec_handle_t    handle{};
    handle.context = context.data();

    ASSERT_FALSE(alcp_is_error(alcp_ec_request(&info, &handle)));

    std::vector<Uint8> priv_key(ECDH_KEYSIZE, 0xab);
    ASSERT_FALSE(alcp_is_error(
        alcp_ec_set_privatekey(&handle, &priv_key[0], priv_key.size())));

    const std::vector<Uint8> cUntouched(ECDH_KEYSIZE, cSentinel);

    std::vector<Uint8> pub_key(pubKeySize, 0xab);
    std::vector<Uint8> secret_key(ECDH_KEYSIZE, cSentinel);
    Uint64             key_length = 0;

    std::vector<Uint8> short_pub_key(cUndersizedKeyLen, 0xab);
    alc_error_t        err = alcp_ec_get_secretkey(&handle,
                                            &secret_key[0],
                                            secret_key.size(),
                                            &short_pub_key[0],
                                            short_pub_key.size(),
                                            &key_length);
    EXPECT_TRUE(alcp_is_error(err));
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
    EXPECT_EQ(secret_key, cUntouched);

    std::vector<Uint8> long_pub_key(pubKeySize + 1, 0xab);
    err = alcp_ec_get_secretkey(&handle,
                                &secret_key[0],
                                secret_key.size(),
                                &long_pub_key[0],
                                long_pub_key.size(),
                                &key_length);
    EXPECT_TRUE(alcp_is_error(err));
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
    EXPECT_EQ(secret_key, cUntouched);

    std::vector<Uint8> short_secret_key(cUndersizedKeyLen, cSentinel);
    err = alcp_ec_get_secretkey(&handle,
                                &short_secret_key[0],
                                short_secret_key.size(),
                                &pub_key[0],
                                pub_key.size(),
                                &key_length);
    EXPECT_TRUE(alcp_is_error(err));
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
    EXPECT_EQ(short_secret_key,
              std::vector<Uint8>(cUndersizedKeyLen, cSentinel));

    EXPECT_EQ(key_length, 0U);

    alcp_ec_finish(&handle);
}

/* All tests to be added here */
TEST(ECDH, KAT_x25519)
{
    if (!CpuId::cpuIsAmd()) {
        GTEST_SKIP() << "ECDH tests are skipped on non-AMD (Intel) machines";
    }
    alc_ec_info_t info;
    info.ecCurveId     = ALCP_EC_CURVE25519;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    ecdh_KAT(info);
}

TEST(ECDH, KAT_p256)
{
    if (!CpuId::cpuIsAmd()) {
        GTEST_SKIP() << "ECDH tests are skipped on non-AMD (Intel) machines";
    }
    alc_ec_info_t info;
    info.ecCurveId     = ALCP_EC_SECP256R1;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_SHORT_WEIERSTRASS;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    ecdh_KAT_p256(info);
}

TEST(ECDH, SetPrivateKeyBadLength_x25519)
{
    alc_ec_info_t info;
    info.ecCurveId     = ALCP_EC_CURVE25519;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    ecdh_set_privatekey_bad_length(info);
}

TEST(ECDH, SetPrivateKeyBadLength_p256)
{
    alc_ec_info_t info;
    info.ecCurveId     = ALCP_EC_SECP256R1;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_SHORT_WEIERSTRASS;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    ecdh_set_privatekey_bad_length(info);
}

TEST(ECDH, GetPublicKeyBadLength_x25519)
{
    alc_ec_info_t info;
    info.ecCurveId     = ALCP_EC_CURVE25519;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    ecdh_get_publickey_bad_length(info);
}

TEST(ECDH, GetSecretKeyBadLength_x25519)
{
    alc_ec_info_t info;
    info.ecCurveId     = ALCP_EC_CURVE25519;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    ecdh_get_secretkey_bad_length(info, ECDH_KEYSIZE);
}

TEST(ECDH, GetSecretKeyBadLength_p256)
{
    alc_ec_info_t info;
    info.ecCurveId     = ALCP_EC_SECP256R1;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_SHORT_WEIERSTRASS;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    ecdh_get_secretkey_bad_length(info, ECDH_KEYSIZE * 2);
}

int
main(int argc, char** argv)
{
    try {
        ::testing::InitGoogleTest(&argc, argv);
        parseTestArgs(argc, argv);
#ifndef USE_IPP
        if (useipp)
            std::cout << RED << "IPP is not available, defaulting to ALCP"
                      << RESET << std::endl;
#endif

#ifndef USE_OSSL
        if (useossl) {
            std::cout << RED << "OpenSSL is not available, defaulting to ALCP"
                      << RESET << std::endl;
        }
#endif
        return RUN_ALL_TESTS();

    } catch (const std::exception& e) {
        std::cerr << "Unhandled exception: " << e.what() << std::endl;
        return 1;
    } catch (const char* e) {
        std::cerr << "Unhandled exception: " << e << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown exception caught" << std::endl;
        return 1;
    }
}
