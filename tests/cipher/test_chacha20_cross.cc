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

#include "cipher/alc_cipher.hh"
#include "cipher/cipher.hh"
#include "cipher/gtest_base_cipher.hh"
#include "rng_base.hh"
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>

using namespace alcp::testing;

// Verify that two RngBase instances seeded identically via setSeedMt19937
// produce bit-for-bit identical output from genRandomMt19937.
TEST(SeedReproducibility, Mt19937OutputIsIdenticalForSameSeed)
{
    constexpr uint64_t fixed_seed = 0xDEADBEEFCAFEBABEULL;
    constexpr size_t   buf_size   = 1024;

    RngBase rb1, rb2;
    rb1.setSeedMt19937(fixed_seed);
    rb2.setSeedMt19937(fixed_seed);

    std::vector<Uint8> out1(buf_size), out2(buf_size);
    rb1.genRandomMt19937(out1);
    rb2.genRandomMt19937(out2);

    EXPECT_EQ(out1, out2)
        << "Same seed must produce identical genRandomMt19937 output";
}

// Verify that a different seed produces different output (sanity check).
TEST(SeedReproducibility, DifferentSeedsProduceDifferentOutput)
{
    constexpr size_t buf_size = 256;

    RngBase rb1, rb2;
    rb1.setSeedMt19937(0x1111111111111111ULL);
    rb2.setSeedMt19937(0x2222222222222222ULL);

    std::vector<Uint8> out1(buf_size), out2(buf_size);
    rb1.genRandomMt19937(out1);
    rb2.genRandomMt19937(out2);

    EXPECT_NE(out1, out2)
        << "Different seeds must produce different genRandomMt19937 output";
}

// End-to-end: simulate the key/IV/plaintext generation sequence used by
// CipherCrossTest (genRandomMt19937 for all vectors, then a seeded
// default_random_engine for ShuffleVector) and verify it is fully reproducible.
TEST(SeedReproducibility, CrossTestVectorsAreReproducibleWithSameSeed)
{
    constexpr uint64_t fixed_seed = 0xABCDEF0123456789ULL;
    constexpr int      key_size   = 32; // bytes
    constexpr int      ivl        = 16;
    constexpr size_t   msg_size   = 1024;

    auto generate = [&](std::vector<Uint8>& key_out,
                        std::vector<Uint8>& iv_out,
                        std::vector<Uint8>& msg_out) {
        RngBase rb;
        rb.setSeedMt19937(fixed_seed);

        msg_out.resize(msg_size);
        rb.genRandomMt19937(msg_out);
        key_out.resize(key_size);
        rb.genRandomMt19937(key_out);
        iv_out.resize(ivl);
        rb.genRandomMt19937(iv_out);

        // Mirror CipherCrossTest: seed ShuffleVector engine from MT19937 stream
        std::vector<Uint8> rng_seed_bytes(sizeof(uint32_t));
        rb.genRandomMt19937(rng_seed_bytes);
        uint32_t rng_seed_val;
        std::memcpy(
            &rng_seed_val, rng_seed_bytes.data(), rng_seed_bytes.size());
        auto rng = std::default_random_engine{ rng_seed_val };
        key_out  = ShuffleVector(key_out, rng);
    };

    std::vector<Uint8> key1, iv1, msg1;
    std::vector<Uint8> key2, iv2, msg2;
    generate(key1, iv1, msg1);
    generate(key2, iv2, msg2);

    EXPECT_EQ(msg1, msg2) << "Plaintext must be identical for same seed";
    EXPECT_EQ(key1, key2) << "Key must be identical for same seed";
    EXPECT_EQ(iv1, iv2) << "IV must be identical for same seed";
}

/* Testing Starts Here! */
TEST(CHACHA20_ENC_256, CROSS_SMALL_256)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have Chacha20 cipher implemented yet";
    CipherCrossTest(256, ENCRYPT, ALC_CHACHA20, SMALL);
}
TEST(CHACHA20_ENC_256, CROSS_BIG_256)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have Chacha20 cipher implemented yet";
    CipherCrossTest(256, ENCRYPT, ALC_CHACHA20, BIG);
}

int
main(int argc, char** argv)
{
    try {
        ::testing::InitGoogleTest(&argc, argv);
        parseTestArgs(argc, argv);
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
