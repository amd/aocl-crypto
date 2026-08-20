/*
 * Copyright (C) 2026, Advanced Micro Devices. All rights reserved.
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
 * @file test_multibuffer_variable_length.cc
 * @brief Test variable-length multi-buffer AES encryption (>32 buffers with
 * mixed lengths)
 */

#include <algorithm>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "alcp/alcp.h"
#include "alcp/cipher.hh"
#include "alcp/types.hh"
#include "alcp/utils/cpuid.hh"

#include "gtest_common.hh"
#include "rng_base.hh"
#include <cstring>
#include <exception>
#include <iostream>

using alcp::Uint64;
using alcp::Uint8;

class VariableLengthMultibufferTest : public ::testing::Test
{
  protected:
    alcp::testing::RngBase rng;

    void SetUp() override
    {
        if (seed_set)
            rng.setSeedMt19937(seed_override);
        std::cout << "[ SEED     ] " << rng.getSeedMt19937()
                  << "  (repro: --seed " << rng.getSeedMt19937() << ")"
                  << std::endl;
    }
    void TearDown() override {}

    // Helper: Generate random data
    std::vector<Uint8> generateRandom(size_t size)
    {
        std::vector<Uint8> v(size);
        rng.genRandomMt19937(v);
        return v;
    }

    // Helper: Single-buffer reference encryption using standard API
    std::vector<Uint8> encryptReference(alc_cipher_mode_t         mode,
                                        int                       key_bits,
                                        const std::vector<Uint8>& key,
                                        const std::vector<Uint8>& iv,
                                        const std::vector<Uint8>& plaintext)
    {
        alc_cipher_handle_t handle;
        handle.ch_context = malloc(alcp_cipher_context_size());
        if (!handle.ch_context) {
            return {};
        }

        alc_error_t err = alcp_cipher_request(mode, key_bits, &handle);
        if (alcp_is_error(err)) {
            free(handle.ch_context);
            return {};
        }

        // Initialize with key and IV
        err = alcp_cipher_init(
            &handle, key.data(), key.size() * 8, iv.data(), iv.size());
        if (alcp_is_error(err)) {
            alcp_cipher_finish(&handle);
            free(handle.ch_context);
            return {};
        }

        std::vector<Uint8> ciphertext(plaintext.size());
        Uint64             outlen = 0;
        err                       = alcp_cipher_encrypt(&handle,
                                  plaintext.data(),
                                  ciphertext.data(),
                                  plaintext.size(),
                                  &outlen);

        alcp_cipher_finish(&handle);
        free(handle.ch_context);

        if (alcp_is_error(err)) {
            return {};
        }

        ciphertext.resize(outlen);
        return ciphertext;
    }
};

// Test 1: Uniform lengths with >32 buffers (should use fast path in groups)
TEST_F(VariableLengthMultibufferTest, UniformLengths_40Buffers)
{
    const int num_buffers = 40;
    const int buffer_size = 1024; // 64 blocks each

    std::vector<Uint8>              key = generateRandom(16); // AES-128
    std::vector<std::vector<Uint8>> ivs;
    std::vector<std::vector<Uint8>> plaintexts;
    std::vector<Uint64>             lengths;

    // Generate test data
    for (int i = 0; i < num_buffers; i++) {
        ivs.push_back(generateRandom(16));
        plaintexts.push_back(generateRandom(buffer_size));
        lengths.push_back(buffer_size);
    }

    // Get reference ciphertexts
    std::vector<std::vector<Uint8>> expected_ciphertexts;
    for (int i = 0; i < num_buffers; i++) {
        expected_ciphertexts.push_back(encryptReference(
            ALC_AES_MODE_CBC, 128, key, ivs[i], plaintexts[i]));
    }

    // Create cipher handle using C API
    alc_cipher_handle_t handle;
    handle.ch_context = malloc(alcp_cipher_context_size());
    ASSERT_NE(handle.ch_context, nullptr);

    // Request cipher context
    alc_error_t err = alcp_cipher_request(ALC_AES_MODE_CBC, 128, &handle);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Initialize cipher (required before multibuffer_init)
    err = alcp_cipher_init(
        &handle, key.data(), key.size() * 8, ivs[0].data(), 16);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Prepare pointer arrays
    std::vector<const Uint8*>       plaintext_ptrs(num_buffers);
    std::vector<const Uint8*>       iv_ptrs(num_buffers);
    std::vector<Uint8*>             ciphertext_ptrs(num_buffers);
    std::vector<std::vector<Uint8>> ciphertexts(num_buffers);

    for (int i = 0; i < num_buffers; i++) {
        plaintext_ptrs[i] = plaintexts[i].data();
        iv_ptrs[i]        = ivs[i].data();
        ciphertexts[i].resize(buffer_size);
        ciphertext_ptrs[i] = ciphertexts[i].data();
    }

    // Initialize multibuffer
    err = alcp_multibuffer_init(
        &handle, nullptr, 0, iv_ptrs.data(), 16, num_buffers);
    if (err == ALC_ERROR_NOT_SUPPORTED) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        GTEST_SKIP() << "Multibuffer not supported on this architecture";
    }
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Flush with variable lengths
    err =
        alcp_flush(&handle, plaintext_ptrs.data(), lengths.data(), num_buffers);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Dequeue with variable lengths
    err = alcp_dequeue(
        &handle, ciphertext_ptrs.data(), num_buffers, lengths.data());
    if (err == ALC_ERROR_NO_FALLBACK) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        GTEST_SKIP() << "Neither AVX512 nor AESNI available on this machine";
    }
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Cleanup
    alcp_cipher_finish(&handle);
    free(handle.ch_context);

    // Verify results
    for (int i = 0; i < num_buffers; i++) {
        EXPECT_EQ(ciphertexts[i], expected_ciphertexts[i])
            << "Buffer " << i << " mismatch";
    }
}

// Test 2: Variable lengths with >32 buffers (should use hybrid scheduler)
TEST_F(VariableLengthMultibufferTest, VariableLengths_48Buffers)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Variable-length multi-buffer requires AES_MULTI_UPDATE to "
                    "be enabled. "
                 << "Configure with -DALCP_ENABLE_CIPHER_MULTI_UPDATE=ON";
#endif
    const int num_buffers = 48;

    std::vector<Uint8>              key = generateRandom(16); // AES-128
    std::vector<std::vector<Uint8>> ivs;
    std::vector<std::vector<Uint8>> plaintexts;
    std::vector<Uint64>             lengths;

    // Generate variable-length test data
    std::vector<size_t> sizes = {
        16,  32,   48,  64,  128,  256, 512, 1024, // Various sizes
        16,  32,   48,  64,  128,  256, 512, 1024, // Repeat pattern
        16,  32,   48,  64,  128,  256, 512, 1024, 16,  32,  48,
        64,  128,  256, 512, 1024, 16,  32,  48,   64,  128, 256,
        512, 1024, 16,  32,  48,   64,  128, 256,  512, 1024
    };

    for (int i = 0; i < num_buffers; i++) {
        ivs.push_back(generateRandom(16));
        size_t size = sizes[i];
        plaintexts.push_back(generateRandom(size));
        lengths.push_back(size);
    }

    // Get reference ciphertexts
    std::vector<std::vector<Uint8>> expected_ciphertexts;
    for (int i = 0; i < num_buffers; i++) {
        expected_ciphertexts.push_back(encryptReference(
            ALC_AES_MODE_CBC, 128, key, ivs[i], plaintexts[i]));
    }

    // Create cipher handle
    alc_cipher_handle_t handle;
    handle.ch_context = malloc(alcp_cipher_context_size());
    ASSERT_NE(handle.ch_context, nullptr);

    alc_error_t err = alcp_cipher_request(ALC_AES_MODE_CBC, 128, &handle);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = alcp_cipher_init(
        &handle, key.data(), key.size() * 8, ivs[0].data(), 16);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Prepare pointer arrays
    std::vector<const Uint8*>       plaintext_ptrs(num_buffers);
    std::vector<const Uint8*>       iv_ptrs(num_buffers);
    std::vector<Uint8*>             ciphertext_ptrs(num_buffers);
    std::vector<std::vector<Uint8>> ciphertexts(num_buffers);

    for (int i = 0; i < num_buffers; i++) {
        plaintext_ptrs[i] = plaintexts[i].data();
        iv_ptrs[i]        = ivs[i].data();
        ciphertexts[i].resize(lengths[i]);
        ciphertext_ptrs[i] = ciphertexts[i].data();
    }

    // Initialize multibuffer
    err = alcp_multibuffer_init(
        &handle, nullptr, 0, iv_ptrs.data(), 16, num_buffers);
    if (err == ALC_ERROR_NOT_SUPPORTED) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        GTEST_SKIP() << "Multibuffer not supported";
    }
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Flush and dequeue with variable lengths
    err =
        alcp_flush(&handle, plaintext_ptrs.data(), lengths.data(), num_buffers);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = alcp_dequeue(
        &handle, ciphertext_ptrs.data(), num_buffers, lengths.data());
    if (err == ALC_ERROR_NO_FALLBACK) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        GTEST_SKIP() << "Neither AVX512 nor AESNI available on this machine";
    }
    EXPECT_EQ(err, ALC_ERROR_NONE);

    alcp_cipher_finish(&handle);
    free(handle.ch_context);

    // Verify results
    for (int i = 0; i < num_buffers; i++) {
        EXPECT_EQ(ciphertexts[i], expected_ciphertexts[i])
            << "Buffer " << i << " (size=" << lengths[i] << ") mismatch";
    }
}

// Test 3: Maximum buffers (126 - just under MAX_CIPHER_BUFFER_SIZE) with highly
// variable lengths
TEST_F(VariableLengthMultibufferTest, MaxBuffers_HighlyVariableLength)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Variable-length multi-buffer requires AES_MULTI_UPDATE to "
                    "be enabled. "
                 << "Configure with -DALCP_ENABLE_CIPHER_MULTI_UPDATE=ON";
#endif
    const int num_buffers =
        126; // MAX_CIPHER_BUFFER_SIZE is 127, dequeue uses >= check

    std::vector<Uint8>              key = generateRandom(32); // AES-256
    std::vector<std::vector<Uint8>> ivs;
    std::vector<std::vector<Uint8>> plaintexts;
    std::vector<Uint64>             lengths;

    // Generate highly variable lengths
    std::mt19937                    gen(42); // Fixed seed for reproducibility
    std::uniform_int_distribution<> dis(1, 128); // 1-128 blocks

    for (int i = 0; i < num_buffers; i++) {
        ivs.push_back(generateRandom(16));
        size_t num_blocks = dis(gen);
        size_t size       = num_blocks * 16; // Multiple of block size
        plaintexts.push_back(generateRandom(size));
        lengths.push_back(size);
    }

    // Get reference ciphertexts
    std::vector<std::vector<Uint8>> expected_ciphertexts;
    for (int i = 0; i < num_buffers; i++) {
        expected_ciphertexts.push_back(encryptReference(
            ALC_AES_MODE_CBC, 256, key, ivs[i], plaintexts[i]));
    }

    // Create cipher handle
    alc_cipher_handle_t handle;
    handle.ch_context = malloc(alcp_cipher_context_size());
    ASSERT_NE(handle.ch_context, nullptr);

    alc_error_t err = alcp_cipher_request(ALC_AES_MODE_CBC, 256, &handle);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = alcp_cipher_init(
        &handle, key.data(), key.size() * 8, ivs[0].data(), 16);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Prepare pointer arrays
    std::vector<const Uint8*>       plaintext_ptrs(num_buffers);
    std::vector<const Uint8*>       iv_ptrs(num_buffers);
    std::vector<Uint8*>             ciphertext_ptrs(num_buffers);
    std::vector<std::vector<Uint8>> ciphertexts(num_buffers);

    for (int i = 0; i < num_buffers; i++) {
        plaintext_ptrs[i] = plaintexts[i].data();
        iv_ptrs[i]        = ivs[i].data();
        ciphertexts[i].resize(lengths[i]);
        ciphertext_ptrs[i] = ciphertexts[i].data();
    }

    // Initialize multibuffer
    err = alcp_multibuffer_init(
        &handle, nullptr, 0, iv_ptrs.data(), 16, num_buffers);
    if (err == ALC_ERROR_NOT_SUPPORTED) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        GTEST_SKIP() << "Multibuffer not supported";
    }
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Flush and dequeue
    err =
        alcp_flush(&handle, plaintext_ptrs.data(), lengths.data(), num_buffers);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = alcp_dequeue(
        &handle, ciphertext_ptrs.data(), num_buffers, lengths.data());
    if (err == ALC_ERROR_NO_FALLBACK) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        GTEST_SKIP() << "Neither AVX512 nor AESNI available on this machine";
    }
    EXPECT_EQ(err, ALC_ERROR_NONE);

    alcp_cipher_finish(&handle);
    free(handle.ch_context);

    // Verify results
    for (int i = 0; i < num_buffers; i++) {
        EXPECT_EQ(ciphertexts[i], expected_ciphertexts[i])
            << "Buffer " << i << " (size=" << lengths[i] << ") mismatch";
    }
}

// Test 4: Edge case - Just over 32 buffers (33)
TEST_F(VariableLengthMultibufferTest, EdgeCase_33Buffers)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Variable-length multi-buffer requires AES_MULTI_UPDATE to "
                    "be enabled. "
                 << "Configure with -DALCP_ENABLE_CIPHER_MULTI_UPDATE=ON";
#endif
    const int num_buffers = 33;

    std::vector<Uint8>              key = generateRandom(24); // AES-192
    std::vector<std::vector<Uint8>> ivs;
    std::vector<std::vector<Uint8>> plaintexts;
    std::vector<Uint64>             lengths;

    // Mixed lengths: some small, some large
    for (int i = 0; i < num_buffers; i++) {
        ivs.push_back(generateRandom(16));
        size_t size = (i % 3 == 0) ? 16 : (i % 3 == 1) ? 128 : 512;
        plaintexts.push_back(generateRandom(size));
        lengths.push_back(size);
    }

    // Get reference ciphertexts
    std::vector<std::vector<Uint8>> expected_ciphertexts;
    for (int i = 0; i < num_buffers; i++) {
        expected_ciphertexts.push_back(encryptReference(
            ALC_AES_MODE_CFB, 192, key, ivs[i], plaintexts[i]));
    }

    // Create cipher handle (CFB mode)
    alc_cipher_handle_t handle;
    handle.ch_context = malloc(alcp_cipher_context_size());
    ASSERT_NE(handle.ch_context, nullptr);

    alc_error_t err = alcp_cipher_request(ALC_AES_MODE_CFB, 192, &handle);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = alcp_cipher_init(
        &handle, key.data(), key.size() * 8, ivs[0].data(), 16);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Prepare pointer arrays
    std::vector<const Uint8*>       plaintext_ptrs(num_buffers);
    std::vector<const Uint8*>       iv_ptrs(num_buffers);
    std::vector<Uint8*>             ciphertext_ptrs(num_buffers);
    std::vector<std::vector<Uint8>> ciphertexts(num_buffers);

    for (int i = 0; i < num_buffers; i++) {
        plaintext_ptrs[i] = plaintexts[i].data();
        iv_ptrs[i]        = ivs[i].data();
        ciphertexts[i].resize(lengths[i]);
        ciphertext_ptrs[i] = ciphertexts[i].data();
    }

    // Initialize multibuffer
    err = alcp_multibuffer_init(
        &handle, nullptr, 0, iv_ptrs.data(), 16, num_buffers);
    if (err == ALC_ERROR_NOT_SUPPORTED) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        GTEST_SKIP() << "Multibuffer not supported";
    }
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Flush and dequeue
    err =
        alcp_flush(&handle, plaintext_ptrs.data(), lengths.data(), num_buffers);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = alcp_dequeue(
        &handle, ciphertext_ptrs.data(), num_buffers, lengths.data());
    if (err == ALC_ERROR_NO_FALLBACK) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        GTEST_SKIP() << "Neither AVX512 nor AESNI available on this machine";
    }
    EXPECT_EQ(err, ALC_ERROR_NONE);

    alcp_cipher_finish(&handle);
    free(handle.ch_context);

    // Verify results
    for (int i = 0; i < num_buffers; i++) {
        EXPECT_EQ(ciphertexts[i], expected_ciphertexts[i])
            << "Buffer " << i << " (size=" << lengths[i] << ") mismatch";
    }
}

// Test 5: Boundary - Single block per buffer (minimum)
TEST_F(VariableLengthMultibufferTest, MinimumLength_64Buffers)
{
    const int num_buffers = 64;
    const int buffer_size = 16; // Single block

    std::vector<Uint8>              key = generateRandom(16); // AES-128
    std::vector<std::vector<Uint8>> ivs;
    std::vector<std::vector<Uint8>> plaintexts;
    std::vector<Uint64>             lengths;

    for (int i = 0; i < num_buffers; i++) {
        ivs.push_back(generateRandom(16));
        plaintexts.push_back(generateRandom(buffer_size));
        lengths.push_back(buffer_size);
    }

    // Get reference ciphertexts
    std::vector<std::vector<Uint8>> expected_ciphertexts;
    for (int i = 0; i < num_buffers; i++) {
        expected_ciphertexts.push_back(encryptReference(
            ALC_AES_MODE_CBC, 128, key, ivs[i], plaintexts[i]));
    }

    // Create cipher handle
    alc_cipher_handle_t handle;
    handle.ch_context = malloc(alcp_cipher_context_size());
    ASSERT_NE(handle.ch_context, nullptr);

    alc_error_t err = alcp_cipher_request(ALC_AES_MODE_CBC, 128, &handle);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = alcp_cipher_init(
        &handle, key.data(), key.size() * 8, ivs[0].data(), 16);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Prepare pointer arrays
    std::vector<const Uint8*>       plaintext_ptrs(num_buffers);
    std::vector<const Uint8*>       iv_ptrs(num_buffers);
    std::vector<Uint8*>             ciphertext_ptrs(num_buffers);
    std::vector<std::vector<Uint8>> ciphertexts(num_buffers);

    for (int i = 0; i < num_buffers; i++) {
        plaintext_ptrs[i] = plaintexts[i].data();
        iv_ptrs[i]        = ivs[i].data();
        ciphertexts[i].resize(buffer_size);
        ciphertext_ptrs[i] = ciphertexts[i].data();
    }

    // Initialize multibuffer
    err = alcp_multibuffer_init(
        &handle, nullptr, 0, iv_ptrs.data(), 16, num_buffers);
    if (err == ALC_ERROR_NOT_SUPPORTED) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        GTEST_SKIP() << "Multibuffer not supported";
    }
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Flush and dequeue
    err =
        alcp_flush(&handle, plaintext_ptrs.data(), lengths.data(), num_buffers);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = alcp_dequeue(
        &handle, ciphertext_ptrs.data(), num_buffers, lengths.data());
    if (err == ALC_ERROR_NO_FALLBACK) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        GTEST_SKIP() << "Neither AVX512 nor AESNI available on this machine";
    }
    EXPECT_EQ(err, ALC_ERROR_NONE);

    alcp_cipher_finish(&handle);
    free(handle.ch_context);

    // Verify results
    for (int i = 0; i < num_buffers; i++) {
        EXPECT_EQ(ciphertexts[i], expected_ciphertexts[i])
            << "Buffer " << i << " mismatch";
    }
}

int
main(int argc, char** argv)
{
    try {
        parseTestArgs(argc, argv);
        ::testing::InitGoogleTest(&argc, argv);

        // Skip if running with IPP (-i) or OpenSSL (-o) flags
        // This test only validates ALCP's variable-length multi-buffer
        // implementation
        if (useipp || useossl) {
            std::cout
                << "Skipping: This test only validates ALCP implementation"
                << std::endl;
            return 0;
        }

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
