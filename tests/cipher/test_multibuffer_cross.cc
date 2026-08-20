/*
 * Copyright (C) 2025-2026, Advanced Micro Devices. All rights reserved.
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

#include <algorithm>
#include <memory>
#include <random>

#include <gtest/gtest.h>

#include "alcp/cipher.hh"
#include "alcp/types.hh"
#include "alcp/utils/cpuid.hh"
#ifndef _WIN32
#include "alcp/cipher/cipher_wrapper.hh"
#endif
#include "alcp/alcp.h"
#include "gtest_common.hh"
#include "rng_base.hh"
#include <cstring>
#include <exception>
#include <iostream>

// Factory removed
using alcp::cipher::CipherKeyLen;
using alcp::cipher::CipherMode;
using alcp::cipher::createCipher;
using alcp::cipher::iCipher;
using alcp::utils::CpuId;

// Parameter structure for parameterized tests
struct MultibufferTestParams
{
    std::string cipher_type;
    int         num_buffers;
    int         block_size;

    MultibufferTestParams(const std::string& cipher, int buffers, int size)
        : cipher_type(cipher)
        , num_buffers(buffers)
        , block_size(size)
    {
    }
};

// Parameterized test class
class AESMultibufferTest
    : public ::testing::TestWithParam<MultibufferTestParams>
{
  protected:
    alcp::testing::RngBase rng;
    std::vector<Uint8>     key;

    void SetUp() override
    {
        if (seed_set)
            rng.setSeedMt19937(seed_override);
        std::cout << "[ SEED     ] " << rng.getSeedMt19937()
                  << "  (repro: --seed " << rng.getSeedMt19937() << ")"
                  << std::endl;
    }

    void TearDown() override {}

    // Helper method to generate unique IV for each buffer
    std::vector<Uint8> generateIV(int buffer_index)
    {
        std::vector<Uint8> iv(16);
        rng.genRandomMt19937(iv);
        // Modify IV slightly for each buffer to make them unique
        iv[15] = static_cast<Uint8>((iv[15] + buffer_index) % 256);
        return iv;
    }

    // Helper method to generate unique plaintext for each buffer
    std::vector<Uint8> generatePlaintext(int buffer_index, int size)
    {
        std::vector<Uint8> plaintext(size);
        rng.genRandomMt19937(plaintext);

        // Modify first byte slightly for each buffer to make them unique
        if (buffer_index > 0 && size > 0) {
            plaintext[0] =
                static_cast<Uint8>((plaintext[0] + buffer_index * 0x10) % 256);
        }

        return plaintext;
    }

    // Helper method to calculate expected ciphertext using single-buffer
    // encryption
    std::vector<Uint8> calculateExpectedCiphertext(
        const std::vector<Uint8>& plaintext,
        const std::vector<Uint8>& iv,
        const std::string&        cipher_type)
    {
        std::vector<Uint8> expected(plaintext.size());

        // Create cipher handle and context using CAPIs
        alc_cipher_handle_t handle;
        alc_error_t         err = ALC_ERROR_NONE;

        // Allocate context
        handle.ch_context = malloc(alcp_cipher_context_size());
        if (!handle.ch_context) {
            return expected; // Return empty vector on allocation failure
        }

        // Determine cipher mode from cipher_type string
        alc_cipher_mode_t mode;
        if (cipher_type.find("cbc") != std::string::npos) {
            mode = ALC_AES_MODE_CBC;
        } else if (cipher_type.find("cfb") != std::string::npos) {
            mode = ALC_AES_MODE_CFB;
        } else {
            free(handle.ch_context);
            handle.ch_context = nullptr;
            return expected; // Unsupported mode
        }

        // Request cipher context
        err = alcp_cipher_request(mode, key.size() * 8, &handle);
        if (alcp_is_error(err)) {
            free(handle.ch_context);
            handle.ch_context = nullptr;
            return expected;
        }

        // Initialize cipher
        err = alcp_cipher_init(
            &handle, key.data(), key.size() * 8, iv.data(), iv.size());
        if (alcp_is_error(err)) {
            alcp_cipher_finish(&handle);
            free(handle.ch_context);
            handle.ch_context = nullptr;
            return expected;
        }

        Uint64 outlen = 0;

        // Encrypt the plaintext
        err = alcp_cipher_encrypt(&handle,
                                  plaintext.data(),
                                  expected.data(),
                                  plaintext.size(),
                                  &outlen);
        if (alcp_is_error(err)) {
            alcp_cipher_finish(&handle);
            free(handle.ch_context);
            handle.ch_context = nullptr;
            expected.clear(); // Clear on error
            expected.resize(
                plaintext.size()); // Resize back to original size with zeros
            return expected;
        }

        // Cleanup
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        handle.ch_context = nullptr;

        return expected;
    }

    // Helper method to generate random key based on cipher type
    std::vector<Uint8> generateKey(const std::string& cipher_type)
    {
        int                len = 16;
        if (cipher_type.find("192") != std::string::npos)
            len = 24;
        else if (cipher_type.find("256") != std::string::npos)
            len = 32;
        std::vector<Uint8> k(len);
        rng.genRandomMt19937(k);
        return k;
    }
};

// Parameterized test for multi-buffer encryption
TEST_P(AESMultibufferTest, MultibufferEncrypt)
{
    const auto&        params      = GetParam();
    const std::string& cipher_type = params.cipher_type;
    const int          num_buffers = params.num_buffers;
    const int          block_size  = params.block_size;

    // Check if either AVX512 or AESNI is supported for multi-buffer operations
    bool avx512_supported =
        CpuId::cpuHasAvx512(alcp::utils::Avx512Flags::AVX512_F);
    bool aesni_supported = CpuId::cpuHasAesni();

    // Skip only if neither AVX512 nor AESNI is available
    if (!avx512_supported && !aesni_supported) {
        GTEST_SKIP() << "Neither AVX512 nor AESNI supported on this machine";
    }

    // Generate the key once for this test
    key = generateKey(cipher_type);

    // Prepare data structures for multiple buffers
    std::vector<std::vector<Uint8>> ivs(num_buffers);
    std::vector<std::vector<Uint8>> plaintexts(num_buffers);
    std::vector<std::vector<Uint8>> outputs(num_buffers);
    std::vector<std::vector<Uint8>> expected_outputs(num_buffers);

    std::vector<const Uint8*> iv_pointers(num_buffers);
    std::vector<const Uint8*> input_pointers(num_buffers);
    std::vector<Uint8*>       output_pointers(num_buffers);

    // Initialize data for each buffer
    for (int i = 0; i < num_buffers; ++i) {
        ivs[i]        = generateIV(i);
        plaintexts[i] = generatePlaintext(i, block_size);
        outputs[i].resize(block_size);

        // Calculate expected output using single-buffer encryption
        expected_outputs[i] =
            calculateExpectedCiphertext(plaintexts[i], ivs[i], cipher_type);

        // Set up pointers
        iv_pointers[i]     = ivs[i].data();
        input_pointers[i]  = plaintexts[i].data();
        output_pointers[i] = outputs[i].data();
    }

    // Create cipher handle and context using CAPIs
    alc_cipher_handle_t handle;
    alc_error_t         err = ALC_ERROR_NONE;

    // Allocate context
    handle.ch_context = malloc(alcp_cipher_context_size());
    ASSERT_NE(handle.ch_context, nullptr)
        << "Failed to allocate cipher context";

    // Determine cipher mode from cipher_type string
    alc_cipher_mode_t mode;
    if (cipher_type.find("cbc") != std::string::npos) {
        mode = ALC_AES_MODE_CBC;
    } else if (cipher_type.find("cfb") != std::string::npos) {
        mode = ALC_AES_MODE_CFB;
    } else {
        free(handle.ch_context);
        handle.ch_context = nullptr;
        GTEST_SKIP() << "Unsupported cipher mode for multibuffer: "
                     << cipher_type;
    }

    // Request cipher context
    err = alcp_cipher_request(mode, key.size() * 8, &handle);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        handle.ch_context = nullptr;
        ASSERT_FALSE(alcp_is_error(err)) << "Failed to request cipher context";
    }

    // Initialize cipher
    err = alcp_cipher_init(
        &handle, key.data(), key.size() * 8, ivs[0].data(), 16);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        handle.ch_context = nullptr;
        ASSERT_FALSE(alcp_is_error(err)) << "Failed to initialize cipher";
    }

    // Initialize multibuffer
    err = alcp_multibuffer_init(
        &handle, NULL, 0, iv_pointers.data(), 16, num_buffers);
    if (err == ALC_ERROR_NOT_SUPPORTED) {
        printf("Unsupported on non-avx512 architectures\n");
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        handle.ch_context = nullptr;
        GTEST_SKIP() << "Multibuffer not supported on this architecture";
    } else if (alcp_is_error(err)) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        handle.ch_context = nullptr;
        ASSERT_FALSE(alcp_is_error(err))
            << "multibufferInit failed for " << num_buffers << " buffers";
    }

    // Create lengths array for uniform-length buffers
    std::vector<Uint64> lengths(num_buffers, block_size);

    // Flush input data
    err =
        alcp_flush(&handle, input_pointers.data(), lengths.data(), num_buffers);
    if (err == ALC_ERROR_NOT_SUPPORTED) {
        printf("Unsupported on non-avx512 architectures\n");
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        handle.ch_context = nullptr;
        GTEST_SKIP() << "Flush operation not supported on this architecture";
    } else if (alcp_is_error(err)) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        handle.ch_context = nullptr;
        ASSERT_FALSE(alcp_is_error(err))
            << "flush failed for " << num_buffers << " buffers";
    }

    // Dequeue output data
    err = alcp_dequeue(
        &handle, output_pointers.data(), num_buffers, lengths.data());
    if (err == ALC_ERROR_NO_FALLBACK) {
        printf("Unsupported on non-avx512 architectures\n");
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        handle.ch_context = nullptr;
        GTEST_SKIP() << "Dequeue operation not supported on this architecture";
    } else if (err == ALC_ERROR_NOT_SUPPORTED) {
        printf("Unsupported AES mode\n");
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        handle.ch_context = nullptr;
        GTEST_SKIP() << "Dequeue operation not supported for this mode";
    } else if (alcp_is_error(err)) {
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
        handle.ch_context = nullptr;
        ASSERT_FALSE(alcp_is_error(err))
            << "dequeue failed for " << num_buffers << " buffers";
    }

    // Verify results for each buffer
    for (int i = 0; i < num_buffers; ++i) {
        EXPECT_EQ(outputs[i], expected_outputs[i])
            << "Buffer " << i << " encryption failed for " << cipher_type
            << " with " << num_buffers << " buffers and " << block_size
            << " byte blocks";
    }

    // Cleanup
    alcp_cipher_finish(&handle);
    free(handle.ch_context);
    handle.ch_context = nullptr;
}

// Helper function to generate test parameters
std::vector<MultibufferTestParams>
generateTestParams()
{
    std::vector<MultibufferTestParams> params;

    // Cipher types to test
    std::vector<std::string> cipher_types = { "aes-cfb-128", "aes-cfb-192",
                                              "aes-cfb-256", "aes-cbc-128",
                                              "aes-cbc-192", "aes-cbc-256" };

    // Buffer counts to test
    std::vector<int> buffer_counts = { 1, 2, 4, 8, 16, 32, 64, 96 };

    // Generate all block sizes from 16 to 2048 in multiples of 16
    std::vector<int> block_sizes;
    for (int size = 16; size <= 2048; size += 16) {
        block_sizes.push_back(size);
    }

    // Generate test parameters for each combination
    for (const auto& cipher : cipher_types) {
        for (int buffer_count : buffer_counts) {
            for (int block_size : block_sizes) {
                // Add some filtering for practical test execution:
                // - For larger block sizes, test fewer buffer counts
                // - For very large block sizes, test only a few combinations
                if (block_size <= 64) {
                    // Test all buffer counts for small block sizes
                    params.emplace_back(cipher, buffer_count, block_size);
                } else if (block_size <= 256) {
                    // Test fewer buffer counts for medium block sizes
                    if (buffer_count <= 16) {
                        params.emplace_back(cipher, buffer_count, block_size);
                    }
                } else if (block_size <= 1024) {
                    // Test even fewer buffer counts for large block sizes
                    if (buffer_count <= 8) {
                        params.emplace_back(cipher, buffer_count, block_size);
                    }
                } else {
                    // Test only small buffer counts for very large block sizes
                    if (buffer_count <= 4) {
                        params.emplace_back(cipher, buffer_count, block_size);
                    }
                }
            }
        }
    }

    return params;
}

// Test parameter instantiation
INSTANTIATE_TEST_SUITE_P(
    AESMultibufferTests,
    AESMultibufferTest,
    ::testing::ValuesIn(generateTestParams()),
    // Custom test name generator
    [](const ::testing::TestParamInfo<MultibufferTestParams>& info) {
        std::string cipher_name = info.param.cipher_type;
        // Replace dashes with underscores for valid test names
        std::replace(cipher_name.begin(), cipher_name.end(), '-', '_');
        return cipher_name + "_" + std::to_string(info.param.num_buffers)
               + "buffers_" + std::to_string(info.param.block_size) + "bytes";
    });

// Main function
int
main(int argc, char** argv)
{
    try {
        parseTestArgs(argc, argv);
        ::testing::InitGoogleTest(&argc, argv);
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
