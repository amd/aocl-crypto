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

#include <benchmark/benchmark.h>
#include <memory>

#include "cipher_expiremental/alc_cipher_gcm.hh"

namespace alcp::benchmarking::cipher {

using namespace alcp::testing::cipher::gcm;
using alcp::testing::cipher::ITestCipher;

std::vector<Int64> blocksizes = { 16, 64, 256, 1024, 8192, 16384, 32768 };

template<bool encryptor, alc_cipher_mode_t mode>
int
BenchCipherExpiremental(benchmark::State& state,
                        const Uint64      cBlockSize,
                        Uint32            keylen)
{
    alignas(64) Uint8 input_text[cBlockSize];
    alignas(64) Uint8 output_text[cBlockSize];
    alignas(32) Uint8 key[keylen / 8];
    alignas(16) Uint8 iv[16];
    alignas(16) Uint8 ad[16];
    alignas(16) Uint8 tag[16];
    // FIXME: Tkey might be needed for XTS

    alc_test_gcm_init_data_t dataInit;
    dataInit.m_iv      = iv;
    dataInit.m_iv_len  = 12;
    dataInit.m_aad     = ad;
    dataInit.m_aad_len = 16;
    dataInit.m_key     = key;
    dataInit.m_key_len = keylen / 8;

    alc_test_gcm_update_data_t dataUpdate;
    dataUpdate.m_iv         = iv;
    dataUpdate.m_iv_len     = 12;
    dataUpdate.m_output     = output_text;
    dataUpdate.m_output_len = cBlockSize;
    dataUpdate.m_input      = input_text;
    dataUpdate.m_input_len  = cBlockSize;

    alc_test_gcm_finalize_data_t dataFinalize;
    dataFinalize.m_tag_expected = tag;
    dataFinalize.m_tag_len      = 16;
    dataFinalize.m_tag          = tag;
    dataFinalize.verified       = false;

    if constexpr (encryptor == false) { // Decrypt
        // Create a vaid data for decryption (mainly tag and ct)
        std::unique_ptr<ITestCipher> iTestCipher =
            std::make_unique<AlcpGcmCipher<true>>();
        bool no_err = true;
        no_err &= iTestCipher->init(&dataInit);
        if (no_err == false) {
            state.SkipWithError("MicroBench: Initialization failed for decrypt "
                                "ct,tag generation using encrypt");
        }
        no_err &= iTestCipher->update(&dataUpdate);
        if (no_err == false) {
            state.SkipWithError("MicroBench: Update failed for decrypt "
                                "ct,tag generation using encrypt");
        }
        no_err &= iTestCipher->finalize(&dataFinalize);
        if (no_err == false) {
            state.SkipWithError("MicroBench: Finalize failed for decrypt "
                                "ct,tag generation using encrypt");
        }
    }

    std::unique_ptr<ITestCipher> iTestCipher =
        std::make_unique<AlcpGcmCipher<encryptor>>();

    // Real benchmark begins here
    bool no_err = true;
    no_err &= iTestCipher->init(&dataInit);
    if (no_err == false) {
        state.SkipWithError("MicroBench: Initialization failed!");
    }

    // Benchmark hot path
    for (auto _ : state) {
        no_err &= iTestCipher->update(&dataUpdate);
        if (no_err == false) {
            state.SkipWithError("MicroBench: Update failed!");
        }
    }

    // Cleanup
    no_err &= iTestCipher->finalize(&dataFinalize);
    if (no_err == false) {
        state.SkipWithError("MicroBench: Finalize failed!");
    }

    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * cBlockSize, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = cBlockSize;
    return 0;
}
} // namespace alcp::benchmarking::cipher

using alcp::benchmarking::cipher::BenchCipherExpiremental;

static void
BENCH_AES_ENCRYPT_GCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchCipherExpiremental<true, ALC_AES_MODE_GCM>(
        state, state.range(0), 128));
}

static void
BENCH_AES_ENCRYPT_GCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchCipherExpiremental<true, ALC_AES_MODE_GCM>(
        state, state.range(0), 192));
}

static void
BENCH_AES_ENCRYPT_GCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchCipherExpiremental<true, ALC_AES_MODE_GCM>(
        state, state.range(0), 256));
}

static void
BENCH_AES_DECRYPT_GCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchCipherExpiremental<false, ALC_AES_MODE_GCM>(
        state, state.range(0), 128));
}

static void
BENCH_AES_DECRYPT_GCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchCipherExpiremental<false, ALC_AES_MODE_GCM>(
        state, state.range(0), 192));
}

static void
BENCH_AES_DECRYPT_GCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(BenchCipherExpiremental<false, ALC_AES_MODE_GCM>(
        state, state.range(0), 256));
}

BENCHMARK(BENCH_AES_ENCRYPT_GCM_128)
    ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes });

BENCHMARK(BENCH_AES_ENCRYPT_GCM_192)
    ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes });

BENCHMARK(BENCH_AES_ENCRYPT_GCM_256)
    ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes });

BENCHMARK(BENCH_AES_DECRYPT_GCM_128)
    ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes });

BENCHMARK(BENCH_AES_DECRYPT_GCM_192)
    ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes });

BENCHMARK(BENCH_AES_DECRYPT_GCM_256)
    ->ArgsProduct({ alcp::benchmarking::cipher::blocksizes });

int
main(int argc, char** argv)
{
    // parseArgs(&argc, argv);
    // #ifndef USE_IPP
    //     if (useipp) {
    //         alcp::testing::utils::printErrors(
    //             "Error IPP not found defaulting to ALCP");
    //     }
    // #endif
    // #ifndef USE_OSSL
    //     if (useossl) {
    //         alcp::testing::utils::printErrors(
    //             "Error OpenSSL not found defaulting to ALCP");
    //     }
    // #endif
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}