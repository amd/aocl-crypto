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

#include "base.hh"
#include "benchmarks.hh"
#include "gbench_base.hh"

// Test blocksizes, append more if needed, size is in bytes
std::vector<int64_t> blocksizes = { 16, 64, 256, 1024, 8192, 16384, 32768 };
// std::vector<int64_t> blocksizes = { 16 };

int
CipherAes(benchmark::State& state,
          uint64_t          blockSize,
          encrypt_t         enc,
          alc_cipher_mode_t alcpMode,
          size_t            keylen)
{
    // Dynamic allocation better for larger sizes
    std::vector<uint8_t>          vec_in(blockSize, 56);
    std::vector<uint8_t>          vec_out(blockSize, 21);
    uint8_t                       key[keylen / 8];
    uint8_t                       iv[16];
    uint8_t                       ad[16];
    uint8_t                       tag[16];
    alcp::testing::CipherBase*    cb;
    alcp::testing::AlcpCipherBase acb =
        alcp::testing::AlcpCipherBase(alcpMode, iv, key, keylen);
    cb = &acb;
#ifdef USE_IPP
    alcp::testing::IPPCipherBase icb =
        alcp::testing::IPPCipherBase(alcpMode, iv, key, keylen);
    if (useipp) {
        cb = &icb;
    }
#endif
#ifdef USE_OSSL
    alcp::testing::OpenSSLCipherBase ocb =
        alcp::testing::OpenSSLCipherBase(alcpMode, iv, key, keylen);
    if (useossl) {
        cb = &ocb;
    }
#endif
    alcp::testing::alcp_data_ex_t data;
    data.in   = &(vec_in[0]);
    data.inl  = blockSize;
    data.out  = &(vec_out[0]);
    data.iv   = iv;
    data.ivl  = 12;
    data.ad   = ad;
    data.adl  = 16;
    data.tag  = tag;
    data.tagl = 16;
    if (enc == false && alcpMode == ALC_AES_MODE_GCM) {
        if (cb->encrypt(data) == false) {
            std::cout << "BENCH_ENC_FAILURE" << std::endl;
        }
        data.in  = &(vec_out[0]);
        data.out = &(vec_in[0]);
        if (alcpMode == ALC_AES_MODE_GCM)
            cb->reset();
    }
    for (auto _ : state) {
        if (enc) {
            if (cb->encrypt(data) == false) {
                std::cout << "BENCH_ENC_FAILURE" << std::endl;
            }
        } else if (cb->decrypt(data) == false) {
            std::cout << "BENCH_DEC_FAILURE" << std::endl;
            exit(-1);
        }
        if (alcpMode == ALC_AES_MODE_GCM)
            cb->reset();
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * blockSize, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = blockSize;

    return 0;
}

// 128 bit key size

/**
 * @brief Encrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_ENCRYPT_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 128));
}
BENCHMARK(BENCH_AES_ENCRYPT_CBC_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_CTR_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CTR, 128));
}
BENCHMARK(BENCH_AES_ENCRYPT_CTR_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_OFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_OFB, 128));
}
BENCHMARK(BENCH_AES_ENCRYPT_OFB_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 128));
}
BENCHMARK(BENCH_AES_ENCRYPT_CFB_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_GCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_GCM, 128));
}
BENCHMARK(BENCH_AES_ENCRYPT_GCM_128)->ArgsProduct({ blocksizes });

/**
 * @brief Decrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_DECRYPT_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CBC, 128));
}
BENCHMARK(BENCH_AES_DECRYPT_CBC_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_CTR_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CTR, 128));
}
BENCHMARK(BENCH_AES_DECRYPT_CTR_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_OFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_OFB, 128));
}
BENCHMARK(BENCH_AES_DECRYPT_OFB_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CFB, 128));
}
BENCHMARK(BENCH_AES_DECRYPT_CFB_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_GCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_GCM, 128));
}
BENCHMARK(BENCH_AES_DECRYPT_GCM_128)->ArgsProduct({ blocksizes });

// END 128 bit key size

// 192 bit key size

/**
 * @brief Encrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_ENCRYPT_CBC_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 192));
}
BENCHMARK(BENCH_AES_ENCRYPT_CBC_192)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_CTR_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CTR, 192));
}
BENCHMARK(BENCH_AES_ENCRYPT_CTR_192)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_OFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_OFB, 192));
}
BENCHMARK(BENCH_AES_ENCRYPT_OFB_192)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_CFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 192));
}
BENCHMARK(BENCH_AES_ENCRYPT_CFB_192)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_GCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_GCM, 192));
}
BENCHMARK(BENCH_AES_ENCRYPT_GCM_192)->ArgsProduct({ blocksizes });

/**
 * @brief Decrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_DECRYPT_CBC_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CBC, 192));
}
BENCHMARK(BENCH_AES_DECRYPT_CBC_192)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_CTR_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CTR, 192));
}
BENCHMARK(BENCH_AES_DECRYPT_CTR_192)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_OFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_OFB, 192));
}
BENCHMARK(BENCH_AES_DECRYPT_OFB_192)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_CFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CFB, 192));
}
BENCHMARK(BENCH_AES_DECRYPT_CFB_192)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_GCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_GCM, 192));
}
BENCHMARK(BENCH_AES_DECRYPT_GCM_192)->ArgsProduct({ blocksizes });

// END 192 bit keysize

// 256 bit key size

/**
 * @brief Encrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_ENCRYPT_CBC_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 256));
}
BENCHMARK(BENCH_AES_ENCRYPT_CBC_256)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_CTR_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CTR, 256));
}
BENCHMARK(BENCH_AES_ENCRYPT_CTR_256)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_OFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_OFB, 256));
}
BENCHMARK(BENCH_AES_ENCRYPT_OFB_256)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 256));
}
BENCHMARK(BENCH_AES_ENCRYPT_CFB_256)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_GCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_GCM, 256));
}
BENCHMARK(BENCH_AES_ENCRYPT_GCM_256)->ArgsProduct({ blocksizes });

/**
 * @brief Decrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_DECRYPT_CBC_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CBC, 256));
}
BENCHMARK(BENCH_AES_DECRYPT_CBC_256)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_CTR_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CTR, 256));
}
BENCHMARK(BENCH_AES_DECRYPT_CTR_256)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_OFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_OFB, 256));
}
BENCHMARK(BENCH_AES_DECRYPT_OFB_256)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CFB, 256));
}
BENCHMARK(BENCH_AES_DECRYPT_CFB_256)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_GCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_GCM, 256));
}
BENCHMARK(BENCH_AES_DECRYPT_GCM_256)->ArgsProduct({ blocksizes });

// END 256 bit keysize

int
main(int argc, char** argv)
{
    parseArgs(&argc, argv);
#ifndef USE_IPP
    if (useipp) {
        alcp::testing::printErrors("Error IPP not found defaulting to ALCP");
    }
#endif
#ifndef USE_OSSL
    if (useossl) {
        alcp::testing::printErrors(
            "Error OpenSSL not found defaulting to ALCP");
    }
#endif
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}
