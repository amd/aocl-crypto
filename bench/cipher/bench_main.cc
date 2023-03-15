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

#include "benchmarks_cipher.hh"
#include "cipher/cipher_base.hh"
#include "gbench_base.hh"
#include <memory>

// Test blocksizes, append more if needed, size is in bytes
std::vector<Int64> blocksizes = { 16, 64, 256, 1024, 8192, 16384, 32768 };

int
CipherAes(benchmark::State& state,
          Uint64          blockSize,
          encrypt_t         enc,
          alc_cipher_mode_t alcpMode,
          size_t            keylen)
{
    // Dynamic allocation better for larger sizes
    std::vector<Uint8>         vec_in(blockSize, 56);
    std::vector<Uint8>         vec_out(blockSize, 21);
    std::unique_ptr<Uint8[]>   tagBuffer = std::make_unique<Uint8[]>(16);
    Uint8                      key[keylen / 8];
    Uint8                      iv[16];
    Uint8                      ad[16];
    Uint8                      tag[16];
    Uint8                      tkey[keylen / 8];
    alcp::testing::CipherBase* cb;

    alcp::testing::AlcpCipherBase acb = alcp::testing::AlcpCipherBase(
        alcpMode, iv, 12, key, keylen, tkey, blockSize);

    cb = &acb;
#ifdef USE_IPP
    alcp::testing::IPPCipherBase icb = alcp::testing::IPPCipherBase(
        alcpMode, iv, 12, key, keylen, tkey, blockSize);
    if (useipp) {
        cb = &icb;
    }
#endif
#ifdef USE_OSSL
    alcp::testing::OpenSSLCipherBase ocb = alcp::testing::OpenSSLCipherBase(
        alcpMode, iv, 12, key, keylen, tkey, blockSize);
    if (useossl) {
        cb = &ocb;
    }
#endif
    alcp::testing::alcp_data_ex_t data;
    data.m_in      = &(vec_in[0]);
    data.m_inl     = blockSize;
    data.m_out     = &(vec_out[0]);
    data.m_iv      = iv;
    data.m_ivl     = 12;
    data.m_ad      = ad;
    data.m_adl     = 16;
    data.m_tag     = tag;
    data.m_tagl    = 16;
    data.m_tkey    = tkey;
    data.m_tagBuff = tagBuffer.get();
    data.m_tkeyl   = 16;
    if (!enc
        && (alcpMode == ALC_AES_MODE_GCM || alcpMode == ALC_AES_MODE_CCM)) {
        if (!cb->encrypt(data)) {
            std::cout << "GCM/CCM: BENCH_ENC_FAILURE" << std::endl;
            exit(-1);
        }
        data.m_in  = &(vec_out[0]);
        data.m_out = &(vec_in[0]);
        if (alcpMode == ALC_AES_MODE_GCM) {
            if (!cb->init(key, keylen)) {
                std::cout << "GCM: BENCH_INIT_FAILURE" << std::endl;
                exit(-1);
            }
        }
    }
    for (auto _ : state) {
        if (enc) {
            if (!cb->encrypt(data)) {
                std::cout << "BENCH_ENC_FAILURE" << std::endl;
                exit(-1);
            }
        } else {
            if (!cb->decrypt(data)) {
                std::cout << "BENCH_DEC_FAILURE" << std::endl;
                exit(-1);
            }
        }
        if (alcpMode == ALC_AES_MODE_GCM) {
            if (!cb->init(key, keylen)) {
                std::cout << "GCM: BENCH_RESET_FAILURE" << std::endl;
                exit(-1);
            }
        }
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

static void
BENCH_AES_ENCRYPT_CTR_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CTR, 128));
}

static void
BENCH_AES_ENCRYPT_OFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_OFB, 128));
}

static void
BENCH_AES_ENCRYPT_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 128));
}

static void
BENCH_AES_ENCRYPT_GCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_GCM, 128));
}

static void
BENCH_AES_ENCRYPT_CCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CCM, 128));
}

static void
BENCH_AES_ENCRYPT_XTS_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_XTS, 128));
}

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

static void
BENCH_AES_DECRYPT_CTR_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CTR, 128));
}

static void
BENCH_AES_DECRYPT_OFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_OFB, 128));
}

static void
BENCH_AES_DECRYPT_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CFB, 128));
}

static void
BENCH_AES_DECRYPT_GCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_GCM, 128));
}

static void
BENCH_AES_DECRYPT_XTS_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_XTS, 128));
}

static void
BENCH_AES_DECRYPT_CCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CCM, 128));
}
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

static void
BENCH_AES_ENCRYPT_CTR_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CTR, 192));
}

static void
BENCH_AES_ENCRYPT_OFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_OFB, 192));
}

static void
BENCH_AES_ENCRYPT_CFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 192));
}

static void
BENCH_AES_ENCRYPT_GCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_GCM, 192));
}

static void
BENCH_AES_ENCRYPT_CCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CCM, 192));
}

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

static void
BENCH_AES_DECRYPT_CTR_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CTR, 192));
}

static void
BENCH_AES_DECRYPT_OFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_OFB, 192));
}

static void
BENCH_AES_DECRYPT_CFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CFB, 192));
}

static void
BENCH_AES_DECRYPT_GCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_GCM, 192));
}

static void
BENCH_AES_DECRYPT_CCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CCM, 192));
}

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

static void
BENCH_AES_ENCRYPT_CTR_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CTR, 256));
}

static void
BENCH_AES_ENCRYPT_OFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_OFB, 256));
}

static void
BENCH_AES_ENCRYPT_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 256));
}

static void
BENCH_AES_ENCRYPT_GCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_GCM, 256));
}

static void
BENCH_AES_ENCRYPT_CCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CCM, 256));
}

static void
BENCH_AES_ENCRYPT_XTS_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_XTS, 256));
}

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

static void
BENCH_AES_DECRYPT_CTR_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CTR, 256));
}

static void
BENCH_AES_DECRYPT_OFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_OFB, 256));
}

static void
BENCH_AES_DECRYPT_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CFB, 256));
}

static void
BENCH_AES_DECRYPT_GCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_GCM, 256));
}

static void
BENCH_AES_DECRYPT_XTS_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_XTS, 256));
}

static void
BENCH_AES_DECRYPT_CCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CCM, 256));
}
// END 256 bit keysize

int
AddBenchmarks()
{
    BENCHMARK(BENCH_AES_ENCRYPT_CBC_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CTR_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_OFB_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CFB_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_GCM_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CBC_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CTR_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_OFB_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CFB_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_GCM_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CBC_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CTR_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_OFB_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CFB_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_GCM_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CBC_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CTR_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_OFB_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CFB_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_GCM_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CBC_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CTR_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_OFB_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CFB_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_GCM_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CBC_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CTR_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_OFB_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CFB_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_GCM_256)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_ENCRYPT_XTS_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_XTS_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_XTS_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_XTS_256)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_ENCRYPT_CCM_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CCM_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CCM_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CCM_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CCM_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CCM_192)->ArgsProduct({ blocksizes });
    return 0;
}

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
    AddBenchmarks();
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}