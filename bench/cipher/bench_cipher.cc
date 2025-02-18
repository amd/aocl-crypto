/*
 * Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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
#include "cipher/cipher.hh"
#include "gbench_base.hh"
#include <memory>

#define MAX_BLOCK_SIZE 32768
#define MAX_KEY_SIZE   256

// Test blocksizes, append more if needed, size is in bytes
std::vector<Int64> blocksizes = { 16, 64, 256, 1024, 8192, 16384, 32768 };

int
CipherAeadBench(benchmark::State& state,
                const Uint64      cBlockSize,
                encrypt_t         enc,
                alc_cipher_mode_t alcpMode,
                size_t            keylen)
{
    /*ensure that non-aead modes are not passed into this function*/
    std::string cModeStr = alcp::testing::GetModeSTR(alcpMode);
    if (!alcp::testing::CheckCipherIsAEAD(alcpMode)) {
        std::cout << "Error! Mode " << cModeStr
                  << " is not an AEAD Cipher! exiting this bench!";
        return -1;
    }
    // Allocate with 512 bit alignment
    /* this is to avoid large stack use(MAX_BLOCK_SIZE),reported by Coverity
     */
#ifdef _WIN32
    auto vec_in_arr = std::unique_ptr<Uint8[], decltype(&_aligned_free)>(
        static_cast<Uint8*>(
            _aligned_malloc(MAX_BLOCK_SIZE * sizeof(Uint8), 64)),
        _aligned_free);
    auto vec_out_arr = std::unique_ptr<Uint8[], decltype(&_aligned_free)>(
        static_cast<Uint8*>(
            _aligned_malloc(MAX_BLOCK_SIZE * sizeof(Uint8), 64)),
        _aligned_free);
#else
    auto vec_in_arr = std::unique_ptr<Uint8[], decltype(&std::free)>(
        static_cast<Uint8*>(
            std::aligned_alloc(64, MAX_BLOCK_SIZE * sizeof(Uint8))),
        std::free);
    auto vec_out_arr = std::unique_ptr<Uint8[], decltype(&std::free)>(
        static_cast<Uint8*>(
            std::aligned_alloc(64, MAX_BLOCK_SIZE * sizeof(Uint8))),
        std::free);
#endif

    alignas(16) Uint8              tag_buffer[16]         = {};
    alignas(16) Uint8              key[MAX_KEY_SIZE / 8]  = {};
    alignas(16) Uint8              iv[16]                 = {};
    alignas(16) Uint8              ad[16]                 = {};
    alignas(16) Uint8              tag[16]                = {};
    alignas(16) Uint8              tkey[MAX_KEY_SIZE / 8] = {};
    alcp::testing::CipherAeadBase* p_cb                   = nullptr;

    alcp::testing::alcp_dc_ex_t data;
    data.m_in      = vec_in_arr.get();
    data.m_inl     = cBlockSize;
    data.m_out     = vec_out_arr.get();
    data.m_outl    = cBlockSize;
    data.m_iv      = iv;
    data.m_ivl     = 12;
    data.m_ad      = ad;
    data.m_adl     = 16;
    data.m_tag     = tag;
    data.m_tagl    = 16;
    data.m_tagBuff = tag_buffer;
    data.m_tkey    = tkey;
    data.m_tkeyl   = 16;

    alc_cipher_state_t cipherState;

    if (alcpMode == ALC_AES_MODE_SIV) {
        data.m_ivl = 16;
    }

    alcp::testing::AlcpCipherAeadBase acb =
        alcp::testing::AlcpCipherAeadBase(alcpMode,
                                          data.m_iv,
                                          data.m_ivl,
                                          key,
                                          keylen,
                                          data.m_tkey,
                                          data.m_outl,
                                          &cipherState);

    p_cb = &acb;
#ifdef USE_IPP
    std::unique_ptr<alcp::testing::IPPCipherAeadBase> icb;
    if (useipp) {
        icb  = std::make_unique<alcp::testing::IPPCipherAeadBase>(alcpMode,
                                                                 data.m_iv,
                                                                 data.m_ivl,
                                                                 key,
                                                                 keylen,
                                                                 data.m_tkey,
                                                                 data.m_outl,
                                                                 nullptr);
        p_cb = icb.get();
    }
#endif
#ifdef USE_OSSL
    std::unique_ptr<alcp::testing::OpenSSLCipherAeadBase> ocb;
    if (useossl) {
        ocb = std::make_unique<alcp::testing::OpenSSLCipherAeadBase>(
            alcpMode,
            data.m_iv,
            data.m_ivl,
            key,
            keylen,
            data.m_tkey,
            data.m_outl,
            &cipherState);
        p_cb = ocb.get();
    }
#endif

    if (!enc && alcp::testing::CheckCipherIsAEAD(alcpMode)) {
        if (!p_cb->encrypt(data)) {
            state.SkipWithError("AEAD : BENCH_ENC_FAILURE");
        }
        data.m_in  = vec_out_arr.get();
        data.m_out = vec_in_arr.get();
        // TAG is the IV
        // cb->init(key, keylen);
        if (alcpMode == ALC_AES_MODE_SIV) {
            memcpy(iv, data.m_tag, 16);
            // Since the tag of 16 bytes is copied to iv, iv length has to
            // be reset to 16 bytes
        }
    }

    for (auto _ : state) {
        // For OpenSSL GCM and SIV, Reset needs to be called again since tag
        // needs to be generated each time
        if ((useossl
             && (alcpMode == ALC_AES_MODE_GCM
                 || alcpMode == ALC_AES_MODE_SIV))) {
            if (!p_cb->init(key, keylen)) {
                state.SkipWithError("GCM: BENCH_RESET_FAILURE");
            }
        }
        if (enc) {
            if (!p_cb->encrypt(data)) {
                state.SkipWithError("BENCH_ENC_FAILURE");
            }
        } else {
            if (!p_cb->decrypt(data)) {
                state.SkipWithError("BENCH_DEC_FAILURE");
            }
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * cBlockSize, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = cBlockSize;

    return 0;
}

int
CipherBench(benchmark::State& state,
            Uint64            blockSize,
            encrypt_t         enc,
            alc_cipher_mode_t alcpMode,
            size_t            keylen)
{
    // Dynamic allocation better for larger sizes
    std::vector<Uint8>       vec_in(blockSize, 0x01);
    std::vector<Uint8>       vec_out(blockSize, 0x21);
    std::unique_ptr<Uint8[]> tag_buffer = std::make_unique<Uint8[]>(16);

    std::vector<Uint8>         key(keylen / 8);
    Uint8                      iv[16];
    Uint8                      tkey[keylen / 8];
    alcp::testing::CipherBase* p_cb;

    alcp::testing::AlcpCipherBase acb = alcp::testing::AlcpCipherBase(
        alcpMode, iv, 12, &key[0], keylen, tkey, blockSize);

    p_cb = &acb;
#ifdef USE_IPP
    alcp::testing::IPPCipherBase icb = alcp::testing::IPPCipherBase(
        alcpMode, iv, 12, &key[0], keylen, tkey, blockSize);
    if (useipp) {
        p_cb = &icb;
    }
#endif
#ifdef USE_OSSL
    alcp::testing::OpenSSLCipherBase ocb = alcp::testing::OpenSSLCipherBase(
        alcpMode, iv, 12, &key[0], keylen, tkey, blockSize);
    if (useossl) {
        p_cb = &ocb;
    }
#endif
    alcp::testing::alcp_dc_ex_t data;
    data.m_in    = &(vec_in[0]);
    data.m_inl   = blockSize;
    data.m_out   = &(vec_out[0]);
    data.m_outl  = blockSize;
    data.m_iv    = iv;
    data.m_ivl   = 16;
    data.m_tkey  = tkey;
    data.m_tkeyl = 16;
    for (auto _ : state) {
        if (enc) {
            if (!p_cb->encrypt(data)) {
                state.SkipWithError("BENCH_ENC_FAILURE");
            }
        } else {
            if (!p_cb->decrypt(data)) {
                state.SkipWithError("BENCH_DEC_FAILURE");
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
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 128));
}

static void
BENCH_AES_ENCRYPT_CTR_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CTR, 128));
}

static void
BENCH_AES_ENCRYPT_OFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_OFB, 128));
}

static void
BENCH_AES_ENCRYPT_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 128));
}

static void
BENCH_AES_ENCRYPT_CCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CCM, 128));
}

static void
BENCH_AES_ENCRYPT_XTS_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_XTS, 128));
}

static void
BENCH_AES_ENCRYPT_SIV_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_SIV, 128));
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
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CBC, 128));
}

static void
BENCH_AES_DECRYPT_CTR_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CTR, 128));
}

static void
BENCH_AES_DECRYPT_OFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_OFB, 128));
}

static void
BENCH_AES_DECRYPT_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CFB, 128));
}

static void
BENCH_AES_DECRYPT_XTS_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_XTS, 128));
}

static void
BENCH_AES_DECRYPT_CCM_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CCM, 128));
}

static void
BENCH_AES_DECRYPT_SIV_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), DECRYPT, ALC_AES_MODE_SIV, 128));
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
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 192));
}

static void
BENCH_AES_ENCRYPT_CTR_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CTR, 192));
}

static void
BENCH_AES_ENCRYPT_OFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_OFB, 192));
}

static void
BENCH_AES_ENCRYPT_CFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 192));
}

static void
BENCH_AES_ENCRYPT_CCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CCM, 192));
}

static void
BENCH_AES_ENCRYPT_SIV_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_SIV, 192));
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
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CBC, 192));
}

static void
BENCH_AES_DECRYPT_CTR_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CTR, 192));
}

static void
BENCH_AES_DECRYPT_OFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_OFB, 192));
}

static void
BENCH_AES_DECRYPT_CFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CFB, 192));
}

static void
BENCH_AES_DECRYPT_CCM_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CCM, 192));
}

static void
BENCH_AES_DECRYPT_SIV_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), DECRYPT, ALC_AES_MODE_SIV, 192));
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
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 256));
}

static void
BENCH_AES_ENCRYPT_CTR_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CTR, 256));
}

static void
BENCH_AES_ENCRYPT_OFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_OFB, 256));
}

static void
BENCH_AES_ENCRYPT_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 256));
}

static void
BENCH_AES_ENCRYPT_CCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_CCM, 256));
}

static void
BENCH_AES_ENCRYPT_XTS_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_XTS, 256));
}

static void
BENCH_AES_ENCRYPT_SIV_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_SIV, 256));
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
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CBC, 256));
}

static void
BENCH_AES_DECRYPT_CTR_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CTR, 256));
}

static void
BENCH_AES_DECRYPT_OFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_OFB, 256));
}

static void
BENCH_AES_DECRYPT_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CFB, 256));
}

static void
BENCH_AES_DECRYPT_XTS_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_AES_MODE_XTS, 256));
}

static void
BENCH_AES_DECRYPT_CCM_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), DECRYPT, ALC_AES_MODE_CCM, 256));
}

static void
BENCH_AES_DECRYPT_SIV_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_SIV, 256));
}
// END 256 bit keysize

/* Multi-init Benchmarks*/
#ifdef MULTI_INIT_BENCH
static void
BENCH_AES_ENCRYPT_GCM_MULTI_INIT_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_GCM, 128));
}

static void
BENCH_AES_DECRYPT_GCM_MULTI_INIT_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), DECRYPT, ALC_AES_MODE_GCM, 128));
}

static void
BENCH_AES_ENCRYPT_GCM_MULTI_INIT_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_GCM, 192));
}

static void
BENCH_AES_DECRYPT_GCM_MULTI_INIT_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), DECRYPT, ALC_AES_MODE_GCM, 192));
}

static void
BENCH_AES_ENCRYPT_GCM_MULTI_INIT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), ENCRYPT, ALC_AES_MODE_GCM, 256));
}

static void
BENCH_AES_DECRYPT_GCM_MULTI_INIT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAeadBench(state, state.range(0), DECRYPT, ALC_AES_MODE_GCM, 256));
}
#endif

/* non AES ciphers */
static void
BENCH_CHACHA20_ENCRYPT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), ENCRYPT, ALC_CHACHA20, 256));
}
static void
BENCH_CHACHA20_DECRYPT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherBench(state, state.range(0), DECRYPT, ALC_CHACHA20, 256));
}

static void
BENCH_CHACHA20_POLY1305_ENCRYPT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherAeadBench(
        state, state.range(0), ENCRYPT, ALC_CHACHA20_POLY1305, 256));
}
static void
BENCH_CHACHA20_POLY1305_DECRYPT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherAeadBench(
        state, state.range(0), DECRYPT, ALC_CHACHA20_POLY1305, 256));
}

int
AddBenchmarks()
{
    /* check if custom block size is provided by user */
    if (block_size != 0) {
        std::cout << "Custom block size selected:" << block_size << std::endl;
        blocksizes.resize(1);
        blocksizes[0] = block_size;
    }
    /* IPPCP doesnt have Chacha20 stream cipher variant yet */
    if (!useipp) {
        BENCHMARK(BENCH_CHACHA20_ENCRYPT_256)->ArgsProduct({ blocksizes });
        BENCHMARK(BENCH_CHACHA20_DECRYPT_256)->ArgsProduct({ blocksizes });
        BENCHMARK(BENCH_CHACHA20_POLY1305_ENCRYPT_256)
            ->ArgsProduct({ blocksizes });
        BENCHMARK(BENCH_CHACHA20_POLY1305_DECRYPT_256)
            ->ArgsProduct({ blocksizes });
    }
    BENCHMARK(BENCH_AES_ENCRYPT_CBC_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CTR_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_OFB_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CFB_128)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_DECRYPT_CBC_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CTR_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_OFB_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CFB_128)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_ENCRYPT_CBC_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CTR_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_OFB_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CFB_192)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_DECRYPT_CBC_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CTR_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_OFB_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CFB_192)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_ENCRYPT_CBC_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CTR_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_OFB_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CFB_256)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_DECRYPT_CBC_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CTR_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_OFB_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CFB_256)->ArgsProduct({ blocksizes });

    BENCHMARK(BENCH_AES_ENCRYPT_XTS_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_XTS_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_XTS_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_XTS_256)->ArgsProduct({ blocksizes });

    /* Benchmark of AEAD Ciphers */
    // SIV Benchmarks
    BENCHMARK(BENCH_AES_ENCRYPT_SIV_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_SIV_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_SIV_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_SIV_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_SIV_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_SIV_256)->ArgsProduct({ blocksizes });
    // CCM Benchmarks
    BENCHMARK(BENCH_AES_ENCRYPT_CCM_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CCM_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CCM_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CCM_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_CCM_192)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_CCM_192)->ArgsProduct({ blocksizes });

#ifdef MULTI_INIT_BENCH
    // Multi-Init Benchmarks
    BENCHMARK(BENCH_AES_ENCRYPT_GCM_MULTI_INIT_128)
        ->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_GCM_MULTI_INIT_128)
        ->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_GCM_MULTI_INIT_192)
        ->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_GCM_MULTI_INIT_192)
        ->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_GCM_MULTI_INIT_256)
        ->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_GCM_MULTI_INIT_256)
        ->ArgsProduct({ blocksizes });
#endif

    return 0;
}

int
main(int argc, char** argv)
{
    parseArgs(&argc, argv);
#ifndef USE_IPP
    if (useipp) {
        alcp::testing::utils::printErrors(
            "Error IPP not found defaulting to ALCP");
    }
#endif
#ifndef USE_OSSL
    if (useossl) {
        alcp::testing::utils::printErrors(
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