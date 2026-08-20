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

#include "benchmarks_cipher.hh"
#include "cipher/cipher.hh"
#include "gbench_base.hh"
#include <alcp/cipher_segment.h>
#include <iostream>
#include <memory>
#include <vector>

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

    if (!vec_in_arr || !vec_out_arr) {
        state.SkipWithError("BENCH_ALLOC_FAILURE");
        return -1;
    }

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

/* Multibuffer Benchmarks */
int
CipherMultibufferBench(benchmark::State& state,
                       Uint64            blockSize,
                       encrypt_t         enc,
                       alc_cipher_mode_t alcpMode,
                       size_t            keylen,
                       Uint64            numBuffers)
{
    // Dynamic allocation better for larger sizes
    std::vector<std::vector<Uint8>> vec_in(numBuffers,
                                           std::vector<Uint8>(blockSize, 0x01));
    std::vector<std::vector<Uint8>> vec_out(
        numBuffers, std::vector<Uint8>(blockSize, 0x21));
    alignas(16)
        Uint8 iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    std::vector<std::vector<Uint8>> ivs(numBuffers,
                                        std::vector<Uint8>(iv, iv + 16));
    std::vector<const Uint8*>       iv_pointers(numBuffers);
    for (Uint64 i = 0; i < numBuffers; ++i) {
        std::next_permutation(ivs[i].begin(), ivs[i].end());
        iv_pointers[i] = ivs[i].data();
    }
    std::unique_ptr<Uint8[]> tag_buffer = std::make_unique<Uint8[]>(16);

    alignas(16) Uint8          key[MAX_KEY_SIZE / 8]  = {};
    alignas(16) Uint8          tkey[MAX_KEY_SIZE / 8] = {};
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
    // assign the input and output vectors to the data structure
    data.m_inl   = blockSize;
    data.m_outl  = blockSize;
    data.m_iv    = iv;
    data.m_ivl   = 16;
    data.m_tkey  = tkey;
    data.m_tkeyl = 16;

    std::vector<const Uint8*> input_buffer_pointers(numBuffers);
    std::vector<Uint8*>       output_buffer_pointers(numBuffers);
    std::vector<Uint64>       bufferLengths(numBuffers, blockSize);
    for (Uint64 i = 0; i < numBuffers; ++i) {
        input_buffer_pointers[i]  = vec_in[i].data();
        output_buffer_pointers[i] = vec_out[i].data();
    }

    // initialize the cipher context
    #ifdef MULTI_INIT_BENCH
    for (auto _ : state) {
    #endif
    if (!p_cb->multibufferInit(
            nullptr, 0, iv_pointers.data(), 16, numBuffers)) {
        // multibuffer initialization
        state.SkipWithError("BENCH_INIT_FAILURE");
    }
    #ifndef MULTI_INIT_BENCH
    for (auto _ : state) {
    #endif
        if (!p_cb->flush(input_buffer_pointers.data(), bufferLengths.data(), numBuffers)) {
            state.SkipWithError("BENCH_FLUSH_FAILURE");
        }

        if (!p_cb->dequeue(
                output_buffer_pointers.data(), numBuffers, bufferLengths.data())) {
            state.SkipWithError("BENCH_DEQUEUE_FAILURE");
        }
    }
    state.counters["Speed(Bytes/s)"] =
        benchmark::Counter(state.iterations() * blockSize * numBuffers,
                           benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = blockSize;
    state.counters["NumBuffers"]       = numBuffers;

    return 0;
}

/* Multibuffer benchmark functions for different modes and key sizes */
static void
BENCH_AES_MULTIBUFFER_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 128, state.range(1)));
}
static void
BENCH_AES_MULTIBUFFER_CBC_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 192, state.range(1)));
}

static void
BENCH_AES_MULTIBUFFER_CBC_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 256, state.range(1)));
}

static void
BENCH_AES_MULTIBUFFER_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 128, state.range(1)));
}
static void
BENCH_AES_MULTIBUFFER_CFB_192(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 192, state.range(1)));
}

static void
BENCH_AES_MULTIBUFFER_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 256, state.range(1)));
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

/**
 * @brief Benchmark for AES-XTS 256 using segment API with TweakBlockCalculate
 * 
 * This benchmark specifically tests the TweakBlockCalculate codepath by using
 * the segment encrypt API with varying startBlockNum values, forcing the
 * tweak block calculation on each iteration.
 */
int
CipherXtsSegmentBench(benchmark::State& state,
                      Uint64            blockSize,
                      encrypt_t         enc,
                      size_t            keylen)
{
    // Allocate buffers
    std::vector<Uint8> vec_in(blockSize, 0x01);
    std::vector<Uint8> vec_out(blockSize, 0x21);

    // Setup keys and IV
    // XTS requires key buffer to contain: [encryption_key || tweak_key]
    // For XTS-256: 32 bytes enc key + 32 bytes tweak key = 64 bytes total
    std::vector<Uint8> key(keylen / 4);
    // Encryption key
    for (size_t i = 0; i < keylen / 8; i++) key[i] = 0xAA;
    // Tweak key (must be different from encryption key)
    for (size_t i = keylen / 8; i < keylen / 4; i++) key[i] = 0xBB;

    alignas(16) Uint8 iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    // Allocate cipher handle
    alc_error_t err;
    Uint64      size = alcp_cipher_context_size();
    std::vector<Uint8> context(size);
    alc_cipher_handle_t handle;
    handle.ch_context = context.data();

    // Request and initialize cipher
    err = alcp_cipher_segment_request(ALC_AES_MODE_XTS, keylen, &handle);
    if (alcp_is_error(err)) {
        state.SkipWithError("XTS_SEGMENT: REQUEST_FAILURE");
        return -1;
    }

    // For segment init:
    // - key buffer contains [enc_key || tweak_key] (64 bytes for XTS-256)
    // - keyLen is ONLY the encryption key length in bits (256 for XTS-256)
    // - ivLen is in bytes (XTS requires exactly 16 bytes)
    err = alcp_cipher_segment_init(&handle, key.data(), keylen, iv, 16);
    if (alcp_is_error(err)) {
        state.SkipWithError("XTS_SEGMENT: INIT_FAILURE");
        alcp_cipher_segment_finish(&handle);
        return -1;
    }

    // Use varying block numbers to trigger TweakBlockCalculate
    // This simulates random access patterns which force recalculation
    Uint64 startBlockNum = 0;
    const Uint64 blockJump = 256; // Jump ahead to force TweakBlockCalculate

    for (auto _ : state) {
        // Increment startBlockNum to force TweakBlockCalculate on each iteration
        startBlockNum += blockJump;

        if (enc) {
            err = alcp_cipher_segment_encrypt_xts(&handle,
                                                  vec_in.data(),
                                                  vec_out.data(),
                                                  blockSize,
                                                  startBlockNum);
            if (alcp_is_error(err)) {
                state.SkipWithError("XTS_SEGMENT: ENCRYPT_FAILURE");
                break;
            }
        } else {
            err = alcp_cipher_segment_decrypt_xts(&handle,
                                                  vec_in.data(),
                                                  vec_out.data(),
                                                  blockSize,
                                                  startBlockNum);
            if (alcp_is_error(err)) {
                state.SkipWithError("XTS_SEGMENT: DECRYPT_FAILURE");
                break;
            }
        }
    }

    alcp_cipher_segment_finish(&handle);

    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * blockSize, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = blockSize;
    state.counters["BlockJump"] = blockJump;

    return 0;
}

static void
BENCH_AES_ENCRYPT_XTS_SEGMENT_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherXtsSegmentBench(state, state.range(0), ENCRYPT, 128));
}

static void
BENCH_AES_ENCRYPT_XTS_SEGMENT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherXtsSegmentBench(state, state.range(0), ENCRYPT, 256));
}

static void
BENCH_AES_DECRYPT_XTS_SEGMENT_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherXtsSegmentBench(state, state.range(0), DECRYPT, 128));
}

static void
BENCH_AES_DECRYPT_XTS_SEGMENT_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherXtsSegmentBench(state, state.range(0), DECRYPT, 256));
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
        CipherAeadBench(state, state.range(0), DECRYPT, ALC_AES_MODE_SIV, 256));
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
        std::cerr << "Custom block size selected:" << block_size << std::endl;
        blocksizes.resize(1);
        blocksizes[0] = block_size;
    }

    /* Define number of buffers to test */
    std::vector<Int64> num_buffers = { 4, 8, 16, 32, 64 };

    /* IPPCP doesnt have Chacha20 stream cipher variant yet */
    if (!useipp) {
        BENCHMARK(BENCH_CHACHA20_ENCRYPT_256)->ArgsProduct({ blocksizes });
        BENCHMARK(BENCH_CHACHA20_DECRYPT_256)->ArgsProduct({ blocksizes });
        BENCHMARK(BENCH_CHACHA20_POLY1305_ENCRYPT_256)
            ->ArgsProduct({ blocksizes });
        BENCHMARK(BENCH_CHACHA20_POLY1305_DECRYPT_256)
            ->ArgsProduct({ blocksizes });

        /* IPPCP Multibuffer benchmarks are not yet enabled */
        BENCHMARK(BENCH_AES_MULTIBUFFER_CBC_128)
            ->ArgsProduct({ blocksizes, num_buffers });
        BENCHMARK(BENCH_AES_MULTIBUFFER_CBC_192)
            ->ArgsProduct({ blocksizes, num_buffers });
        BENCHMARK(BENCH_AES_MULTIBUFFER_CBC_256)
            ->ArgsProduct({ blocksizes, num_buffers });
        BENCHMARK(BENCH_AES_MULTIBUFFER_CFB_128)
            ->ArgsProduct({ blocksizes, num_buffers });
        BENCHMARK(BENCH_AES_MULTIBUFFER_CFB_192)
            ->ArgsProduct({ blocksizes, num_buffers });
        BENCHMARK(BENCH_AES_MULTIBUFFER_CFB_256)
            ->ArgsProduct({ blocksizes, num_buffers });
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

    // XTS Segment API benchmarks
    BENCHMARK(BENCH_AES_ENCRYPT_XTS_SEGMENT_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_XTS_SEGMENT_128)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_ENCRYPT_XTS_SEGMENT_256)->ArgsProduct({ blocksizes });
    BENCHMARK(BENCH_AES_DECRYPT_XTS_SEGMENT_256)->ArgsProduct({ blocksizes });

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
    parseBenchArgs(&argc, argv);
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
