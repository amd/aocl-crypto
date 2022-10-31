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

#pragma once
#include "digest/alc_base.hh"
#include "digest/base.hh"

#ifdef USE_IPP
#include "digest/ipp_base.hh"
#endif

#ifdef USE_OSSL
#include "digest/openssl_base.hh"
#endif

#include "gbench_base.hh"
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include <string.h>

using namespace alcp::testing;

void
Digest_SHA2_224(benchmark::State& state, uint64_t block_size)
{
    alc_error_t    error;
    Uint8          message[32768] = { 0 };
    Uint8          digest[512]    = { 0 };
    AlcpDigestBase adb(ALC_SHA2_224, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_224);
    DigestBase*    db = &adb;
#ifdef USE_IPP
    IPPDigestBase idb(ALC_SHA2_224, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_224);
    if (useipp) {
        db = &idb;
    }
#endif

#ifdef USE_OSSL
    OpenSSLDigestBase odb(
        ALC_SHA2_224, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_224);
    if (useossl) {
        db = &odb;
    }
#endif

    for (auto _ : state) {
        error =
            db->digest_function(message, block_size, digest, sizeof(digest));
        db->reset();
        if (alcp_is_error(error)) {
            printf("Error in running benchmark");
            return;
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

void
Digest_SHA2_256(benchmark::State& state, uint64_t block_size)
{
    alc_error_t    error;
    Uint8          message[32768] = { 0 };
    Uint8          digest[512]    = { 0 };
    AlcpDigestBase adb(ALC_SHA2_256, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_256);
    DigestBase*    db = &adb;
#ifdef USE_IPP
    IPPDigestBase idb(ALC_SHA2_256, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_256);
    if (useipp) {
        db = &idb;
    }
#endif

#ifdef USE_OSSL
    OpenSSLDigestBase odb(
        ALC_SHA2_256, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_256);
    if (useossl) {
        db = &odb;
    }
#endif

    for (auto _ : state) {
        error =
            db->digest_function(message, block_size, digest, sizeof(digest));
        db->reset();
        if (alcp_is_error(error)) {
            printf("Error in running benchmark");
            return;
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

void
Digest_SHA2_384(benchmark::State& state, uint64_t block_size)
{
    alc_error_t    error;
    Uint8          message[32768] = { 0 };
    Uint8          digest[512]    = { 0 };
    AlcpDigestBase adb(ALC_SHA2_384, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_384);
    DigestBase*    db = &adb;
#ifdef USE_IPP
    IPPDigestBase idb(ALC_SHA2_384, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_384);
    if (useipp) {
        db = &idb;
    }
#endif

#ifdef USE_OSSL
    OpenSSLDigestBase odb(
        ALC_SHA2_384, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_384);
    if (useossl) {
        db = &odb;
    }
#endif

    for (auto _ : state) {
        error =
            db->digest_function(message, block_size, digest, sizeof(digest));
        db->reset();
        if (alcp_is_error(error)) {
            printf("Error in running benchmark");
            return;
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

void
Digest_SHA2_512(benchmark::State& state, uint64_t block_size)
{
    alc_error_t    error;
    Uint8          message[32768] = { 0 };
    Uint8          digest[512]    = { 0 };
    AlcpDigestBase adb(ALC_SHA2_512, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_512);
    DigestBase*    db = &adb;
#ifdef USE_IPP
    IPPDigestBase idb(ALC_SHA2_512, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_512);
    if (useipp) {
        db = &idb;
    }
#endif

#ifdef USE_OSSL
    OpenSSLDigestBase odb(
        ALC_SHA2_512, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_512);
    if (useossl) {
        db = &odb;
    }
#endif

    for (auto _ : state) {
        error =
            db->digest_function(message, block_size, digest, sizeof(digest));
        db->reset();
        if (alcp_is_error(error)) {
            printf("Error in running benchmark");
            return;
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

/* SHA3 functions */
void
Digest_SHA3_224(benchmark::State& state, uint64_t block_size)
{
    alc_error_t    error;
    Uint8          message[32768] = { 0 };
    Uint8          digest[512]    = { 0 };
    AlcpDigestBaseSHA3 adb(ALC_SHA3_224, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_224);
    DigestBaseSHA3*    db = &adb;

#ifdef USE_OSSL
    OpenSSLDigestBaseSHA3 odb(
        ALC_SHA3_224, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_224);
    if (useossl) {
        db = &odb;
    }
#endif

    for (auto _ : state) {
        error =
            db->digest_function(message, block_size, digest, sizeof(digest));
        db->reset();
        if (alcp_is_error(error)) {
            printf("Error in running benchmark");
            return;
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

void
Digest_SHA3_256(benchmark::State& state, uint64_t block_size)
{
    alc_error_t    error;
    Uint8          message[32768] = { 0 };
    Uint8          digest[512]    = { 0 };
    AlcpDigestBaseSHA3 adb(ALC_SHA3_256, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_256);
    DigestBaseSHA3*    db = &adb;

#ifdef USE_OSSL
    OpenSSLDigestBaseSHA3 odb(
        ALC_SHA3_256, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_256);
    if (useossl) {
        db = &odb;
    }
#endif

    for (auto _ : state) {
        error =
            db->digest_function(message, block_size, digest, sizeof(digest));
        db->reset();
        if (alcp_is_error(error)) {
            printf("Error in running benchmark");
            return;
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

void
Digest_SHA3_384(benchmark::State& state, uint64_t block_size)
{
    alc_error_t    error;
    Uint8          message[32768] = { 0 };
    Uint8          digest[512]    = { 0 };
    AlcpDigestBaseSHA3 adb(ALC_SHA3_384, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_384);
    DigestBaseSHA3*    db = &adb;

#ifdef USE_OSSL
    OpenSSLDigestBaseSHA3 odb(
        ALC_SHA3_384, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_384);
    if (useossl) {
        db = &odb;
    }
#endif

    for (auto _ : state) {
        error =
            db->digest_function(message, block_size, digest, sizeof(digest));
        db->reset();
        if (alcp_is_error(error)) {
            printf("Error in running benchmark");
            return;
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

void
Digest_SHA3_512(benchmark::State& state, uint64_t block_size)
{
    alc_error_t    error;
    Uint8          message[32768] = { 0 };
    Uint8          digest[512]    = { 0 };
    AlcpDigestBaseSHA3 adb(ALC_SHA3_512, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_512);
    DigestBaseSHA3*    db = &adb;

#ifdef USE_OSSL
    OpenSSLDigestBaseSHA3 odb(
        ALC_SHA3_512, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_512);
    if (useossl) {
        db = &odb;
    }
#endif

    for (auto _ : state) {
        error =
            db->digest_function(message, block_size, digest, sizeof(digest));
        db->reset();
        if (alcp_is_error(error)) {
            printf("Error in running benchmark");
            return;
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

/* add all your new benchmarks here */
/* SHA3 benchmarks */
static void
BENCH_SHA3_224_16(benchmark::State& state) {
    Digest_SHA3_224(state, 16);
}
BENCHMARK(BENCH_SHA3_224_16);

static void
BENCH_SHA3_224_64(benchmark::State& state) {
    Digest_SHA3_224(state, 64);
}
BENCHMARK(BENCH_SHA3_224_64);

static void
BENCH_SHA3_224_256(benchmark::State& state) {
    Digest_SHA3_224(state, 256);
}
BENCHMARK(BENCH_SHA3_224_256);

static void
BENCH_SHA3_224_1024(benchmark::State& state) {
    Digest_SHA3_224(state, 1024);
}
BENCHMARK(BENCH_SHA3_224_1024);

static void
BENCH_SHA3_224_8192(benchmark::State& state) {
    Digest_SHA3_224(state, 8192);
}
BENCHMARK(BENCH_SHA3_224_8192);

static void
BENCH_SHA3_224_16384(benchmark::State& state) {
    Digest_SHA3_224(state, 16384);
}
BENCHMARK(BENCH_SHA3_224_16384);

static void
BENCH_SHA3_224_32768(benchmark::State& state) {
    Digest_SHA3_224(state, 32768);
}
BENCHMARK(BENCH_SHA3_224_32768);

/* SHA2 benchmarks */
static void
BENCH_SHA2_224_16(benchmark::State& state)
{
    Digest_SHA2_224(state, 16);
}
BENCHMARK(BENCH_SHA2_224_16);

static void
BENCH_SHA2_224_64(benchmark::State& state)
{
    Digest_SHA2_224(state, 64);
}
BENCHMARK(BENCH_SHA2_224_64);

static void
BENCH_SHA2_224_256(benchmark::State& state)
{
    Digest_SHA2_224(state, 256);
}
BENCHMARK(BENCH_SHA2_224_256);

static void
BENCH_SHA2_224_1024(benchmark::State& state)
{
    Digest_SHA2_224(state, 1024);
}
BENCHMARK(BENCH_SHA2_224_1024);

static void
BENCH_SHA2_224_8192(benchmark::State& state)
{
    Digest_SHA2_224(state, 8192);
}
BENCHMARK(BENCH_SHA2_224_8192);

static void
BENCH_SHA2_224_16384(benchmark::State& state)
{
    Digest_SHA2_224(state, 16384);
}
BENCHMARK(BENCH_SHA2_224_16384);

static void
BENCH_SHA2_224_32768(benchmark::State& state)
{
    Digest_SHA2_224(state, 32768);
}
BENCHMARK(BENCH_SHA2_224_32768);

/*256*/
/* add all your new benchmarks here */
static void
BENCH_SHA2_256_16(benchmark::State& state)
{
    Digest_SHA2_256(state, 16);
}
BENCHMARK(BENCH_SHA2_256_16);

static void
BENCH_SHA2_256_64(benchmark::State& state)
{
    Digest_SHA2_256(state, 64);
}
BENCHMARK(BENCH_SHA2_256_64);

static void
BENCH_SHA2_256_256(benchmark::State& state)
{
    Digest_SHA2_256(state, 256);
}
BENCHMARK(BENCH_SHA2_256_256);

static void
BENCH_SHA2_256_1024(benchmark::State& state)
{
    Digest_SHA2_256(state, 1024);
}
BENCHMARK(BENCH_SHA2_256_1024);

static void
BENCH_SHA2_256_8192(benchmark::State& state)
{
    Digest_SHA2_256(state, 8192);
}
BENCHMARK(BENCH_SHA2_256_8192);

static void
BENCH_SHA2_256_16384(benchmark::State& state)
{
    Digest_SHA2_256(state, 16384);
}
BENCHMARK(BENCH_SHA2_256_16384);

static void
BENCH_SHA2_256_32768(benchmark::State& state)
{
    Digest_SHA2_256(state, 32768);
}
BENCHMARK(BENCH_SHA2_256_32768);

/*384*/
static void
BENCH_SHA2_384_16(benchmark::State& state)
{
    Digest_SHA2_384(state, 16);
}
BENCHMARK(BENCH_SHA2_384_16);

static void
BENCH_SHA2_384_64(benchmark::State& state)
{
    Digest_SHA2_384(state, 64);
}
BENCHMARK(BENCH_SHA2_384_64);

static void
BENCH_SHA2_384_256(benchmark::State& state)
{
    Digest_SHA2_384(state, 256);
}
BENCHMARK(BENCH_SHA2_384_256);

static void
BENCH_SHA2_384_1024(benchmark::State& state)
{
    Digest_SHA2_384(state, 1024);
}
BENCHMARK(BENCH_SHA2_384_1024);

static void
BENCH_SHA2_384_8192(benchmark::State& state)
{
    Digest_SHA2_384(state, 8192);
}
BENCHMARK(BENCH_SHA2_384_8192);

static void
BENCH_SHA2_384_16384(benchmark::State& state)
{
    Digest_SHA2_384(state, 16384);
}
BENCHMARK(BENCH_SHA2_384_16384);

static void
BENCH_SHA2_384_32768(benchmark::State& state)
{
    Digest_SHA2_384(state, 32768);
}
BENCHMARK(BENCH_SHA2_384_32768);

/*SHA512*/
static void
BENCH_SHA2_512_16(benchmark::State& state)
{
    Digest_SHA2_512(state, 16);
}
BENCHMARK(BENCH_SHA2_512_16);

static void
BENCH_SHA2_512_64(benchmark::State& state)
{
    Digest_SHA2_512(state, 64);
}
BENCHMARK(BENCH_SHA2_512_64);

static void
BENCH_SHA2_512_256(benchmark::State& state)
{
    Digest_SHA2_512(state, 256);
}
BENCHMARK(BENCH_SHA2_512_256);

static void
BENCH_SHA2_512_1024(benchmark::State& state)
{
    Digest_SHA2_512(state, 1024);
}
BENCHMARK(BENCH_SHA2_512_1024);

static void
BENCH_SHA2_512_8192(benchmark::State& state)
{
    Digest_SHA2_512(state, 8192);
}
BENCHMARK(BENCH_SHA2_512_8192);

static void
BENCH_SHA2_512_16384(benchmark::State& state)
{
    Digest_SHA2_512(state, 16384);
}
BENCHMARK(BENCH_SHA2_512_16384);

static void
BENCH_SHA2_512_32768(benchmark::State& state)
{
    Digest_SHA2_512(state, 32768);
}
BENCHMARK(BENCH_SHA2_512_32768);
