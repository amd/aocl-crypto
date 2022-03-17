#pragma once
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include "alc_base.hh"
#include "base.hh"
#include "string.h"
#include "gtest_base.hh"

using namespace alcp::bench;

void
Digest_SHA2_224(benchmark::State& state, uint64_t block_size) {
    alc_error_t error;
    alc_digest_handle_t handle;
    /*update this*/
    uint8_t * message = (uint8_t*)malloc(16384);
    uint8_t * digest = (uint8_t*)malloc(512);
    for (auto _ : state) {
        AlcpDigestBase DigestBase(&handle, ALC_SHA2_224, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_224);
        error = DigestBase.digest_function(&handle, message, block_size, digest, sizeof(digest));
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }
        alcp_digest_finish(&handle);
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(state.iterations() * block_size,
                                                        benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    free(message);
    free(digest);
    return;
}

/* add all your new benchmarks here */
static void
BENCH_SHA2_224_16(benchmark::State& state) {
    Digest_SHA2_224(state, 16);
}
BENCHMARK(BENCH_SHA2_224_16);

static void
BENCH_SHA2_224_64(benchmark::State& state) {
    Digest_SHA2_224(state, 64);
}
BENCHMARK(BENCH_SHA2_224_64);

static void
BENCH_SHA2_224_256(benchmark::State& state) {
    Digest_SHA2_224(state, 256);
}
BENCHMARK(BENCH_SHA2_224_256);

static void
BENCH_SHA2_224_1024(benchmark::State& state) {
    Digest_SHA2_224(state, 1024);
}
BENCHMARK(BENCH_SHA2_224_1024);

static void
BENCH_SHA2_224_8192(benchmark::State& state) {
    Digest_SHA2_224(state, 8192);
}
BENCHMARK(BENCH_SHA2_224_8192);

static void
BENCH_SHA2_224_16384(benchmark::State& state) {
    Digest_SHA2_224(state, 16384);
}
BENCHMARK(BENCH_SHA2_224_16384);