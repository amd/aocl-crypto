#ifndef BENCHMARKS_HH_
#define BENCHMARKS_HH_

#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include "common.hh"

/*conformance*/
static void
CipherConformanceTest_AES_CBC(benchmark::State& state)
{
    cipher_test(state, ALC_AES_MODE_CBC, ALC_TEST_CIPHER_CONF);
    return;
}
BENCHMARK(CipherConformanceTest_AES_CBC);

/*perf tests*/
static void
CipherPerformanceTest_AES_CBC(benchmark::State& state)
{
    benchmark::DoNotOptimize(cipher_test(state, ALC_AES_MODE_CBC, ALC_TEST_CIPHER_PERF));
    return;
}
BENCHMARK(CipherPerformanceTest_AES_CBC);

#endif  //BENCHMARKS_HH