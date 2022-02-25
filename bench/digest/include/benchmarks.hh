#ifndef BENCHMARKS_HH_
#define BENCHMARKS_HH_

#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include "common.hh"
#include "perf.hh"
#include "conf.hh"

static void
HashConformanceTest_SHA2_224(benchmark::State& state)
{
    RunHashConformanceTest(ALC_SHA2_224);
    return;
}
BENCHMARK(HashConformanceTest_SHA2_224);

static void
HashConformanceTest_SHA2_256(benchmark::State& state)
{
    RunHashConformanceTest(ALC_SHA2_256);
    return;
}
BENCHMARK(HashConformanceTest_SHA2_256);

static void
HashPerformanceTest_SHA2_224(benchmark::State& state)
{
    for (auto _ : state) {
        //for(int i=0; i<PERF_TEST_LOOP; i++) {
            benchmark::DoNotOptimize(RunHashPerformanceTest(ALC_SHA2_224));
        //}
    }
    state.counters["MOPS"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
    return;
}
BENCHMARK(HashPerformanceTest_SHA2_224);

static void
HashPerformanceTest_SHA2_256(benchmark::State& state)
{
    for (auto _ : state) {
        //for(int i=0; i<PERF_TEST_LOOP; i++) {
            benchmark::DoNotOptimize(RunHashPerformanceTest(ALC_SHA2_256));
        //}
    }
    state.counters["MOPS"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
    return;
}
BENCHMARK(HashPerformanceTest_SHA2_256);

#endif  //BENCHMARKS_HH