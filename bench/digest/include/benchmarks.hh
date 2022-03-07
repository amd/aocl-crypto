#ifndef BENCHMARKS_HH_
#define BENCHMARKS_HH_

#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include "common.hh"
#include "perf.hh"
#include "conf.hh"

/*conformance*/
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
HashConformanceTest_SHA2_384(benchmark::State& state)
{
    RunHashConformanceTest(ALC_SHA2_384);
    return;
}
BENCHMARK(HashConformanceTest_SHA2_384);

static void
HashConformanceTest_SHA2_512(benchmark::State& state)
{
    RunHashConformanceTest(ALC_SHA2_512);
    return;
}
BENCHMARK(HashConformanceTest_SHA2_512);

/*perf tests*/
static void
HashPerformanceTest_SHA2_224(benchmark::State& state)
{
    benchmark::DoNotOptimize(RunHashPerformanceTest(state, ALC_SHA2_224));
    return;
}
BENCHMARK(HashPerformanceTest_SHA2_224);

static void
HashPerformanceTest_SHA2_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(RunHashPerformanceTest(state, ALC_SHA2_256));
    return;
}
BENCHMARK(HashPerformanceTest_SHA2_256);

static void
HashPerformanceTest_SHA2_384(benchmark::State& state)
{
    benchmark::DoNotOptimize(RunHashPerformanceTest(state, ALC_SHA2_384));
    return;
}
BENCHMARK(HashPerformanceTest_SHA2_384);

static void
HashPerformanceTest_SHA2_512(benchmark::State& state)
{
    benchmark::DoNotOptimize(RunHashPerformanceTest(state, ALC_SHA2_512));
    return;
}
BENCHMARK(HashPerformanceTest_SHA2_512);

#endif  //BENCHMARKS_HH