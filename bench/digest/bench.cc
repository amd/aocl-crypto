#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include "common.hh"

/*move these to a different file later on */
static void
HashConformanceTest(benchmark::State& state)
{
    RunHashConformanceTest(ALC_SHA2_224);
    return;
}
BENCHMARK(HashConformanceTest);

static void
HashPerformanceTest(benchmark::State& state)
{
    for (auto _ : state) {
        for(int i=0; i<PERF_TEST_LOOP; i++) {
            benchmark::DoNotOptimize(RunHashPerformanceTest(ALC_SHA2_224));
        }
    }
    state.counters["MOPS"] = benchmark::Counter(state.iterations()*PERF_TEST_LOOP, benchmark::Counter::kIsRate);
    return;
}
BENCHMARK(HashPerformanceTest);

int main(int argc, char** argv) {
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();
    return 0;
}

