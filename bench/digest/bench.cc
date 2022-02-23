#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include "common.hh"

/*move these to a different file later on */
static void
HashTest(benchmark::State& state)
{
    RunHashConformanceTest(ALC_SHA2_224);
    return;
}
BENCHMARK(HashTest);

int main(int argc, char** argv) {
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();
    return 0;
}

