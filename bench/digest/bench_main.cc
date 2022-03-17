#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include "alc_base.hh"
#include "base.hh"
#include "string.h"
#include "gtest_base.hh"
#include "benchmarks.hh"

int main(int argc, char** argv) {
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();
    return 0;
}