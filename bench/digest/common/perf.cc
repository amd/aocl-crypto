#include "perf.hh"
#include "digest_data_perf.hh"
#include "common.hh"
#include "utils.hh"

int
RunHashPerformanceTest(benchmark::State& state,
		               _alc_sha2_mode digest_mode)
{
    _alc_hash_test_data test_data;
    /* Add more SHA digest cases here */
    switch (digest_mode)
    {
    case ALC_SHA2_224:
        RunHashPerformance(state, digest_mode, &test_data, STRING_VECTORS_PERF_SHA224);
        break;
    case ALC_SHA2_256:
        RunHashPerformance(state, digest_mode, &test_data, STRING_VECTORS_PERF_SHA256);
        break;
    case ALC_SHA2_384:
        RunHashPerformance(state, digest_mode, &test_data, STRING_VECTORS_PERF_SHA384);
        break;
    case ALC_SHA2_512:
        RunHashPerformance(state, digest_mode, &test_data, STRING_VECTORS_PERF_SHA512);
        break;
    default:
        break;
    }
    return 0;
}

/* run perf tests, get BitsPerSecond*/
/*Later, feed this with a different perf test data? */
int
RunHashPerformance(benchmark::State& state,
                   _alc_sha2_mode digest_mode,
                   _alc_hash_test_data * test_data,
                   std::vector <_alc_hash_kat_vector> test_vector)
{
    /* run with random data? or an array? */
    /* do we need a loop here?*/
    test_data->input_data = test_vector[0].input;
    size_t input_len = strlen(test_data->input_data);
    for (auto _ : state) {
        test_hash(digest_mode, test_data);
    }
    state.counters["Bits/Sec"] = benchmark::Counter(state.iterations() * input_len * 8,
                                                    benchmark::Counter::kIsRate);
    state.counters["InputSize(Bytes)"] = input_len;
    return 0;
}
