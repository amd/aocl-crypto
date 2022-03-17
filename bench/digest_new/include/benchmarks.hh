#pragma once
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include "alc_base.hh"
#include "base.hh"
#include "string.h"
#include "gtest_base.hh"

using namespace alcp::bench;

/* add all your new benchmark tests here */
static void
BENCHMARK_SHA_2_224(benchmark::State& state) {
    alc_error_t error;
    alc_digest_handle_t handle;
    /*update this*/
    DataSet ds = DataSet("/home/pjayaraj/aocl-crypto/bench/digest_new/test_data/dataset_SHA_224.csv");

    uint64_t input_size;
    while (ds.readMsgDigest()) {
        for (auto _ : state) { 
            AlcpDigestBase DigestBase(&handle, ALC_SHA2_224, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_224);
            uint8_t * message = &(ds.getMessage()[0]);
            //uint8_t * expected = &(ds.getDigest()[0]);
            uint8_t digest[512] = { 0 };
            input_size = ds.getMessage().size();
            error = DigestBase.digest_function(&handle, message, ds.getMessage().size(), digest, sizeof(digest));
            if (alcp_is_error(error)) {
                printf("Error");
            }
            alcp_digest_finish(&handle);
            //check op and expected
        }
        state.counters["Speed(Bits/Sec)"] = benchmark::Counter(state.iterations() * input_size * 8,
                                                    benchmark::Counter::kIsRate);
        state.counters["InputSize(Bytes)"] = input_size;
    }
    return;
}
BENCHMARK(BENCHMARK_SHA_2_224);