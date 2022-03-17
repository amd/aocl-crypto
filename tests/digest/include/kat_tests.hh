#pragma once
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include "alc_base.hh"
#include "base.hh"
#include "string.h"
#include "gtest_base.hh"

using namespace alcp::bench;

/* to test using KAT vectors */
void
Digest_SHA2_224_KAT() {
    alc_error_t error;
    alc_digest_handle_t handle;

    DataSet ds = DataSet("/home/pjayaraj/aocl-crypto/bench/digest_new/test_data/dataset_SHA_224.csv");
    uint8_t * message = &(ds.getMessage()[0]);
    //uint8_t * expected = &(ds.getDigest()[0]);
    uint8_t * digest = (uint8_t*)malloc(512);

    uint64_t input_size = ds.getMessage().size();
    AlcpDigestBase DigestBase(&handle, ALC_SHA2_224, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_224);
    error = DigestBase.digest_function(&handle, message, input_size, digest, sizeof(digest));
    if (alcp_is_error(error)) {
        printf("Error");
        return;
    }
    alcp_digest_finish(&handle);
    free(digest);
    return;
}
