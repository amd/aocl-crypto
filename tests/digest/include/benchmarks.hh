#pragma once
#include <alcp/alcp.h>
#include <iostream>
#include "alc_base.hh"
#include "base.hh"
#include "string.h"
#include "gtest_base.hh"

using namespace alcp::bench;

/* Add all the KAT tests here */
TEST(DIGEST_SHA2, KAT_224) {
    alc_error_t error;
    DataSet ds = DataSet("dataset_SHA_224.csv");
    while (ds.readMsgDigest()) {
        AlcpDigestBase DigestBase(ALC_SHA2_224, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_224);
        uint8_t * message = &(ds.getMessage()[0]);
        uint8_t * expected = &(ds.getDigest()[0]);
        uint8_t digest [512] = { 0 };
        error = DigestBase.digest_function(message, ds.getMessage().size(), digest, sizeof(digest));
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }
        /*now check expected and actual */
        std::vector<uint8_t>output_vec(digest, digest+ sizeof(digest)/sizeof(digest[0]));
        std::vector<uint8_t>expected_vec(expected, expected + sizeof(expected)/sizeof(expected[0]));

        EXPECT_TRUE(ArraysMatch(
            ds.getDigest(),  //output
            ds.getDigest(),  //expected, from the KAT test data
            ds,
            std::string("SHA2_224_KAT")));
    }

}
