/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

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
        uint8_t digest[512] = { 0 };
        char digest_output_string[57] = {0};

        error = DigestBase.digest_function(ds.getMessage(), ds.getMessage().size(), digest, sizeof(digest));
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }

        DigestBase.hash_to_string(digest_output_string, digest, 224);

        /*now check expected and actual */
        std::vector<uint8_t> output_vec(digest_output_string, 
                            digest_output_string + 
                            sizeof digest_output_string / sizeof digest_output_string[0]);

        EXPECT_TRUE(ArraysMatch(
            output_vec,  //output
            ds.getDigest(),  //expected, from the KAT test data
            ds,
            std::string("SHA2_224_KAT")));
    }
}

