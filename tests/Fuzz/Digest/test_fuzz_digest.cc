/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include "../../include/Fuzz/alcp_fuzz_test.hh"
#include "alcp/alcp.h"
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <stddef.h>
#include <stdint.h>
#include <unordered_map>

std::unordered_map<alc_digest_mode_t, Uint64> MODE_SIZE = {
    { ALC_SHA2_224, 28 }, { ALC_SHA2_256, 32 },     { ALC_SHA2_384, 48 },
    { ALC_SHA2_512, 64 }, { ALC_SHA2_512_224, 28 }, { ALC_SHA2_512_224, 32 },
    { ALC_SHA3_224, 28 }, { ALC_SHA3_256, 32 },     { ALC_SHA3_384, 48 },
    { ALC_SHA3_512, 64 }, { ALC_SHAKE_128, 1 },     { ALC_SHAKE_256, 1 }
};
const int ERR_SIZE = 256;
Uint8     err_buf[ERR_SIZE];
void
Check_Error(alc_error_t err)
{
    if (alcp_is_error(err)) {
        alcp_error_str(err, err_buf, ERR_SIZE);
    }
}

// TEST(ALCP, FUZZ_DIGEST)
// {
//     EXPECT_TRUE(true);
// }

int
FuzzerTestOneInput(const Uint8* buf, size_t len)
{
    const Uint8* src     = buf;
    Uint32       srcSize = len;

    /* Initializing digest info */
    alc_error_t         err;
    alc_digest_handle_p m_handle = new alc_digest_handle_t;

    // Change the digest mode here to run SHA2 and SHA3 variants
    alc_digest_mode_t mode     = ALC_SHAKE_256;
    Uint32            out_size = MODE_SIZE[mode];
    if (out_size == 0) { // For modes that are not part of MODE_SIZE
        std::cout << mode << " is not supported. Exiting.." << std::endl;
        return 0;
    } else if (out_size == 1) { // SHAKE Variants
        FuzzedDataProvider stream(buf, len);
        out_size = stream.ConsumeIntegral<Uint32>();
    }
    Uint8 output1[out_size], output2[out_size];

    /* Start to Fuzz Digest APIs */
    FuzzedDataProvider stream(buf, len);
    Uint64 context_size = alcp_digest_context_size(); // Context_size = 96

    if ((m_handle == nullptr)) {
        std::cout << "Error: Mem alloc for digest handle" << std::endl;
        goto OUT;
    }
    /* Request a context with dinfo */
    m_handle->context = malloc(context_size);
    if ((m_handle->context == nullptr)) {
        std::cout << "Error: Mem alloc for digest context" << std::endl;
        goto OUT;
    }
    err = alcp_digest_request(mode, m_handle);
    Check_Error(err);
    err = alcp_digest_init(m_handle);
    Check_Error(err);
    err = alcp_digest_update(m_handle, src, srcSize);
    Check_Error(err);
    err = alcp_digest_finalize(m_handle, output1, out_size);
    Check_Error(err);

    goto CLOSE;

CLOSE:
    if (m_handle != nullptr) {
        alcp_digest_finish(m_handle);
        free(m_handle->context);
        delete m_handle;
    }

OUT:
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    // DoSomethingInterestingWithMyAPI(Data, Size);
    return FuzzerTestOneInput(Data, Size);
    // return 0;  // Values other than 0 and -1 are reserved for future use.
}

// int
// main(int argc, char** argv)
// {
//     ::testing::InitGoogleTest(&argc, argv);
//     return RUN_ALL_TESTS();
// }