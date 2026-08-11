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

#include "Fuzz/alcp_fuzz_test.hh"

bool
TestRngNegLifecycle_0(alc_rng_handle_p handle,
                      Uint8*           output,
                      Uint64           size_output)
{
    if (alcp_is_error(alcp_rng_gen_random(handle, &output[0], size_output))
        || alcp_is_error(alcp_rng_finish(handle))
        || alcp_is_error(
            alcp_rng_gen_random(handle, &output[0], size_output))) {
        std::cout << "Neg lifecycle Test FAIL!-> randomize->finish->randomize"
                  << std::endl;
        return false;
    }
    return true;
}

int
ALCP_Fuzz_Rng(const Uint8* buf, size_t len, bool TestNegLifecycle)
{
    FuzzedDataProvider stream(buf, len);

    size_t             size_output = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> output(size_output, 0);

    std::cout << "Generating for output size: " << size_output << std::endl;

    alc_rng_source_t source = ALC_RNG_SOURCE_OS;
    alc_rng_handle_p handle = new alc_rng_handle_t;
    alc_rng_info_t   rng_info;

    int rng_randomize_call_count;

    static std::uniform_int_distribution<int> id(1, 100);
    rng_randomize_call_count = id(rng);

    rng_info.ri_distrib = ALC_RNG_DISTRIB_UNIFORM;
    rng_info.ri_source  = source;
    rng_info.ri_type    = ALC_RNG_TYPE_DISCRETE;

    if (alcp_rng_supported(&rng_info) != ALC_ERROR_NONE) {
        std::cout << "Error: alcp_rng_supported" << std::endl;
        goto rng_dealloc_exit;
    }
    handle->rh_context = malloc(alcp_rng_context_size(&rng_info));
    if (handle->rh_context == nullptr) {
        std::cout << "Error: alcp_rng_context_size" << std::endl;
        goto rng_dealloc_exit;
    }
    if (alcp_rng_request(&rng_info, handle) != ALC_ERROR_NONE) {
        std::cout << "Error: alcp_rng_request" << std::endl;
        goto rng_dealloc_exit;
    }
    if (TestNegLifecycle) {
        if (!TestRngNegLifecycle_0(handle, &output[0], size_output))
            goto rng_dealloc_exit;
    } else {
        for (int i = 0; i < rng_randomize_call_count; i++) {
            std::cout << "Calling alcp_rng_gen_random for iteration:" << i
                      << std::endl;
            if (alcp_rng_gen_random(handle, &output[0], size_output)
                != ALC_ERROR_NONE) {
                std::cout << "Error: alcp_rng_gen_random" << std::endl;
                goto rng_dealloc_exit;
            }
        }
    }
    goto rng_exit;

rng_dealloc_exit:
    alcp_rng_finish(handle);
    if (handle->rh_context) {
        free(handle->rh_context);
        handle->rh_context = nullptr;
    }
    delete (handle);
    handle = nullptr;
    return -1;

rng_exit:
    alcp_rng_finish(handle);
    if (handle->rh_context) {
        free(handle->rh_context);
        handle->rh_context = nullptr;
    }
    delete (handle);
    handle = nullptr;
    /* Check if Output is not null/all zeros */
    bool zeros =
        std::all_of(output.begin(), output.end(), [](int i) { return i == 0; });
    if (output.empty() || zeros) {
        std::cout << "Error! Empty output generated for size: " << size_output
                  << std::endl;
        return -1;
    }
    std::cout << "Passed for output size: " << size_output << std::endl;
    return 0;
}
