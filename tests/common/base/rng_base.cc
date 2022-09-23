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
#include "rng_base.hh"
#include <malloc.h>
namespace alcp::testing {

RngBase::RngBase()
{
    alc_rng_info_t rng_info;
    rng_info.ri_distrib =
        ALC_RNG_DISTRIB_UNIFORM; // Output should be uniform probablilty
    rng_info.ri_source = ALC_RNG_SOURCE_OS;     // Use OS RNG
    rng_info.ri_type   = ALC_RNG_TYPE_DESCRETE; // Discrete output (uint8)
    /* Check if RNG mode is supported with RNG info */
    if (alcp_rng_supported(&rng_info) != ALC_ERROR_NONE) {
        printf("Support Failed!\n");
        throw "RNG not supported";
    }
    if (m_handle.rh_context != nullptr) {
        free(m_handle.rh_context);
    }
    m_handle.rh_context = malloc(alcp_rng_context_size(&rng_info));
    if (alcp_rng_request(&rng_info, &m_handle) != ALC_ERROR_NONE) {
        printf("Request Failed!\n");
        throw "RNG request failed!";
    }
}
RngBase::~RngBase()
{
    alcp_rng_finish(&m_handle);
    free(m_handle.rh_context);
}
std::vector<Uint8>
RngBase::genRandomBytes(std::size_t l)
{
    std::vector<Uint8> ret(l, 0);
    if (alcp_rng_gen_random(&m_handle, &(ret[0]), l) == ALC_ERROR_NO_ENTROPY) {
        throw "rng_base.cc : Bail out! not enough entropy!";
    }
    return ret;
}
} // namespace alcp::testing