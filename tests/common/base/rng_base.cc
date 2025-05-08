/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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
#include <iostream>
#include <malloc.h>
namespace alcp::testing {

RngBase::RngBase()
{
    alc_rng_info_t rng_info;

    // Using CAPI for RNG we initialize OS RNG for best performance
    rng_info.ri_distrib =
        ALC_RNG_DISTRIB_UNIFORM; // Output should be uniform probablilty
    rng_info.ri_source = ALC_RNG_SOURCE_OS;     // Use OS RNG
    rng_info.ri_type   = ALC_RNG_TYPE_DISCRETE; // Discrete output (uint8)

    /* Check if RNG mode is supported with RNG info */
    if (alcp_rng_supported(&rng_info) != ALC_ERROR_NONE) {
        try {
            throw "RNG not supported";
        } catch (const char* exc) {
            std::cerr << exc << std::endl;
        }
    }

    // Assuming this is the first run, allocate and request for a handle.
    m_handle.rh_context = malloc(alcp_rng_context_size(&rng_info));
    if (alcp_rng_request(&rng_info, &m_handle) != ALC_ERROR_NONE) {
        try {
            throw "RNG request failed!";
        } catch (const char* exc) {
            std::cerr << exc << std::endl;
        }
    }

    // Intialize internal PRNG for faster RNG with reproducability
    std::vector<Uint8> seed_v = genRandomBytes(sizeof(Uint64));
    std::copy(&seed_v[0],
              &seed_v[0] + seed_v.size(),
              reinterpret_cast<Uint8*>(&m_seed_));
    mt_rand_ = std::mt19937(m_seed_); // Initialize with a random seed
}

RngBase::~RngBase()
{
    if (m_handle.rh_context != nullptr) {
        alcp_rng_finish(&m_handle);
        free(m_handle.rh_context);
        m_handle.rh_context = nullptr;
    }
}

std::vector<Uint8>
RngBase::genRandomBytes(std::size_t l)
{
    std::vector<Uint8> ret = {};
    if (l == 0) {
        return ret;
    }
    ret = std::vector<Uint8>(l, 0);
    if (alcp_rng_gen_random(&m_handle, &(ret[0]), l) == ALC_ERROR_NO_ENTROPY) {
        try {
            throw "rng_base.cc : Bail out! not enough entropy!";
        } catch (const char* exc) {
            std::cerr << exc << std::endl;
        }
    }
    return ret;
}

// We can optimize by assuming 64 bit (8byte) alignment of buffer
void
RngBase::genRandomMt19937(std::vector<Uint8>& buffer)
{
    {
        size_t iter = buffer.size() / 4;
        for (size_t i = 0; i < iter; i++) {
            Uint32 r   = mt_rand_();
            Uint8* r_8 = reinterpret_cast<Uint8*>(&r);
            std::copy(r_8, r_8 + 4, (&buffer[0]) + (i * 4));
        }
    }
    {
        int rem = buffer.size() % 4;
        if (rem) {
            Uint32 r   = mt_rand_();
            Uint8* r_8 = reinterpret_cast<Uint8*>(&r);
            std::copy(
                r_8, r_8 + rem, ((&buffer[0]) + (buffer.size() - 1) - rem));
        }
    }
}

void
RngBase::setSeedMt19937(Uint64 seed)
{
    m_seed_  = seed;
    mt_rand_ = std::mt19937(m_seed_); // Initialize with the random seed
}

Uint64
RngBase::getSeedMt19937()
{
    return m_seed_;
}

} // namespace alcp::testing