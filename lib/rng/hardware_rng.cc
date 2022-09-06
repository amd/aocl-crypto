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

#include <cstdlib>

// Enable debug for debugging the code
// #define DEBUG

#include "hardware_rng.hh"

#ifdef USE_AOCL_SRNG
#include "secrng.h"
#endif

namespace alcp::random_number {

class HardwareRngImpl
{
  public:
    static alc_error_t randomize(Uint8 output[], size_t length)
    {
#ifdef DEBUG
        printf("Engine hardware_randomize\n");
#endif
#ifdef USE_AOCL_SRNG
        int opt;
        opt = get_rdrand_bytes_arr(
            output,
            length,
            100 // Retires is hard coded as 100, may be add this to context.
        );
        if (opt != SECRNG_SUCCESS) {
            return ALC_ERROR_NO_ENTROPY;
        } else {
            return ALC_ERROR_NONE;
        }
#else
        return ALC_ERROR_NOT_SUPPORTED; // Error not implemented
#endif
    }
};

HardwareRng::HardwareRng(const alc_rng_info_t& rRngInfo)
//: m_pimpl{ std::make_unique<SystemRng::Impl>() }
{
    // UNUSED(rRngInfo);
}

alc_error_t
HardwareRng::randomize(Uint8 output[], size_t length)
{
    return HardwareRngImpl::randomize(output, length);
}

bool
HardwareRng::isSeeded() const
{
    return true;
}

size_t
HardwareRng::reseed()
{
    return 0;
}

} // namespace alcp::random_number
