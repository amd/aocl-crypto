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

#include "system_rng.hh"
// Enable debug for debugging the code
// #define DEBUG

namespace alcp::random_number {

#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#define ALCP_CONFIG_OS_HAS_DEVRANDOM 1
#else
#include <sys/random.h>
#define ALCP_CONFIG_OS_HAS_GETRANDOM 1
#endif

#if defined(ALCP_CONFIG_OS_HAS_DEVRANDOM)

class SystemRngImpl
{
  private:
  public:
    SystemRngImpl() {}

    ~SystemRngImpl() {}

    static alc_error_t randomize(Uint8 output[], size_t length)
    {
#ifdef DEBUG
        printf("Engine system_randomize_devrandom\n");
#endif
        static int m_fd = -1;
        size_t     out  = 0;

        if (m_fd < 0) {
            m_fd = open("/dev/urandom", O_RDONLY | O_NOCTTY);
            if (m_fd < 0) {
                return ALC_ERROR_NOT_PERMITTED;
            }
        }

        for (int i = 0; i < 10; i++) {
            if (out < length) {
                auto delta = length - out;
                out += read(m_fd, &output[out], delta);
            } else {
                break;
            }
        }
        if (out != length) // not enough entropy , throw here,
            return ALC_ERROR_NO_ENTROPY;
        return ALC_ERROR_NONE;
    }
};

#elif defined(ALCP_CONFIG_OS_HAS_GETRANDOM)

class SystemRngImpl
{
  public:
    static alc_error_t randomize(Uint8 output[], size_t length)
    {
#ifdef DEBUG
        printf("Engine system_randomize_getrandom\n");
#endif
        const int flag = 0;
        size_t    out  = getrandom(&output[0], length, flag);

        for (int i = 0; i < 10; i++) {
            if (out < length) {
                auto delta = length - out;
                out += getrandom(&output[out], delta, flag);
            } else {
                break;
            }
        }

        if (out != length) // not enough entropy , throw here,
            return ALC_ERROR_NO_ENTROPY;

        return ALC_ERROR_NONE;
    }
};

#endif

SystemRng::SystemRng(const alc_rng_info_t& rRngInfo)
//: m_pimpl{ std::make_unique<SystemRng::Impl>() }
{
    // UNUSED(rRngInfo);
}

alc_error_t
SystemRng::randomize(Uint8 output[], size_t length)
{
    return SystemRngImpl::randomize(output, length);
}

bool
SystemRng::isSeeded() const
{
    return true;
}

size_t
SystemRng::reseed()
{
    return 0;
}

} // namespace alcp::random_number
