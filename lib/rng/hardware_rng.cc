/*
 * Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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

#include "hardware_rng.hh"
#include "alcp/base.hh"
#include "alcp/utils/copy.hh"

#include <algorithm>
#include <immintrin.h>

namespace alcp::rng {

#define ATTRIBUTE_RAND __attribute__((__target__("rdrnd")))
//
// in C++20 Use
// std::is_trivial<T>::value && std::is_standard_layout<T>::value
// instead of std::is_pod

template<typename T,
         size_t W,
         typename = typename std::enable_if<sizeof(T) == W>::type>
bool
read_rdrand(T* ptr) __attribute__((__target__("rdrnd")));

/**
 * Read random bytes from hardware Rng on x86
 *
 * \param        success         Updates status in this variable
 *                               received by reference
 * \param        T               Should be an simple-integer type
 */
template<typename T = Uint16>
bool ATTRIBUTE_RAND
read_rdrand(T* ptr)
{
    int rc = 0;
    T   result;

    rc   = _rdrand16_step(&result);
    *ptr = result;

    return (1 == rc);
}

#if 0
    template<typename T = Uint32>
    bool ATTRIBUTE_RAND read_rdrand(T* ptr)
    {
        int rc = 0;
        T   result;

        rc   = _rdrand32_step(&result);
        *ptr = result;

        return (1 == rc);
    }

    template<typename T>
    inline bool read_rdrand(T* ptr, std::is_same<sizeof(T), sizeof(Uint64)>)
    {
        int rc = 0;
        T   result;

        rc   = _rdrand64_step(&result);
        *ptr = result;

        return (1 == rc);
    }
#endif

HardwareRng::HardwareRng()
//: m_pimpl{ std::make_unique<HardwareRng::Impl>() }
{
    // UNUSED(rRngInfo);
}

alc_error_t
HardwareRng::readRandom(Uint8* buf, size_t length)
{
    return randomize(buf, length);
}

// AMD and Intel both document ten retries as enough to ride out transient
// exhaustion of the on-chip entropy buffer. A failure that survives ten
// attempts means the generator is broken or not passed through, not busy.
static constexpr int RdRandRetryCount = 10;

alc_error_t
HardwareRng::randomize(Uint8 output[], size_t length)
{
    constexpr size_t cWordSize = sizeof(Uint16);

    size_t remaining = length;
    Uint8* p_output  = output;

    while (remaining) {
        Uint16 word = 0;

        bool is_success = false;
        for (int i = 0; i < RdRandRetryCount && !is_success; i++) {
            is_success = read_rdrand<Uint16>(&word);
        }
        if (!is_success) {
            // No Entropy
            return ALC_ERROR_NO_ENTROPY;
        }

        // output may be arbitrarily aligned, so the word is copied out
        // byte-wise rather than stored through a Uint16 pointer.
        const size_t bytes = std::min(remaining, cWordSize);
        utils::CopyBytes(p_output, &word, bytes);

        p_output += bytes;
        remaining -= bytes;
    }

    return ALC_ERROR_NONE;
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

alc_error_t
HardwareRng::setPredictionResistance(bool value)
{
    m_prediction_resistance = value;
    return ALC_ERROR_NONE;
}

} // namespace alcp::rng
