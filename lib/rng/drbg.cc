/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "rng/drbg.hh"
#include "alcp/base.hh"
#include "rng.hh"
#include <memory>

namespace alcp::rng {

// FIXME: Predicition resistance is to be added
Status
Drbg::initialize(int                 security_strength,
                 std::vector<Uint8>& personalization_string)
{
    Status s = StatusOk();
#if 0
            /*
                FIXME: Implement Security Strength
                getCurrMinSecurity() -> Implemented in HMAC_Drbg
                Calling the above function returns the min security strength.
            */
            if (security_strength < get_curr_min_security()) {
                // Bail out
                // Return error here
                s = alcp::base::InternalError(
                    "ERROR: Requested algorithm does not meet min requirements "
                    "for security level specified.");
                return s;
            }
#endif
    std::vector<Uint8> entropy_input(128);
    std::vector<Uint8> nonce(128);

    s = m_entropy_in->randomize(&entropy_input[0], entropy_input.size());
    if (!s.ok()) {
        return s;
    }

    s = m_entropy_in->randomize(&nonce[0], nonce.size());
    if (!s.ok()) {
        return s;
    }

    instantiate(entropy_input, nonce, personalization_string);
    return s;
}

// FIXME: Predicition resistance is to be added
Status
Drbg::randomize(Uint8               output[],
                size_t              length,
                int                 security_strength,
                std::vector<Uint8>& additional_input)
{
    Status s = StatusOk();
#if 0
            // TODO: Enable after implementing
            /*
                FIXME: Implement Max Generate Bits
                getMaxAllowedBits() -> Implemented in HMAC_Drbg
                Calling the above function returns the current security strength.
            */
            if (length > getMaxAllowedBits()) {
                s = InternalError(
                    "ERROR: Impossible amount of bits to generate per call");
                return s;
            }
            /*
                FIXME: Implement Security Strength
                getCurrSecurityStrength() -> Implemented in HMAC_Drbg
                Calling the above function returns the current security strength.
            */
            if (security_strength >= getCurrSecurityStrength()) {
                // Bail out
                // Return error here
                s = alcp::base::InternalError(
                    "ERROR: Requested algorithm does not meet min requirements "
                    "for security level specified.");
                return s;
            }
            /*
                FIXME: Implement Max Additional Input Length
                getMaxGeneratableBits() -> Implemented in HMAC_Drbg
                Calling the above function returns the current security strength.
            */
            if(additional_input.size()> getMaxAddInputLength()){
                s = InternalError(
                    "ERROR: Additional Input too large");
                return s;
            }
            // FIXME: Handle Predicition Resistance Request
            // FIXME: Handle reseed required flag
#endif
    generate(&additional_input[0], additional_input.size(), output, length);
    return s;
}

Status
Drbg::randomize(Uint8 output[], size_t length)
{
    std::vector<Uint8> add = std::vector<Uint8>(0);
    return randomize(output, length, 512, add);
}

} // namespace alcp::rng
