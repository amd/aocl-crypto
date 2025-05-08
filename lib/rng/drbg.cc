/*
 * Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"

#include "alcp/rng.hh"
#include "alcp/rng/drbg.hh"
#include <memory>

namespace alcp::rng {

alc_error_t
Drbg::initialize(int                 cSecurityStrength,
                 std::vector<Uint8>& personalization_string)
{
    alc_error_t err{ ALC_ERROR_NONE };
#if 0
        /*
            FIXME: Implement Security Strength
            getCurrMinSecurity() -> Implemented in HMAC_Drbg
            Calling the above function returns the min security strength.
        */
        if (cSecurityStrength < get_curr_min_security()) {
            // Bail out
            // Return error here
            s = alcp::base::InternalError(
                "ERROR: Requested algorithm does not meet min requirements "
                "for security level specified.");
            return s;
        }
#endif
    std::vector<Uint8> entropy_input(m_entropy_len);
    std::vector<Uint8> nonce(m_nonce_len);
    entropy_input.reserve(1);
    nonce.reserve(1);

    if (entropy_input.size()) {
        err = m_entropy_in->randomize(&entropy_input[0], entropy_input.size());
        if (alcp_is_error(err)) {
            return err;
        }
    }

    if (nonce.size()) {
        err = m_entropy_in->randomize(&nonce[0], nonce.size());
        if (alcp_is_error(err)) {
            return err;
        }
    }

    instantiate(entropy_input, nonce, personalization_string);
    return err;
}

alc_error_t
Drbg::randomize(Uint8        p_Output[],
                const size_t cOutputLength,
                int          cSecurityStrength,
                const Uint8  cAdditionalInput[],
                const size_t cAdditionalInputLength)
{
    alc_error_t err{ ALC_ERROR_NONE };
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
            if (cSecurityStrength >= getCurrSecurityStrength()) {
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
    if (m_prediction_resistance) {
        // If prediction resistance then reseed before generating the random
        // bits.
        std::vector<Uint8> entropy_input(128);
        err = m_entropy_in->randomize(&entropy_input[0], entropy_input.size());
        if (alcp_is_error(err)) {
            return err;
        }
        internalReseed(&entropy_input[0],
                       entropy_input.size(),
                       &cAdditionalInput[0],
                       cAdditionalInputLength);
    }
    generate(cAdditionalInput, cAdditionalInputLength, p_Output, cOutputLength);
    return err;
}
alc_error_t
Drbg::randomize(Uint8               p_Output[],
                const size_t        cOutputLength,
                const int           cSecurityStrength,
                std::vector<Uint8>& additional_input)
{
    return randomize(p_Output,
                     cOutputLength,
                     cSecurityStrength,
                     &additional_input[0],
                     additional_input.size());
}

alc_error_t
Drbg::randomize(Uint8 output[], size_t length)
{
    std::vector<Uint8> add = std::vector<Uint8>(0);
    add.reserve(1);
    return randomize(output, length, 512, add);
}

alc_error_t
Drbg::readRandom(Uint8 buf[], Uint64 size)
{
    return randomize(buf, size);
}

alc_error_t
Drbg::setRng(std::shared_ptr<IRng> entropyIn)
{
    if (entropyIn == nullptr) {
        // No Entropy Source
        return ALC_ERROR_INVALID_ARG;
    }
    m_entropy_in = std::move(entropyIn);
    return ALC_ERROR_NONE;
}

alc_error_t
Drbg::setPredictionResistance(bool value)
{
    alc_error_t err{ ALC_ERROR_NONE };
    m_prediction_resistance = value;
    if (m_entropy_in) {
        m_entropy_in->setPredictionResistance(value);
    } else {
        // No Entropy Source
        err = ALC_ERROR_NO_ENTROPY;
    }
    return err;
}

} // namespace alcp::rng
