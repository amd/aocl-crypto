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

#include "alcp/base.hh"
#include "rng.hh"
#include "utils/copy.hh"
#include <functional>
#include <vector>
namespace alcp { namespace random_number {

    class Drbg : public IRng
    {
        // Way to take entropy (IRng class object)
        // Way to select type of DRBG (HMAC,CTR)
        // Set Reseed interval?
      private:
        std::shared_ptr<IRng> m_entropy_in = {};

      public:
        Drbg() {}

        Drbg(std::shared_ptr<IRng> entropy_in)
            : m_entropy_in{ entropy_in }
        {}

        // FIXME: Predicition resistance is to be added
        Status initialize(int                 security_strength,
                          std::vector<Uint8>& personalization_string)
        {
            Status s(ErrorCode::eOk);
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

            s = m_entropy_in->randomize(&entropy_input[0],
                                        entropy_input.size());
            if (!s.ok()) {
                return s;
            }

            s = m_entropy_in->randomize(&nonce[0], nonce.size());
            if (!s.ok()) {
                return s;
            }

            Instantiate(entropy_input, nonce, personalization_string);
            return s;
        }

        // FIXME: Predicition resistance is to be added
        Status randomize(Uint8               output[],
                         size_t              length,
                         int                 security_strength,
                         std::vector<Uint8>& additional_input)
        {
            Status s(ErrorCode::eOk);
#if 0
            // TODO: Enable after implementing
            /*
                FIXME: Implement Max Generate Bits
                get_max_generatable_bits() -> Implemented in HMAC_Drbg
                Calling the above function returns the current security strength.
            */
            if (length > get_max_generatable_bits()) {
                s = InternalError(
                    "ERROR: Impossible amount of bits to generate per call");
                return s;
            }
            /*
                FIXME: Implement Security Strength
                get_curr_security_strength() -> Implemented in HMAC_Drbg
                Calling the above function returns the current security strength.
            */
            if (security_strength >= get_curr_security_strength()) {
                // Bail out
                // Return error here
                s = alcp::base::InternalError(
                    "ERROR: Requested algorithm does not meet min requirements "
                    "for security level specified.");
                return s;
            }
            /*
                FIXME: Implement Max Additional Input Length
                get_max_generatable_bits() -> Implemented in HMAC_Drbg
                Calling the above function returns the current security strength.
            */
            if(additional_input.size()> get_max_add_input_length()){
                s = InternalError(
                    "ERROR: Additional Input too large");
                return s;
            }
            // FIXME: Handle Predicition Resistance Request
            // FIXME: Handle reseed required flag
#endif
            Generate(
                &additional_input[0], additional_input.size(), output, length);
            return s;
        }

        Status randomize(Uint8 output[], size_t length)
        {
            std::vector<Uint8> add = std::vector<Uint8>(0);
            return randomize(output, length, 512, add);
        }

        Status readRandom(Uint8* pBuf, Uint64 size)
        {
            return randomize(pBuf, size);
        }

        virtual std::string name() const = 0;

        bool isSeeded() const { return true; }

        size_t reseed() { return 0; }

        virtual void Instantiate(const Uint8* entropy_input,
                                 const Uint64 entropy_input_len,
                                 const Uint8* nonce,
                                 const Uint64 nonce_len,
                                 const Uint8* personalization_string,
                                 const Uint64 personalization_string_len) = 0;

        virtual void Instantiate(
            const std::vector<Uint8>& entropy_input,
            const std::vector<Uint8>& nonce,
            const std::vector<Uint8>& personalization_string) = 0;

        virtual void Generate(const Uint8* additional_input,
                              const Uint64 additional_input_len,
                              Uint8*       output,
                              const Uint64 output_len) = 0;

        virtual void Generate(const std::vector<Uint8>& additional_input,
                              std::vector<Uint8>&       output) = 0;

        virtual void Reseed(const Uint8* entropy_input,
                            const Uint64 entropy_input_len,
                            const Uint8* additional_input,
                            const Uint64 additional_input_len) = 0;

        virtual void Reseed(const std::vector<Uint8>& entropy_input,
                            const std::vector<Uint8>& additional_input) = 0;
    };
}} // namespace alcp::random_number